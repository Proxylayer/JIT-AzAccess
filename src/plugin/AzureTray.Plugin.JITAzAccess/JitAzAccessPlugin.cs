using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using AzureTray.Plugin.JITAzAccess.Models;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// AzureTray plugin for JIT-AzAccess.
///
/// Designed to "just work" once an AzureTray tenant is signed in — no separate
/// app registration and no manual URLs. Optional settings (default/offered
/// grant durations) are exposed via <see cref="IPluginConfigurable"/>:
///
///   • Token acquisition piggybacks on the host's ARM token (ArmScope).
///   • The function app URL is self-discovered by scanning the tags of every
///     app registration the signed-in user can read via Graph (the JIT function
///     app self-registers its URL as a tag via profile.ps1 on cold start).
///   • Authorization at the function app is gated on the caller holding a
///     custom "JIT-Requester" RBAC role on the function app site resource.
///
/// Multi-tenant: every ready tenant the host surfaces (already filtered to the
/// tenants the plugin is enabled for) is tracked independently, with its own
/// discovered URLs, targets, and active rules. The tray menu groups resources
/// under a per-tenant header (LAPS/PIM style) and offers a per-tenant Refresh.
/// </summary>
public sealed class JitAzAccessPlugin : ITrayPlugin, IMenuChangeNotifier, IBadgeProvider, IPluginTestProvider, IPluginConfigurable, IDisposable
{
    // ── Events ────────────────────────────────────────────────────────────────

    public event Action? MenuChanged;
    public event Action? BadgeChanged;
    public event Action? ValuesChanged;

    // ── ITrayPlugin ───────────────────────────────────────────────────────────

    public string Id          => "net.proxylayer.AzureTray.Plugin.JITAzAccess";
    public string DisplayName => "JIT Azure Access";
    public string Version     => AssemblyVersion;
    public int    ApiVersion  => PluginApiVersion.Current;

    // Resolved once and cached. Prefers AssemblyInformationalVersion (which
    // dotnet pack sets from the csproj <Version>), strips any "+commitSha"
    // suffix the build pipeline may append, and falls back to AssemblyVersion
    // if the informational attribute is missing.
    private static readonly string AssemblyVersion = ResolveVersion();

    private static string ResolveVersion()
    {
        var asm = typeof(JitAzAccessPlugin).Assembly;
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            var plus = info.IndexOf('+');
            return plus >= 0 ? info[..plus] : info;
        }
        return asm.GetName().Version?.ToString() ?? "0.0.0";
    }

    /// <summary>
    /// OAuth scopes the host must hold before this plugin makes network calls.
    ///   ARM   — used by JitClient (talks to the JIT function app with an ARM token).
    ///   Graph — used by JitUrlDiscovery (reads app registration tags to self-discover the JIT URL).
    /// </summary>
    public IReadOnlyList<PluginPermissionRequirement> RequiredPermissions =>
        new[]
        {
            new PluginPermissionRequirement(
                Api:         PermissionApi.AzureResourceManager,
                ScopeId:     "user_impersonation",
                ScopeName:   "Azure Resource Manager user_impersonation",
                DisplayName: "Call the JIT function app + verify rules via ARM"),

            new PluginPermissionRequirement(
                Api:         PermissionApi.MicrosoftGraph,
                ScopeId:     "Application.Read.All",
                ScopeName:   "Microsoft Graph Application.Read.All",
                DisplayName: "Read app registration tags (auto-discover JIT URL)"),
        };

    // ── IBadgeProvider ────────────────────────────────────────────────────────

    public int Count => SnapshotAllRules().Count;

    public BadgeState State
    {
        get
        {
            var rules = SnapshotAllRules();
            if (rules.Count == 0) return BadgeState.Normal;
            var expiresSoon = rules.Any(r => (r.ExpiresUtc - DateTime.UtcNow).TotalMinutes < 30);
            return expiresSoon ? BadgeState.Pending : BadgeState.Normal;
        }
    }

    public string? BadgeTooltip
    {
        get
        {
            var rules = SnapshotAllRules();
            var count = rules.Count;
            if (count == 0) return null;
            var expiring = rules.Count(r => (r.ExpiresUtc - DateTime.UtcNow).TotalMinutes < 30);
            if (expiring == 0)     return $"JIT Access — {count} active";
            if (expiring == count) return $"JIT Access — {expiring} expiring";
            return $"JIT Access — {count} active, {expiring} expiring";
        }
    }

    // Flat snapshot of active rules across every tracked tenant.
    private List<JitServerRule> SnapshotAllRules()
    {
        var all = new List<JitServerRule>();
        foreach (var state in _tenants.Values)
            lock (state.Lock) all.AddRange(state.ServerRules);
        return all;
    }

    // ── IPluginConfigurable ───────────────────────────────────────────────────

    private const string DefaultDurationOptionKey  = "defaultDurationHours";
    private const string AllowedDurationsOptionKey = "allowedDurations";

    // Asset-type selector keys. The host's generic option grid only renders
    // Boolean/Text/Number (no Select/ComboBox), so the type picker is a set of
    // Boolean checkboxes — one per catalog type plus an "All" master.
    private const string IncludeAllOptionKey = "include.all";
    private const string IncludePrefix       = "include.";

    private static string IncludeKey(string token) => IncludePrefix + token;

    // Defaults applied before the user changes anything (and the fallback when
    // a stored value is blank or malformed).
    private const int    DefaultDurationHoursValue = 4;
    private const string DefaultAllowedDurations   = "1,2,4,8";

    // Built once from the canonical catalog: the two duration options, the "All
    // asset types" master, then one "Include <label>" checkbox per asset type.
    // Defaulting every checkbox to true preserves the pre-selector behaviour of
    // discovering every supported type.
    public IReadOnlyList<PluginOption> Options { get; } = BuildOptions();

    private static IReadOnlyList<PluginOption> BuildOptions()
    {
        var options = new List<PluginOption>
        {
            new PluginOption(
                Key:          DefaultDurationOptionKey,
                Label:        "Default access duration (hours)",
                Kind:         PluginOptionKind.Number,
                Description:  "Pre-selected duration in the grant prompt. A resource that declares its own durations still overrides this.",
                DefaultValue: DefaultDurationHoursValue),
            new PluginOption(
                Key:          AllowedDurationsOptionKey,
                Label:        "Offered durations (hours)",
                Kind:         PluginOptionKind.Text,
                Description:  "Comma-separated durations offered in the grant prompt (e.g. 1,2,4,8). Used when a resource doesn't specify its own.",
                DefaultValue: DefaultAllowedDurations),
            new PluginOption(
                Key:          IncludeAllOptionKey,
                Label:        "All asset types",
                Kind:         PluginOptionKind.Boolean,
                Description:  "When on, discover every supported asset type. Turning it off lets you pick individual types below.",
                DefaultValue: true),
        };

        options.AddRange(AssetTypeCatalog.All.Select(t => new PluginOption(
            Key:          IncludeKey(t.Token),
            Label:        $"Include {t.DisplayLabel}",
            Kind:         PluginOptionKind.Boolean,
            Description:  $"Discover {t.DisplayLabel} ({t.ArmType}) resources.",
            DefaultValue: true)));

        return options;
    }

    // Seeded with every option's default so the keys exist before the host
    // hydrates persisted values (SetValue ignores unknown keys), and so the
    // typed accessors below always resolve.
    private readonly Dictionary<string, object?> _optionValues = BuildDefaultValues();

    private static Dictionary<string, object?> BuildDefaultValues()
    {
        var values = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [DefaultDurationOptionKey]  = DefaultDurationHoursValue,
            [AllowedDurationsOptionKey] = DefaultAllowedDurations,
            [IncludeAllOptionKey]       = true,
        };
        foreach (var t in AssetTypeCatalog.All)
            values[IncludeKey(t.Token)] = true;
        return values;
    }

    public IReadOnlyDictionary<string, object?> Values => _optionValues;

    public void SetValue(string key, object? value)
    {
        if (!_optionValues.TryGetValue(key, out var current)) return;   // unknown key
        if (Equals(current, value)) return;
        _optionValues[key] = value;

        // Keep the "All asset types" master in sync with the per-type
        // checkboxes. Sibling keys are written straight into the dictionary
        // (never via a nested SetValue), so ValuesChanged/MenuChanged fire
        // exactly once below and there is no re-entrancy loop.
        if (key == IncludeAllOptionKey)
        {
            var on = ToBool(value);
            foreach (var t in AssetTypeCatalog.All)
                _optionValues[IncludeKey(t.Token)] = on;
        }
        else if (key.StartsWith(IncludePrefix, StringComparison.Ordinal))
        {
            // Unchecking any type turns the master off; checking the last one
            // turns it back on.
            var allOn = AssetTypeCatalog.All.All(
                t => ToBool(_optionValues.GetValueOrDefault(IncludeKey(t.Token))));
            _optionValues[IncludeAllOptionKey] = allOn;
        }

        ValuesChanged?.Invoke();

        // Remaining options (default/offered durations) are read fresh on every
        // grant prompt; the type selection is read fresh on every discovery poll
        // — so a change has no side effects beyond the next menu build.
        MenuChanged?.Invoke();
    }

    /// <summary>
    /// Asset-type tokens the plugin should discover. Returns the full catalog
    /// (no filter) when "All asset types" is on, when no include keys are set
    /// (fresh install / missing keys), or when the user has cleared every
    /// individual type — preserving the pre-selector behaviour of querying
    /// everything. Otherwise returns just the checked tokens.
    /// </summary>
    public IReadOnlySet<string> SelectedAssetTypes
    {
        get
        {
            var allTokens = AssetTypeCatalog.All.Select(t => t.Token).ToHashSet(StringComparer.Ordinal);

            if (ToBool(_optionValues.GetValueOrDefault(IncludeAllOptionKey)))
                return allTokens;

            var selected = AssetTypeCatalog.All
                .Where(t => ToBool(_optionValues.GetValueOrDefault(IncludeKey(t.Token))))
                .Select(t => t.Token)
                .ToHashSet(StringComparer.Ordinal);

            return selected.Count == 0 ? allTokens : selected;
        }
    }

    private static bool ToBool(object? value) => value switch
    {
        bool b                                          => b,
        string s when bool.TryParse(s, out var p)       => p,
        int i                                           => i != 0,
        long l                                          => l != 0,
        _                                               => false,
    };

    public object? BuildSettingsView() => null;   // generic option grid only

    // ── Option accessors ──────────────────────────────────────────────────────

    // Pre-selected grant duration. Falls back to the built-in default if the
    // stored value is missing, non-numeric, or non-positive.
    private int DurationHoursDefault =>
        TryToInt(_optionValues.GetValueOrDefault(DefaultDurationOptionKey), out var n) && n > 0
            ? n
            : DefaultDurationHoursValue;

    // Durations offered when a target doesn't declare its own.
    private int[] OfferedDurations =>
        ParseDurations(_optionValues.GetValueOrDefault(AllowedDurationsOptionKey) as string);

    private static bool TryToInt(object? value, out int result)
    {
        switch (value)
        {
            case int i:                                    result = i;                  return true;
            case long l:                                   result = (int)l;             return true;
            case double d:                                 result = (int)Math.Round(d); return true;
            case string s when int.TryParse(s, out var p): result = p;                  return true;
            default:                                       result = 0;                  return false;
        }
    }

    private static int[] ParseDurations(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv)) return new[] { 1, 2, 4, 8 };
        var parsed = csv
            .Split(new[] { ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => int.TryParse(s, out var n) ? n : 0)
            .Where(n => n > 0)
            .Distinct()
            .OrderBy(n => n)
            .ToArray();
        return parsed.Length > 0 ? parsed : new[] { 1, 2, 4, 8 };
    }

    // ── IPluginTestProvider ───────────────────────────────────────────────────

    public IReadOnlyList<PluginTest> Tests => new[]
    {
        new PluginTest(
            Name:        "Discover JIT function app URL",
            Description: "Scans readable app registration tags via Graph for each tracked tenant.",
            Run:         TestDiscoveryAsync),

        new PluginTest(
            Name:        "JIT Function App connectivity",
            Description: "Probes Get-JITRules on each discovered URL. Any HTTP response (including 403) confirms reachability.",
            Run:         TestConnectivityAsync),
    };

    private async Task<PluginTestResult> TestDiscoveryAsync(CancellationToken ct)
    {
        if (_discovery is null) return PluginTestResult.Fail("Plugin not initialised.");

        var states = _tenants.Values.ToArray();
        if (states.Length == 0) return PluginTestResult.Fail("No active tenant.");

        var lines    = new List<string>();
        var anyFound = false;
        foreach (var state in states)
        {
            var result = await _discovery.DiscoverAsync(state.Tenant.TenantId, ct)
                .ConfigureAwait(false);
            if (!result.IsEmpty)
            {
                anyFound = true;
                lines.Add($"{state.Tenant.DisplayName}: {result.AllUrls.Count()} URL(s)");
            }
            else
            {
                lines.Add($"{state.Tenant.DisplayName}: none");
            }
        }

        var summary = string.Join("; ", lines);
        return anyFound ? PluginTestResult.Pass(summary) : PluginTestResult.Fail(summary);
    }

    private async Task<PluginTestResult> TestConnectivityAsync(CancellationToken ct)
    {
        if (_client is null) return PluginTestResult.Fail("Plugin not initialised.");

        var states = _tenants.Values.ToArray();
        if (states.Length == 0) return PluginTestResult.Fail("No active tenant.");

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

        var report  = new List<string>();
        var anyFail = false;
        foreach (var state in states)
        {
            JitUrlDiscoveryResult urls;
            lock (state.Lock) urls = state.Urls;
            if (urls.IsEmpty)
            {
                report.Add($"{state.Tenant.DisplayName}: no URL discovered");
                anyFail = true;
                continue;
            }

            foreach (var url in urls.AllUrls)
            {
                try
                {
                    var result = await _client.GetActiveRulesAsync(state.Tenant.TenantId, url, timeoutCts.Token)
                        .ConfigureAwait(false);
                    report.Add($"{url}: {result.Rules.Count} active rule(s)");
                }
                catch (JitHttpException ex)
                {
                    // Any HTTP status came back — the host is up, even if it
                    // refused us. That's a successful connectivity result.
                    report.Add($"{url}: HTTP {ex.StatusCode}");
                }
                catch (OperationCanceledException)
                {
                    report.Add($"{url}: timed out");
                    anyFail = true;
                }
                catch (Exception ex)
                {
                    report.Add($"{url}: {ex.Message}");
                    anyFail = true;
                }
            }
        }

        var summary = string.Join("; ", report);
        return anyFail ? PluginTestResult.Fail(summary) : PluginTestResult.Pass(summary);
    }

    // ── Internal state ────────────────────────────────────────────────────────

    private IPluginContext?    _context;
    private JitClient?         _client;
    private ArmVerifier?       _verifier;
    private ActiveRulesStore?  _localStore;
    private JitUrlDiscovery?   _discovery;
    private ResourceDiscovery? _resources;
    private FavoritesStore?    _favorites;

    // One state object per tracked tenant. A single poll timer fans out across
    // all of them; each carries its own lock, discovered URLs, targets, rules,
    // and auth/suspended flags.
    private readonly ConcurrentDictionary<string, TenantState> _tenants =
        new(StringComparer.OrdinalIgnoreCase);

    // Busy keys are tenant-scoped: "{tenantId}|{type}|{sub}|{rg}|{name}|{hours}".
    private readonly object          _busyLock = new();
    private readonly HashSet<string> _busyKeys = new(StringComparer.Ordinal);

    private Timer? _pollTimer;

    private static readonly TimeSpan TargetsTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RulesTtl   = TimeSpan.FromSeconds(90);

    // Display string mentioned in the menu when auth is blocked. The actual
    // role name comes from the server; this is purely a hint to the user.
    private const string JitRequesterRoleNameDefault = "JIT-Requester";

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public Task InitializeAsync(IPluginContext context, CancellationToken cancellationToken)
    {
        _context    = context;
        _client     = new JitClient(context);
        _verifier   = new ArmVerifier(context);
        _localStore = new ActiveRulesStore(context.DataDir, context.Logger);
        _discovery  = new JitUrlDiscovery(context);
        _resources  = new ResourceDiscovery(context);
        _favorites  = new FavoritesStore(context.DataDir, context.Logger);

        context.Logger.LogInformation("JIT Azure Access plugin initialised.");

        context.TenantReady   += OnTenantReady;
        context.TenantRemoved += OnTenantRemoved;

        // Track every already-signed-in tenant the host surfaces. The host has
        // already filtered ReadyTenants to the tenants this plugin is enabled
        // for, so there's nothing more to gate on here.
        foreach (var tenant in context.ReadyTenants)
            OnTenantReady(tenant);

        return Task.CompletedTask;
    }

    private void StartPollTimer()
    {
        _pollTimer ??= new Timer(_ => _ = PollAllAsync(), null,
            TimeSpan.Zero, TimeSpan.FromSeconds(90));
    }

    public async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        _context?.Logger.LogInformation("JIT Azure Access plugin shutting down.");

        if (_pollTimer is not null)
        {
            await _pollTimer.DisposeAsync().ConfigureAwait(false);
            _pollTimer = null;
        }

        if (_context is not null)
        {
            _context.TenantReady   -= OnTenantReady;
            _context.TenantRemoved -= OnTenantRemoved;
        }

        _tenants.Clear();
        _context = null;
        _client  = null;
    }

    public void Dispose()
    {
        // Stop the timer AND unsubscribe context events even if ShutdownAsync
        // wasn't called — otherwise the host's IPluginContext keeps this
        // instance alive via the event handlers after a hot-reload. Idempotent:
        // ShutdownAsync nulls _context, so a later Dispose is a no-op here.
        _pollTimer?.Dispose();
        _pollTimer = null;
        if (_context is not null)
        {
            _context.TenantReady   -= OnTenantReady;
            _context.TenantRemoved -= OnTenantRemoved;
        }
    }

    // ── Tenant lifecycle ──────────────────────────────────────────────────────

    private void OnTenantReady(PluginTenant tenant)
    {
        var added = false;
        var state = _tenants.GetOrAdd(tenant.TenantId, _ =>
        {
            added = true;
            return new TenantState(tenant);
        });

        // Only kick off discovery on first sight of the tenant; a re-fire while
        // the tenant is already tracked is a no-op (the poll timer keeps it fresh).
        if (added)
        {
            _context?.Logger.LogInformation(
                "JIT: tracking tenant {TenantId} ({DisplayName}).", tenant.TenantId, tenant.DisplayName);
            _ = DiscoverAndPollAsync(state);
        }
    }

    private void OnTenantRemoved(string tenantId)
    {
        if (_tenants.TryRemove(tenantId, out _))
        {
            BadgeChanged?.Invoke();
            MenuChanged?.Invoke();
            _context?.Logger.LogWarning(
                "JIT: tenant {TenantId} signed out — untracked.", tenantId);
        }
    }

    // Discover this tenant's function-app URLs, then start polling. Safe to call
    // repeatedly (e.g. on a manual discovery retry).
    private async Task DiscoverAndPollAsync(TenantState state)
    {
        var context   = _context;
        var discovery = _discovery;
        if (context is null || discovery is null) return;

        var tenantId = state.Tenant.TenantId;
        context.Logger.LogInformation(
            "JIT: discovering function app URL(s) for tenant {TenantId} ({DisplayName}).",
            tenantId, state.Tenant.DisplayName);

        JitUrlDiscoveryResult urls;
        try
        {
            urls = await discovery.DiscoverAsync(tenantId, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            context.Logger.LogWarning(ex, "JIT: URL discovery failed for tenant {TenantId}.", tenantId);
            urls = JitUrlDiscoveryResult.Empty;
        }

        lock (state.Lock) state.Urls = urls;

        if (urls.IsEmpty)
        {
            context.Logger.LogWarning(
                "JIT: could not discover any function app URL for tenant {TenantId} — " +
                "menu will show 'not deployed' state.", tenantId);
            MenuChanged?.Invoke();
            return;
        }

        StartPollTimer();
        MenuChanged?.Invoke();
        await PollTenantAsync(state).ConfigureAwait(false);
    }

    private async Task RetryDiscoveryAsync(TenantState state)
    {
        var context   = _context;
        var discovery = _discovery;
        if (context is null || discovery is null) return;

        context.Logger.LogDebug("JIT: manual discovery retry for tenant {TenantId}.", state.Tenant.TenantId);
        var result = await discovery.DiscoverAsync(state.Tenant.TenantId, CancellationToken.None)
            .ConfigureAwait(false);

        if (!result.IsEmpty)
        {
            lock (state.Lock)
            {
                state.Urls          = result;
                state.PollSuspended = false;
                state.TargetsAt     = DateTime.MinValue;
                state.RulesAt       = DateTime.MinValue;
            }
            StartPollTimer();
            await PollTenantAsync(state).ConfigureAwait(false);
        }
        MenuChanged?.Invoke();
    }

    // ── Background polling ────────────────────────────────────────────────────

    private async Task PollAllAsync()
    {
        var states = _tenants.Values.ToArray();
        if (states.Length == 0) return;
        await Task.WhenAll(states.Select(PollTenantAsync)).ConfigureAwait(false);
    }

    private async Task PollTenantAsync(TenantState state)
    {
        var context   = _context;
        var client    = _client;
        var resources = _resources;
        if (context is null || client is null) return;

        bool suspended;
        JitUrlDiscoveryResult urls;
        lock (state.Lock)
        {
            suspended = state.PollSuspended;
            urls      = state.Urls;
        }
        if (suspended || urls.IsEmpty) return;

        // Skip if a poll for this tenant is already running — overlapping runs
        // race the shared per-tenant state (last-writer-wins). Cheap CAS guard.
        if (Interlocked.Exchange(ref state.Polling, 1) == 1) return;
        try
        {
            var now      = DateTime.UtcNow;
            var changed  = false;
            var tenantId = state.Tenant.TenantId;

            DateTime targetsAt;
            lock (state.Lock) targetsAt = state.TargetsAt;
            if (now - targetsAt > TargetsTtl && resources is not null)
            {
                // Targets are discovered client-side from ARM Resource Graph
                // using the user's own token. One call returns every NSG / SQL
                // server / storage account / Key Vault the user has ARM read
                // access to across all visible subscriptions.
                try
                {
                    var targets = await resources
                        .DiscoverAsync(tenantId, SelectedAssetTypes, CancellationToken.None)
                        .ConfigureAwait(false);
                    lock (state.Lock) { state.Targets = targets; state.TargetsAt = now; }
                    changed = true;
                    context.Logger.LogDebug(
                        "JIT: discovered {Count} target(s) for tenant {TenantId}.", targets.Count, tenantId);
                }
                catch (ArgumentException ex) when (IsTenantNotEnabled(ex))
                {
                    SuspendForTenantMismatch(state, "resource discovery");
                    return;
                }
                catch (Exception ex)
                {
                    context.Logger.LogWarning(ex, "JIT: resource discovery failed for tenant {TenantId}.", tenantId);
                }
            }

            DateTime rulesAt;
            lock (state.Lock) rulesAt = state.RulesAt;
            if (now - rulesAt > RulesTtl)
            {
                var allRules     = new List<JitServerRule>();
                var anySucceeded = false;
                string? callerIp = null;

                foreach (var url in urls.AllUrls)
                {
                    try
                    {
                        var result = await client
                            .GetActiveRulesAsync(tenantId, url, CancellationToken.None)
                            .ConfigureAwait(false);
                        // Tag each rule with the URL it came from so Revoke can route correctly.
                        foreach (var rule in result.Rules)
                            allRules.Add(rule with { SourceFunctionAppUrl = url });
                        if (!string.IsNullOrEmpty(result.CallerIp))
                            callerIp = result.CallerIp;
                        anySucceeded = true;
                        context.Logger.LogDebug(
                            "JIT: refreshed {Count} active rule(s) from {Url}.", result.Rules.Count, url);
                    }
                    catch (ArgumentException ex) when (IsTenantNotEnabled(ex))
                    {
                        SuspendForTenantMismatch(state, "rules refresh");
                        return;
                    }
                    catch (JitHttpException ex) when (ex.StatusCode is 401 or 403)
                    {
                        NotifyAuthBlocked(state, ex, url);
                    }
                    catch (Exception ex)
                    {
                        context.Logger.LogWarning(ex, "JIT: rules refresh failed for {Url}.", url);
                    }
                }

                if (anySucceeded)
                {
                    lock (state.Lock)
                    {
                        state.ServerRules = allRules;
                        state.RulesAt     = now;
                        if (callerIp is not null) state.CallerIp = callerIp;
                    }
                    changed = true;
                    ClearAuthBlocked(state);
                }
            }

            if (changed)
            {
                BadgeChanged?.Invoke();
                MenuChanged?.Invoke();
            }
        }
        finally
        {
            Interlocked.Exchange(ref state.Polling, 0);
        }
    }

    private static bool IsTenantNotEnabled(ArgumentException ex) =>
        ex.ParamName == "tenantId" || ex.Message.Contains("is not enabled for plugin");

    private void SuspendForTenantMismatch(TenantState state, string operation)
    {
        lock (state.Lock) state.PollSuspended = true;
        _context?.Logger.LogError(
            "JIT: tenant {TenantId} is not enabled for this plugin (operation: {Operation}). " +
            "Enable the plugin for that tenant in AzureTray settings. Polling suspended for it.",
            state.Tenant.TenantId, operation);
        MenuChanged?.Invoke();
    }

    /// <summary>
    /// Called when a poll returns 401/403 for a tenant. Sets the auth-blocked
    /// state and pushes a one-shot toast. Subsequent failures don't repeat the
    /// toast until <see cref="ClearAuthBlocked"/> resets the state.
    /// </summary>
    private void NotifyAuthBlocked(TenantState state, JitHttpException ex, string url)
    {
        var context = _context;
        if (context is null) return;

        // Suppress repeat toasts when the status hasn't changed.
        lock (state.Lock)
        {
            if (state.AuthBlocked && state.AuthBlockedStatus == ex.StatusCode)
            {
                context.Logger.LogDebug(
                    "JIT: still auth-blocked ({Status}) on {Url} — suppressing duplicate toast.", ex.StatusCode, url);
                return;
            }
            state.AuthBlocked       = true;
            state.AuthBlockedStatus = ex.StatusCode;
        }

        var (title, body) = ex.StatusCode switch
        {
            401 => ("JIT Access — sign-in required",
                    "Your token was rejected by the JIT function app. Sign in to the tenant in AzureTray and try again."),
            403 => ($"JIT Access — '{JitRequesterRoleNameDefault}' role required",
                    $"You don't hold the '{JitRequesterRoleNameDefault}' RBAC role on the JIT function app. " +
                    "Ask an admin to assign it to you on the function app site (or any parent scope)."),
            _   => ("JIT Access — request rejected",
                    ex.ServerError ?? ex.Message),
        };

        context.Logger.LogWarning(
            "JIT: {Operation} returned {Status} from {Url}: {Server}",
            ex.Operation, ex.StatusCode, url, ex.ServerError ?? "(no body)");

        _ = context.Notifier.ShowAsync(
            new InformationRequest(Title: title, Message: body)
            {
                Severity = NotificationSeverity.Warning,
                Details  = new[]
                {
                    new NotificationDetail("Tenant",   state.Tenant.DisplayName),
                    new NotificationDetail("Status",   ex.StatusCode.ToString()),
                    new NotificationDetail("Endpoint", url),
                    new NotificationDetail("Server",   ex.ServerError ?? ex.Message),
                },
            },
            CancellationToken.None);

        MenuChanged?.Invoke();
    }

    /// <summary>Clears a tenant's auth-blocked state after a successful poll.</summary>
    private void ClearAuthBlocked(TenantState state)
    {
        lock (state.Lock)
        {
            if (!state.AuthBlocked) return;
            state.AuthBlocked       = false;
            state.AuthBlockedStatus = 0;
        }
        _context?.Logger.LogInformation(
            "JIT: authorization restored for tenant {TenantId} — polls succeeding again.", state.Tenant.TenantId);
        MenuChanged?.Invoke();
    }

    // ── Menu entry point ──────────────────────────────────────────────────────

    public IReadOnlyList<PluginMenuItem> GetMenuItems()
    {
        var states = _tenants.Values.ToArray();

        var total = 0;
        var warn  = false;
        foreach (var s in states)
        {
            lock (s.Lock)
            {
                total += s.ServerRules.Count;
                if (s.PollSuspended || s.AuthBlocked) warn = true;
            }
        }

        var label = warn
            ? "🔑  JIT Access  ⚠"
            : total > 0
                ? $"🔑  JIT Access  ({total})"
                : "🔑  JIT Access";

        return new[] {
            new PluginMenuItem(
                Text:              label,
                SearchProvider:    BuildSearchItems,
                SearchPlaceholder: "Filter by name or environment…")
        };
    }

    /// <summary>
    /// Single source of truth for the menu body. Groups rows under a per-tenant
    /// header (when more than one tenant is tracked) and handles every state:
    /// no tenant, no URL, loading, no targets, no matches, auth-blocked, and the
    /// normal list-of-targets case.
    /// </summary>
    private IReadOnlyList<PluginMenuItem> BuildSearchItems(string query)
    {
        var states = _tenants.Values
            .OrderBy(s => s.Tenant.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (states.Length == 0)
            return new[] { new PluginMenuItem("⚙ Sign in to a tenant to enable JIT access.", IsEnabled: false) };

        var multiTenant = states.Length > 1;
        var items       = new List<PluginMenuItem>();

        foreach (var state in states)
            AppendTenantItems(items, state, query, multiTenant);

        if (items.Count == 0)
            items.Add(new PluginMenuItem("  No matching resources.", IsEnabled: false));

        return items;
    }

    // Renders one tenant's section into <paramref name="items"/>. In multi-tenant
    // setups each section is bracketed by a "— DisplayName —" header and a
    // trailing separator; single-tenant setups stay flat. A tenant with nothing
    // to show during an active search is skipped entirely (header included).
    private void AppendTenantItems(List<PluginMenuItem> items, TenantState state, string query, bool multiTenant)
    {
        JitUrlDiscoveryResult urls;
        List<JitTarget>       targets;
        List<JitServerRule>   rules;
        DateTime              targetsAt;
        string?               callerIp;
        bool                  authBlocked, pollSuspended;
        lock (state.Lock)
        {
            urls          = state.Urls;
            targets       = state.Targets;
            rules         = state.ServerRules;
            targetsAt     = state.TargetsAt;
            callerIp      = state.CallerIp;
            authBlocked   = state.AuthBlocked;
            pollSuspended = state.PollSuspended;
        }

        var hasQuery = !string.IsNullOrWhiteSpace(query);
        var indent   = multiTenant ? "    " : string.Empty;

        // Build the tenant body first so we only emit a header when there's
        // something under it (important while searching).
        var body = new List<PluginMenuItem>();

        if (urls.IsEmpty)
        {
            if (!hasQuery)
            {
                body.Add(new PluginMenuItem($"{indent}⚠ JIT function app URL not yet discovered.",  IsEnabled: false));
                body.Add(new PluginMenuItem($"{indent}  Deploy the JIT function app in this tenant.", IsEnabled: false));
                body.Add(new PluginMenuItem(
                    Text:         $"{indent}Retry discovery",
                    Invoke:       () => _ = RetryDiscoveryAsync(state),
                    Icon:         "↻",
                    KeepMenuOpen: true));
            }
        }
        else
        {
            if (authBlocked && !hasQuery)
                body.Add(new PluginMenuItem(
                    $"{indent}⚠ Missing '{JitRequesterRoleNameDefault}' role — see notification.", IsEnabled: false));

            if (pollSuspended && !hasQuery)
                body.Add(new PluginMenuItem(
                    $"{indent}⚠ Tenant not enabled for this plugin.", IsEnabled: false));

            if (targets.Count == 0 && targetsAt == DateTime.MinValue)
            {
                if (!hasQuery) body.Add(new PluginMenuItem($"{indent}  Loading targets…", IsEnabled: false));
            }
            else
            {
                var filtered = hasQuery
                    ? targets.Where(t => MatchesQuery(t, query)).ToList()
                    : targets;

                if (filtered.Count > 0)
                {
                    // Favorites float to the top. Within each group sort by
                    // environment then display name.
                    body.AddRange(filtered
                        .OrderByDescending(t => _favorites?.IsFavorite(t.Id) ?? false)
                        .ThenBy(t => t.Environment)
                        .ThenBy(t => t.DisplayName)
                        .Select(t => BuildTargetItem(state, t, rules, callerIp, indent)));
                }
                else if (!hasQuery)
                {
                    body.Add(new PluginMenuItem(
                        $"{indent}  No Azure resources found that you have access to request.", IsEnabled: false));
                }
            }

            // Per-tenant refresh — hidden during search to keep results tight.
            if (!hasQuery)
                body.Add(new PluginMenuItem(
                    Text:         $"{indent}Refresh",
                    Invoke:       () => RefreshTenant(state),
                    Icon:         "↻",
                    KeepMenuOpen: true));
        }

        if (body.Count == 0) return;   // nothing to show for this tenant

        if (multiTenant)
            items.Add(new PluginMenuItem($"— {state.Tenant.DisplayName} —", IsEnabled: false));
        items.AddRange(body);
        if (multiTenant)
            items.Add(PluginMenuItem.Separator);
    }

    private static bool MatchesQuery(JitTarget t, string query) =>
        t.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
        t.ResourceName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
        (t.Environment?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
        t.TargetType.Contains(query, StringComparison.OrdinalIgnoreCase);

    private void RefreshTenant(TenantState state)
    {
        _context?.Logger.LogDebug("JIT: manual refresh requested for tenant {TenantId}.", state.Tenant.TenantId);
        lock (state.Lock)
        {
            state.TargetsAt = DateTime.MinValue;
            state.RulesAt   = DateTime.MinValue;
        }
        _ = PollTenantAsync(state);
    }

    // ── Target row ────────────────────────────────────────────────────────────

    private PluginMenuItem BuildTargetItem(
        TenantState state, JitTarget target, IReadOnlyList<JitServerRule> rules, string? callerIp, string indent)
    {
        var envBadge   = string.IsNullOrEmpty(target.Environment) ? string.Empty : $"[{target.Environment.ToUpper()}] ";
        var isFavorite = _favorites?.IsFavorite(target.Id) ?? false;

        // Toggled by the host when the user clicks the row's favorite star.
        // Persists to the local store; the host flips the glyph in place, so we
        // don't raise MenuChanged here.
        void ToggleFavorite()
        {
            var now = _favorites?.Toggle(target.Id);
            _context?.Logger.LogInformation(
                "JIT: {Action} favorite for {ResourceName} (id={Id}).",
                now == true ? "added" : "removed", target.ResourceName, target.Id);
        }

        var activeRule = rules.FirstOrDefault(r =>
            string.Equals(r.SubscriptionId, target.SubscriptionId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ResourceGroup,  target.ResourceGroup,  StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ResourceName,   target.ResourceName,   StringComparison.OrdinalIgnoreCase));

        if (activeRule is not null)
        {
            var r         = activeRule;
            var remaining = r.ExpiresUtc - DateTime.UtcNow;
            // Greyed-out row with the "active" suffix + countdown. Right-click
            // reveals Copy rule ID and Revoke.
            return new PluginMenuItem(
                Text:             $"{indent}  ✓ {envBadge}{target.DisplayName}  — active ({FormatTimeRemaining(remaining)})",
                IsEnabled:        false,
                Icon:             remaining.TotalMinutes < 30 ? "⚠" : "✓",
                IsFavorite:       isFavorite,
                OnToggleFavorite: ToggleFavorite,
                ContextItems:     new[]
                {
                    new PluginMenuItem(
                        Text:         "  📋 Copy rule ID",
                        Invoke:       () => _context?.Clipboard.SetText(r.RuleId),
                        KeepMenuOpen: true),
                    PluginMenuItem.Separator,
                    new PluginMenuItem(
                        Text:   "  🗑 Revoke access",
                        Invoke: () => _ = ConfirmRevokeAsync(state, r)),
                });
        }

        // Already permanently whitelisted? If the caller's current IP is an
        // exact match for an existing firewall entry on this resource, there's
        // nothing to request — show it greyed like an active rule.
        if (!string.IsNullOrEmpty(callerIp) &&
            (target.WhitelistedIps.Contains(callerIp) || target.WhitelistedIps.Contains(callerIp + "/32")))
        {
            return new PluginMenuItem(
                Text:             $"{indent}  ✓ {envBadge}{target.DisplayName}  — IP already allowed",
                IsEnabled:        false,
                Icon:             "✓",
                IsFavorite:       isFavorite,
                OnToggleFavorite: ToggleFavorite);
        }

        // Single-click target rows. Duration is asked via a ChoiceRequest popup.
        var targetPrefix = $"{state.Tenant.TenantId}|{target.TargetType}|{target.SubscriptionId}|{target.ResourceGroup}|{target.ResourceName}|";
        bool isBusy;
        lock (_busyLock) isBusy = _busyKeys.Any(k => k.StartsWith(targetPrefix, StringComparison.Ordinal));

        var isProd = string.Equals(target.Environment, "prod", StringComparison.OrdinalIgnoreCase);
        return new PluginMenuItem(
            Text:             $"{indent}  {envBadge}{target.DisplayName}",
            Icon:             isProd ? "⚠" : null,
            Invoke:           isBusy ? null : () => _ = PromptAndGrantAsync(state, target),
            IsEnabled:        !isBusy,
            IsBusy:           isBusy,
            KeepMenuOpen:     false,
            IsFavorite:       isFavorite,
            OnToggleFavorite: ToggleFavorite);
    }

    /// <summary>
    /// Single-click entry point on a target row. Pops a ChoiceRequest asking for
    /// the grant duration, then hands off to the grant flow.
    /// </summary>
    private async Task PromptAndGrantAsync(TenantState state, JitTarget target)
    {
        var context = _context;
        if (context is null) return;

        // A resource that declares its own durations wins; otherwise offer the
        // configured list. The configured default is pre-selected either way.
        var offered   = target.AllowedDurations is { Length: > 0 } ? target.AllowedDurations : OfferedDurations;
        var durations = BuildDurationList(DurationHoursDefault, offered);
        var choices   = durations.Select(h => h == 1 ? "1 hour" : $"{h} hours").ToArray();

        var result = await context.Notifier.ShowAsync(
            new ChoiceRequest(
                Title:   $"Grant JIT access — {target.DisplayName}",
                Message: $"How long? ({TargetTypeLabel(target.TargetType)}: {target.ResourceName})",
                Choices: choices),
            CancellationToken.None).ConfigureAwait(false);

        if (result is not ChoiceResult { SelectedChoice: { Length: > 0 } picked })
        {
            context.Logger.LogInformation(
                "JIT: duration prompt cancelled for {ResourceName}.", target.ResourceName);
            return;
        }

        // Map the selected label back to hours via index — safer than parsing.
        var idx = Array.IndexOf(choices, picked);
        if (idx < 0 || idx >= durations.Length)
        {
            context.Logger.LogWarning(
                "JIT: unknown duration choice '{Choice}' for {ResourceName}.", picked, target.ResourceName);
            return;
        }

        var hours      = durations[idx];
        var requestKey = $"{state.Tenant.TenantId}|{target.TargetType}|{target.SubscriptionId}|{target.ResourceGroup}|{target.ResourceName}|{hours}";
        await GrantFromTargetAsync(state, target, hours, requestKey).ConfigureAwait(false);
    }

    // ── Grant flow ───────────────────────────────────────────────────────────

    private async Task GrantFromTargetAsync(TenantState state, JitTarget target, int durationHours, string requestKey)
    {
        var context = _context;
        var client  = _client;
        if (context is null || client is null) return;

        var tenantId = state.Tenant.TenantId;

        // Justification is required on EVERY grant by default. It becomes optional
        // only when the tenant opted out via the JustificationRequired:false app-reg
        // tag — but a resource-level RequiresJustification still forces the prompt
        // even in an opt-out tenant. The server enforces this authoritatively; this
        // is the matching client-side UX.
        string? justification = null;
        if (!state.Urls.JustificationOptional || target.RequiresJustification)
        {
            var result = await context.Notifier.ShowAsync(
                new TextInputRequest(
                    Title:       "Justification Required",
                    Message:     $"Provide a reason for requesting access to \"{target.DisplayName}\".",
                    Placeholder: "e.g. Investigating incident #12345"),
                CancellationToken.None).ConfigureAwait(false);

            if (result is not TextInputResult { Text: { Length: > 0 } text })
            {
                context.Logger.LogInformation(
                    "JIT: grant cancelled at justification prompt for {TargetType} {ResourceName}.",
                    target.TargetType, target.ResourceName);
                return;
            }
            justification = text;
        }

        var isProd = string.Equals(target.Environment, "prod", StringComparison.OrdinalIgnoreCase);
        if (isProd)
        {
            var confirm = await context.Notifier.ShowAsync(
                new YesNoRequest(
                    Title:   "⚠ Production Resource",
                    Message: $"You are about to grant yourself {durationHours}h access to the PRODUCTION resource " +
                             $"\"{target.DisplayName}\" ({target.TargetType}: {target.ResourceName}).\n\nContinue?"),
                CancellationToken.None).ConfigureAwait(false);

            if (confirm is not YesNoResult { Accepted: true })
            {
                context.Logger.LogInformation(
                    "JIT: prod grant cancelled at confirmation prompt for {ResourceName}.", target.ResourceName);
                return;
            }
        }

        lock (_busyLock)
        {
            if (!_busyKeys.Add(requestKey)) return;
        }
        MenuChanged?.Invoke();

        // Route the grant to the function app responsible for this target's
        // subscription. Falls back to the legacy single URL if no per-sub
        // entry exists (single-deploy setups).
        var grantUrl = state.Urls.UrlForSubscription(target.SubscriptionId);
        if (string.IsNullOrEmpty(grantUrl))
        {
            context.Logger.LogError(
                "JIT: no function app URL discovered for subscription {SubscriptionId}.", target.SubscriptionId);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Failed",
                    Message: $"No JIT function app is registered for subscription {target.SubscriptionId}.")
                { Severity = NotificationSeverity.Error },
                CancellationToken.None);
            lock (_busyLock) _busyKeys.Remove(requestKey);
            MenuChanged?.Invoke();
            return;
        }

        try
        {
            var request = new JitRequest(
                target.TargetType,
                target.SubscriptionId,
                target.ResourceGroup,
                target.ResourceName,
                durationHours,
                target.TargetType == "nsg" ? target.DefaultPort : null,
                justification);

            var response = await client
                .RequestAccessAsync(tenantId, grantUrl, request, CancellationToken.None)
                .ConfigureAwait(false);

            _localStore?.Add(new ActiveRule(
                RuleId:         response.RuleId,
                TenantId:       tenantId,
                TargetType:     response.TargetType,
                SubscriptionId: target.SubscriptionId,
                ResourceGroup:  target.ResourceGroup,
                ResourceName:   target.ResourceName,
                Port:           response.Port,
                DurationHours:  durationHours,
                GrantedUtc:     DateTime.UtcNow,
                ExpiryUtc:      response.ExpiresUtc));

            context.Logger.LogInformation(
                "JIT access granted: {TargetType} {ResourceName}, rule {RuleId}, expires {ExpiresUtc}.",
                response.TargetType, target.ResourceName, response.RuleId, response.ExpiresUtc);

            // Sole post-grant user feedback is raised by VerifyAndNotifyAsync
            // (exactly one toast per outcome). No success toast fires here —
            // green is reserved for a real ARM-confirmed grant.
            _ = VerifyAndNotifyAsync(response, target, context, tenantId, durationHours);
        }
        catch (JitHttpException ex) when (ex.StatusCode == 400)
        {
            // Authoritative server-side rejection (e.g. missing/invalid
            // justification). Surface the server's own message as a clear Warning
            // rather than a generic red error, so the reason reads cleanly.
            var serverMessage = string.IsNullOrWhiteSpace(ex.ServerError) ? ex.Message : ex.ServerError!;
            context.Logger.LogWarning(ex,
                "JIT grant rejected (400) for {ResourceName}: {ServerError}.",
                target.ResourceName, serverMessage);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Not Granted",
                    Message: $"{target.DisplayName} — the request was rejected by the server.\n{serverMessage}")
                {
                    Severity = NotificationSeverity.Warning,
                    Details  = new[] { new NotificationDetail("Server", serverMessage) },
                },
                CancellationToken.None);
        }
        catch (Exception ex)
        {
            context.Logger.LogError(ex, "JIT grant failed for {ResourceName}.", target.ResourceName);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Failed",
                    Message: $"{target.DisplayName} — request rejected.")
                {
                    Severity = NotificationSeverity.Error,
                    Details  = new[] { new NotificationDetail("Error", ex.Message) },
                },
                CancellationToken.None);
        }
        finally
        {
            lock (_busyLock) _busyKeys.Remove(requestKey);
            lock (state.Lock) state.RulesAt = DateTime.MinValue;
            _ = PollTenantAsync(state);
        }
    }

    // ── Revoke flow ───────────────────────────────────────────────────────────

    private async Task ConfirmRevokeAsync(TenantState state, JitServerRule rule)
    {
        var context = _context;
        var client  = _client;
        if (context is null || client is null) return;

        var confirm = await context.Notifier.ShowAsync(
            new YesNoRequest(
                Title:   "Revoke JIT Access",
                Message: $"Remove the active rule for {rule.TargetType}: {rule.ResourceName}?\n" +
                         $"Rule {rule.RuleId} — expires {rule.ExpiresUtc:HH:mm} UTC"),
            CancellationToken.None).ConfigureAwait(false);

        if (confirm is not YesNoResult { Accepted: true })
        {
            context.Logger.LogInformation(
                "JIT: revoke cancelled at confirmation prompt for rule {RuleId}.", rule.RuleId);
            return;
        }

        // Route the revoke to the function app the rule was originally fetched
        // from. SourceFunctionAppUrl is tagged during the poll; fall back to the
        // per-sub map if it's somehow missing.
        var revokeUrl = !string.IsNullOrEmpty(rule.SourceFunctionAppUrl)
            ? rule.SourceFunctionAppUrl
            : state.Urls.UrlForSubscription(rule.SubscriptionId);

        if (string.IsNullOrEmpty(revokeUrl))
        {
            context.Logger.LogError(
                "JIT: cannot determine which function app to call to revoke rule {RuleId} " +
                "(subscription {SubscriptionId}).", rule.RuleId, rule.SubscriptionId);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "Revoke Failed",
                    Message: $"No JIT function app URL known for rule {rule.RuleId}.")
                { Severity = NotificationSeverity.Error },
                CancellationToken.None);
            return;
        }

        try
        {
            await client
                .RevokeAsync(state.Tenant.TenantId, revokeUrl, rule.RuleId, CancellationToken.None)
                .ConfigureAwait(false);

            context.Logger.LogInformation("JIT rule revoked: {RuleId} via {Url}.", rule.RuleId, revokeUrl);

            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Revoked",
                    Message: $"{rule.TargetType}: {rule.ResourceName} — rule {rule.RuleId} removed.")
                { Severity = NotificationSeverity.Success },
                CancellationToken.None);
        }
        catch (Exception ex)
        {
            context.Logger.LogError(ex, "JIT revoke failed for {RuleId}.", rule.RuleId);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "Revoke Failed",
                    Message: $"Could not revoke rule {rule.RuleId}.")
                {
                    Severity = NotificationSeverity.Error,
                    Details  = new[] { new NotificationDetail("Error", ex.Message) },
                },
                CancellationToken.None);
        }
        finally
        {
            lock (state.Lock) state.RulesAt = DateTime.MinValue;
            _ = PollTenantAsync(state);
        }
    }

    // ── ARM post-grant verification ───────────────────────────────────────────

    // Sole owner of post-grant user feedback: raises EXACTLY ONE toast for the
    // grant, and green ONLY when ARM actually confirms the rule. Every
    // VerificationResult value is covered, plus a fallback for the (practically
    // unreachable) case where the verifier was never constructed, so no grant is
    // ever silent. Called fire-and-forget once per grant, so there is no
    // re-entrancy concern.
    private async Task VerifyAndNotifyAsync(
        JitGrantResponse grant, JitTarget target, IPluginContext context, string tenantId, int durationHours)
    {
        var expiry = $"Expires {grant.ExpiresUtc:HH:mm} UTC  |  Rule: {grant.RuleId}";

        if (_verifier is null)
        {
            // _verifier is assigned alongside _context/_client in InitializeAsync
            // and the grant path already guards on those being non-null, so this
            // branch should not be reachable in practice. Emit a single neutral
            // toast anyway rather than leaving the grant silent.
            context.Logger.LogWarning(
                "JIT ARM verification skipped: verifier unavailable for rule {RuleId}.", grant.RuleId);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Granted",
                    Message: $"{target.DisplayName} — {durationHours}h access granted.\n{expiry}")
                { Severity = NotificationSeverity.Info },
                CancellationToken.None);
            return;
        }

        var result = await _verifier.VerifyAsync(grant, tenantId).ConfigureAwait(false);

        switch (result)
        {
            case VerificationResult.Confirmed:
                context.Logger.LogInformation(
                    "JIT ARM verification confirmed: rule {RuleId} visible in {ResourceName}.",
                    grant.RuleId, grant.ResourceName);
                _ = context.Notifier.ShowAsync(
                    new InformationRequest(
                        Title:   "✅ JIT Access Granted",
                        Message: $"{target.DisplayName} — {durationHours}h access confirmed.\n" +
                                 $"Your IP ({grant.CallerIp}) is present in the Azure resource.\n{expiry}")
                    { Severity = NotificationSeverity.Success },
                    CancellationToken.None);
                break;

            case VerificationResult.NotFound:
                context.Logger.LogWarning(
                    "JIT ARM verification: rule {RuleId} NOT found in {ResourceName} after grant.",
                    grant.RuleId, grant.ResourceName);
                _ = context.Notifier.ShowAsync(
                    new InformationRequest(
                        Title:   "⚠ Whitelist Verification Failed",
                        Message: "The grant was accepted but the rule is not yet visible via ARM.\n" +
                                 "Access may still propagate — wait 30s and retry if needed.")
                    {
                        Severity = NotificationSeverity.Warning,
                        Details  = new[] { new NotificationDetail("Rule ID", grant.RuleId) },
                    },
                    CancellationToken.None);
                break;

            case VerificationResult.Timeout:
                context.Logger.LogWarning("JIT ARM verification timed out for rule {RuleId}.", grant.RuleId);
                _ = context.Notifier.ShowAsync(
                    new InformationRequest(
                        Title:   "JIT Access Granted",
                        Message: "Access granted; verification timed out — it may still be propagating.\n" +
                                 expiry)
                    { Severity = NotificationSeverity.Info },
                    CancellationToken.None);
                break;

            case VerificationResult.Skipped:
                context.Logger.LogInformation(
                    "JIT ARM verification skipped for {TargetType} rule {RuleId} (type not auto-verifiable).",
                    grant.TargetType, grant.RuleId);
                _ = context.Notifier.ShowAsync(
                    new InformationRequest(
                        Title:   "JIT Access Granted",
                        Message: "Access granted. This resource type can't be auto-verified.\n" + expiry)
                    { Severity = NotificationSeverity.Info },
                    CancellationToken.None);
                break;

            case VerificationResult.Error:
            default:
                context.Logger.LogWarning(
                    "JIT ARM verification could not complete for rule {RuleId}.", grant.RuleId);
                _ = context.Notifier.ShowAsync(
                    new InformationRequest(
                        Title:   "JIT Access Granted",
                        Message: "Access granted; verification could not complete.\n" + expiry)
                    { Severity = NotificationSeverity.Info },
                    CancellationToken.None);
                break;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string FormatTimeRemaining(TimeSpan remaining)
    {
        if (remaining.TotalSeconds <= 0) return "expired";
        if (remaining.TotalMinutes < 1)  return "< 1m";
        if (remaining.TotalHours < 1)    return $"{(int)remaining.TotalMinutes}m";
        return $"{(int)remaining.TotalHours}h {remaining.Minutes:D2}m";
    }

    private static string TargetTypeLabel(string targetType) => AssetTypeCatalog.LabelForToken(targetType);

    private static int[] BuildDurationList(int defaultDuration, int[]? allowed)
    {
        var standard = allowed is { Length: > 0 } ? allowed : new[] { 1, 2, 4, 8 };
        return new[] { defaultDuration }
            .Concat(standard.Where(d => d != defaultDuration))
            .Distinct()
            .ToArray();
    }

    // ── Per-tenant state ────────────────────────────────────────────────────────

    // Mutated on poll completion and read while the menu/badge build; callers
    // lock around compound reads/writes. Reference swaps for the lists are
    // atomic, but the flags/timestamps travel together so we guard them too.
    private sealed class TenantState
    {
        public TenantState(PluginTenant tenant) { Tenant = tenant; }

        public PluginTenant Tenant { get; }
        public object       Lock   { get; } = new();

        public JitUrlDiscoveryResult Urls        { get; set; } = JitUrlDiscoveryResult.Empty;
        public List<JitTarget>       Targets     { get; set; } = new();
        public List<JitServerRule>   ServerRules { get; set; } = new();
        public DateTime              TargetsAt   { get; set; } = DateTime.MinValue;
        public DateTime              RulesAt     { get; set; } = DateTime.MinValue;
        public string?               CallerIp    { get; set; }

        public bool PollSuspended     { get; set; }
        public bool AuthBlocked       { get; set; }
        public int  AuthBlockedStatus { get; set; }

        // Re-entrancy guard for PollTenantAsync (Interlocked — must be a field).
        public int Polling;
    }
}
