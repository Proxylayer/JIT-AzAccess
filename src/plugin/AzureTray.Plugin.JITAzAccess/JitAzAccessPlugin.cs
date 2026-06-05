using System;
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
/// Designed to "just work" once an AzureTray tenant is signed in — no plugin
/// options, no separate app registration, no manual URLs:
///
///   • Token acquisition piggybacks on the host's ARM token (ArmScope).
///   • The function app URL is discovered by reading the host's app
///     registration notes (the JIT function app self-registers it via
///     profile.ps1 on cold start).
///   • Authorization at the function app is gated on the caller holding a
///     custom "JIT Requester" RBAC role on the function app site resource.
///
/// Tray menu under a single "JIT Access" parent:
///   • My Active Rules — server-side list with countdown timers + Revoke.
///   • Browse Resources — the user's own ARM resources, discovered client-side.
///   • Post-grant ARM verification — independently confirms the rule was
///     written to the resource via ARM.
///   • Justification prompts — shown before granting when target requires it.
/// </summary>
public sealed class JitAzAccessPlugin : ITrayPlugin, IMenuChangeNotifier, IBadgeProvider, IPluginTestProvider, IDisposable
{
    // ── Events ────────────────────────────────────────────────────────────────

    public event Action? MenuChanged;
    public event Action? BadgeChanged;

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
    ///   Graph — used by JitUrlDiscovery (reads the AzureTray app reg tags).
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
                DisplayName: "Read AzureTray app registration tags (auto-discover JIT URL)"),
        };

    // ── IBadgeProvider ────────────────────────────────────────────────────────

    public int Count => _serverRules.Count;

    public BadgeState State
    {
        get
        {
            var rules = _serverRules;   // snapshot the reference (poll swaps it)
            if (rules.Count == 0) return BadgeState.Normal;
            var expiresSoon = rules.Any(r => (r.ExpiresUtc - DateTime.UtcNow).TotalMinutes < 30);
            return expiresSoon ? BadgeState.Pending : BadgeState.Normal;
        }
    }

    public string? BadgeTooltip
    {
        get
        {
            var rules = _serverRules;   // snapshot the reference
            var count = rules.Count;
            if (count == 0) return null;
            var expiring = rules.Count(r => (r.ExpiresUtc - DateTime.UtcNow).TotalMinutes < 30);
            if (expiring == 0)     return $"JIT Access — {count} active";
            if (expiring == count) return $"JIT Access — {expiring} expiring";
            return $"JIT Access — {count} active, {expiring} expiring";
        }
    }

    // ── IPluginTestProvider ───────────────────────────────────────────────────

    public IReadOnlyList<PluginTest> Tests => new[]
    {
        new PluginTest(
            Name:        "Discover JIT function app URL",
            Description: "Reads the AzureTray app registration tags via Graph to confirm the JIT URL is discoverable.",
            Run:         TestDiscoveryAsync),

        new PluginTest(
            Name:        "JIT Function App connectivity",
            Description: "Probes Get-JITRules. Any HTTP response (including 403) confirms the URL is reachable.",
            Run:         TestConnectivityAsync),
    };

    private async Task<PluginTestResult> TestDiscoveryAsync(CancellationToken ct)
    {
        if (_discovery is null || string.IsNullOrWhiteSpace(_tenantId))
            return PluginTestResult.Fail("Plugin not initialised or no active tenant.");

        _context?.Logger.LogInformation("JIT: discovery test invoked for tenant {TenantId}.", _tenantId);

        var result = await _discovery.DiscoverAsync(_tenantId, AzureTrayAppRegistrationName, ct).ConfigureAwait(false);
        if (result.IsEmpty)
        {
            return PluginTestResult.Fail(
                "No JIT function app URL found in AzureTray app reg tags. Ensure the function app has been deployed and started at least once.");
        }

        var urls = result.AllUrls.ToList();
        return PluginTestResult.Pass(
            $"Discovered {urls.Count} URL(s): {string.Join(", ", urls)}");
    }

    private async Task<PluginTestResult> TestConnectivityAsync(CancellationToken ct)
    {
        if (_client is null || string.IsNullOrWhiteSpace(_tenantId) || _urls.IsEmpty)
            return PluginTestResult.Fail("Plugin not initialised, no active tenant, or URL not yet discovered.");

        _context?.Logger.LogInformation(
            "JIT: connectivity test invoked (tenant={TenantId}, urls={Urls}).",
            _tenantId, string.Join(", ", _urls.AllUrls));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

        // Probe Get-JITRules on each function-app URL — any HTTP response
        // (including 403) means the host is reachable and your token was
        // accepted by the runtime. Targets aren't fetched from the function
        // app anymore (they come from ARM Resource Graph directly).
        var report  = new List<string>();
        var anyFail = false;
        foreach (var url in _urls.AllUrls)
        {
            try
            {
                var result = await _client.GetActiveRulesAsync(_tenantId, url, timeoutCts.Token)
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

        var summary = string.Join("; ", report);
        return anyFail ? PluginTestResult.Fail(summary) : PluginTestResult.Pass(summary);
    }

    // ── Internal state ────────────────────────────────────────────────────────

    // displayName of the AzureTray host's per-tenant app registration whose
    // tags carry the jit-baseurl:<sub>=<url> entries. Hardcoded to match the
    // host default; can be made configurable later if needed.
    private const string AzureTrayAppRegistrationName = "AzureTray";

    // Default UX duration when target.allowedDurations is empty. Per-target
    // overrides are still honoured.
    private const int DefaultDurationHours = 4;

    private IPluginContext?    _context;
    private JitClient?         _client;
    private ArmVerifier?       _verifier;
    private ActiveRulesStore?  _localStore;
    private JitUrlDiscovery?   _discovery;
    private ResourceDiscovery? _resources;
    private FavoritesStore?    _favorites;

    private string _tenantId = string.Empty;

    // All discovered function-app URLs for this tenant. Per-subscription map
    // plus the legacy single URL fallback.
    private JitUrlDiscoveryResult _urls = JitUrlDiscoveryResult.Empty;

    private List<JitTarget>     _targets     = new();
    private List<JitServerRule> _serverRules = new();
    private DateTime            _targetsAt   = DateTime.MinValue;

    // The caller's current public IP as the function app sees it (from the
    // Get-JITRules X-JIT-Caller-IP header). Used to flag resources whose
    // firewall already permanently allows this IP so we don't re-request.
    private volatile string?    _callerIp;

    // Re-entrancy guard for PollAsync. The 90s timer plus the many manual
    // `_ = PollAsync()` triggers (refresh, post-grant, post-revoke, retry) could
    // otherwise overlap and race the shared _serverRules/_targets/_*At state.
    private int _polling;
    private DateTime            _rulesAt     = DateTime.MinValue;

    private readonly object          _busyLock = new();
    private readonly HashSet<string> _busyKeys = new(StringComparer.Ordinal);

    private Timer? _pollTimer;
    private bool   _pollSuspended;

    // Authentication/authorization state — set when polls return 401/403,
    // cleared on the next successful response. Used to (a) surface a status
    // line in the menu, (b) push a one-shot toast so the user notices, and
    // (c) suppress repeat toasts until the status code changes.
    private bool _authBlocked;
    private int  _authBlockedStatus;
    private static readonly TimeSpan TargetsTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RulesTtl   = TimeSpan.FromSeconds(90);

    private bool IsReady =>
        !string.IsNullOrWhiteSpace(_tenantId) && !_urls.IsEmpty;

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

        // Auto-select the first already-signed-in tenant, if any.
        if (context.ReadyTenants.Count > 0)
            _ = ApplyTenantAndDiscoverAsync(context.ReadyTenants[0], cancellationToken);

        return Task.CompletedTask;
    }

    private async Task ApplyTenantAndDiscoverAsync(PluginTenant tenant, CancellationToken ct)
    {
        var context   = _context;
        var discovery = _discovery;
        if (context is null || discovery is null) return;

        _tenantId = tenant.TenantId;
        context.Logger.LogInformation(
            "JIT: using tenant {TenantId} ({DisplayName}).", tenant.TenantId, tenant.DisplayName);

        _urls = await discovery.DiscoverAsync(_tenantId, AzureTrayAppRegistrationName, ct)
            .ConfigureAwait(false);

        if (_urls.IsEmpty)
        {
            context.Logger.LogWarning(
                "JIT: could not discover any function app URL — plugin will display 'not deployed' state.");
            MenuChanged?.Invoke();
            return;
        }

        StartPollTimer();
        MenuChanged?.Invoke();
    }

    private void StartPollTimer()
    {
        _pollTimer ??= new Timer(_ => _ = PollAsync(), null,
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

    // ── Background polling ────────────────────────────────────────────────────

    private async Task PollAsync()
    {
        var context = _context;
        var client  = _client;
        if (context is null || client is null || !IsReady || _pollSuspended) return;

        // Skip if a poll is already running — overlapping runs race the shared
        // _serverRules/_targets/_*At state (last-writer-wins). Cheap CAS guard.
        if (Interlocked.Exchange(ref _polling, 1) == 1) return;
        try
        {
            await PollCoreAsync(context, client).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Exchange(ref _polling, 0);
        }
    }

    private async Task PollCoreAsync(IPluginContext context, JitClient client)
    {
        var now     = DateTime.UtcNow;
        var changed = false;
        var urls    = _urls.AllUrls.ToList();

        if (now - _targetsAt > TargetsTtl && _resources is not null)
        {
            // Targets are discovered client-side from ARM Resource Graph using
            // the user's own token. One call returns every NSG / SQL server /
            // storage account / Key Vault the user has ARM read access to
            // across all visible subscriptions — no need for the function app
            // to serve a curated manifest.
            try
            {
                var targets = await _resources
                    .DiscoverAsync(_tenantId, CancellationToken.None)
                    .ConfigureAwait(false);
                _targets   = targets;
                _targetsAt = now;
                changed    = true;
                context.Logger.LogDebug("JIT: discovered {Count} target(s) via Resource Graph.", targets.Count);
            }
            catch (ArgumentException ex) when (IsTenantNotEnabled(ex))
            {
                SuspendForTenantMismatch("resource discovery");
                return;
            }
            catch (Exception ex)
            {
                context.Logger.LogWarning(ex, "JIT: resource discovery failed.");
            }
        }

        if (now - _rulesAt > RulesTtl)
        {
            var allRules = new List<JitServerRule>();
            var anySucceeded = false;

            foreach (var url in urls)
            {
                try
                {
                    var result = await client
                        .GetActiveRulesAsync(_tenantId, url, CancellationToken.None)
                        .ConfigureAwait(false);
                    // Tag each rule with the URL it came from so Revoke can route correctly.
                    foreach (var rule in result.Rules)
                        allRules.Add(rule with { SourceFunctionAppUrl = url });
                    // Cache the caller IP the function reported so BuildTargetItem
                    // can flag resources whose firewall already allows it.
                    if (!string.IsNullOrEmpty(result.CallerIp))
                        _callerIp = result.CallerIp;
                    anySucceeded = true;
                    context.Logger.LogDebug("JIT: refreshed {Count} active rule(s) from {Url}.", result.Rules.Count, url);
                }
                catch (ArgumentException ex) when (IsTenantNotEnabled(ex))
                {
                    SuspendForTenantMismatch("rules refresh");
                    return;
                }
                catch (JitHttpException ex) when (ex.StatusCode is 401 or 403)
                {
                    NotifyAuthBlocked(ex, url);
                }
                catch (Exception ex)
                {
                    context.Logger.LogWarning(ex, "JIT: rules refresh failed for {Url}.", url);
                }
            }

            if (anySucceeded)
            {
                _serverRules = allRules;
                _rulesAt     = now;
                changed      = true;
                ClearAuthBlocked();
            }
        }

        if (changed)
        {
            BadgeChanged?.Invoke();
            MenuChanged?.Invoke();
        }
    }

    private static bool IsTenantNotEnabled(ArgumentException ex) =>
        ex.ParamName == "tenantId" || ex.Message.Contains("is not enabled for plugin");

    private void SuspendForTenantMismatch(string operation)
    {
        _pollSuspended = true;
        _pollTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        _context?.Logger.LogError(
            "JIT: tenant {TenantId} is not enabled for this plugin (operation: {Operation}). " +
            "Enable the plugin for that tenant in AzureTray settings. Polling suspended.",
            _tenantId, operation);
        MenuChanged?.Invoke();
    }

    /// <summary>
    /// Called when a poll returns 401/403. Sets the auth-blocked state and
    /// pushes a one-shot toast. Subsequent failures don't repeat the toast
    /// until <see cref="ClearAuthBlocked"/> resets the state.
    /// </summary>
    private void NotifyAuthBlocked(JitHttpException ex, string url)
    {
        var context = _context;
        if (context is null) return;

        // Suppress repeat toasts when the status hasn't changed.
        if (_authBlocked && _authBlockedStatus == ex.StatusCode)
        {
            context.Logger.LogDebug(
                "JIT: still auth-blocked ({Status}) on {Url} — suppressing duplicate toast.", ex.StatusCode, url);
            return;
        }

        _authBlocked       = true;
        _authBlockedStatus = ex.StatusCode;

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
                    new NotificationDetail("Status",   ex.StatusCode.ToString()),
                    new NotificationDetail("Endpoint", url),
                    new NotificationDetail("Server",   ex.ServerError ?? ex.Message),
                },
            },
            CancellationToken.None);

        MenuChanged?.Invoke();
    }

    /// <summary>Clears the auth-blocked state after a successful poll.</summary>
    private void ClearAuthBlocked()
    {
        if (!_authBlocked) return;
        _authBlocked       = false;
        _authBlockedStatus = 0;
        _context?.Logger.LogInformation("JIT: authorization restored — polls succeeding again.");
        MenuChanged?.Invoke();
    }

    // ── Menu entry point ──────────────────────────────────────────────────────

    public IReadOnlyList<PluginMenuItem> GetMenuItems()
    {
        // Top-level label reflects current state: count of active rules, plus
        // any error indicators. Single item — no Active / Browse split.
        var label = _pollSuspended || _authBlocked
            ? "🔑  JIT Access  ⚠"
            : _serverRules.Count > 0
                ? $"🔑  JIT Access  ({_serverRules.Count})"
                : "🔑  JIT Access";

        return new[] {
            new PluginMenuItem(
                Text:              label,
                SearchProvider:    BuildSearchItems,
                SearchPlaceholder: "Filter by name or environment…")
        };
    }

    /// <summary>
    /// Single source of truth for the menu body. Handles every state: no tenant,
    /// no URL, loading, no targets, no matches, auth-blocked, and the normal
    /// list-of-targets case. Active rules surface inline on each target row.
    /// </summary>
    private IReadOnlyList<PluginMenuItem> BuildSearchItems(string query)
    {
        var items = new List<PluginMenuItem>();

        if (string.IsNullOrWhiteSpace(_tenantId))
        {
            items.Add(new PluginMenuItem("⚙ Sign in to a tenant to enable JIT access.", IsEnabled: false));
            return items;
        }

        if (_urls.IsEmpty)
        {
            items.Add(new PluginMenuItem("⚠ JIT function app URL not yet discovered.",  IsEnabled: false));
            items.Add(new PluginMenuItem("  Deploy the JIT function app in this tenant.", IsEnabled: false));
            items.Add(PluginMenuItem.Separator);
            items.Add(new PluginMenuItem(
                Text:         "↻ Retry discovery",
                Invoke:       () => _ = RetryDiscoveryAsync(),
                Icon:         "↻",
                KeepMenuOpen: true));
            return items;
        }

        if (_authBlocked)
        {
            items.Add(new PluginMenuItem(
                $"⚠ Missing '{JitRequesterRoleNameDefault}' role — see notification.", IsEnabled: false));
            items.Add(PluginMenuItem.Separator);
        }

        if (_pollSuspended)
        {
            items.Add(new PluginMenuItem(
                $"⚠ Tenant {_tenantId} not enabled for this plugin.", IsEnabled: false));
            items.Add(PluginMenuItem.Separator);
        }

        if (_targets.Count == 0 && _targetsAt == DateTime.MinValue)
        {
            items.Add(new PluginMenuItem("  Loading targets…", IsEnabled: false));
            return items;
        }

        if (_targets.Count == 0)
        {
            items.Add(new PluginMenuItem(
                "  No targets configured — add entries to jit-config/targets.json in storage.",
                IsEnabled: false));
            return items;
        }

        var filtered = string.IsNullOrWhiteSpace(query)
            ? _targets
            : _targets.Where(t =>
                t.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                t.ResourceName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                (t.Environment?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                t.TargetType.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();

        if (filtered.Count == 0)
        {
            items.Add(new PluginMenuItem("  No matching resources.", IsEnabled: false));
            return items;
        }

        // Favorites float to the top. Within each group (favorites / rest)
        // sort by environment then display name.
        items.AddRange(filtered
            .OrderByDescending(t => _favorites?.IsFavorite(t.Id) ?? false)
            .ThenBy(t => t.Environment)
            .ThenBy(t => t.DisplayName)
            .Select(BuildTargetItem));

        items.Add(PluginMenuItem.Separator);
        items.Add(new PluginMenuItem(
            Text:         "↻ Refresh",
            Invoke:       () =>
            {
                _context?.Logger.LogDebug("JIT: manual refresh requested from menu.");
                _targetsAt = DateTime.MinValue;
                _rulesAt   = DateTime.MinValue;
                _          = PollAsync();
            },
            Icon:         "↻",
            KeepMenuOpen: true));

        return items;
    }

    // Display string mentioned in the menu when auth is blocked. The actual
    // role name comes from the server; this is purely a hint to the user.
    private const string JitRequesterRoleNameDefault = "JIT Requester";

    private async Task RetryDiscoveryAsync()
    {
        if (_context is null || _discovery is null || string.IsNullOrWhiteSpace(_tenantId)) return;

        _context.Logger.LogDebug("JIT: manual discovery retry requested.");
        var result = await _discovery.DiscoverAsync(_tenantId, AzureTrayAppRegistrationName, CancellationToken.None)
            .ConfigureAwait(false);

        if (!result.IsEmpty)
        {
            _urls           = result;
            _pollSuspended  = false;
            _targetsAt      = DateTime.MinValue;
            _rulesAt        = DateTime.MinValue;
            StartPollTimer();
        }
        MenuChanged?.Invoke();
    }

    // ── Target row ────────────────────────────────────────────────────────────

    private PluginMenuItem BuildTargetItem(JitTarget target)
    {
        var envBadge   = string.IsNullOrEmpty(target.Environment) ? string.Empty : $"[{target.Environment.ToUpper()}] ";
        var isFavorite = _favorites?.IsFavorite(target.Id) ?? false;

        // Toggled by the host when the user clicks the row's favorite star.
        // Persists to the local store; the host flips the glyph in place, so we
        // don't raise MenuChanged here (the open target submenu wouldn't be
        // refreshed by it anyway — only the next open re-sorts favorites up).
        void ToggleFavorite()
        {
            var now = _favorites?.Toggle(target.Id);
            _context?.Logger.LogInformation(
                "JIT: {Action} favorite for {ResourceName} (id={Id}).",
                now == true ? "added" : "removed", target.ResourceName, target.Id);
        }

        var activeRule = _serverRules.FirstOrDefault(r =>
            string.Equals(r.SubscriptionId, target.SubscriptionId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ResourceGroup,  target.ResourceGroup,  StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ResourceName,   target.ResourceName,   StringComparison.OrdinalIgnoreCase));

        if (activeRule is not null)
        {
            var r         = activeRule;
            var remaining = r.ExpiresUtc - DateTime.UtcNow;
            // Greyed-out row with the "active" suffix + countdown. The favorite
            // star sits on the right (toggled via OnToggleFavorite); right-click
            // reveals Copy rule ID and Revoke (no hover-expanding submenu).
            return new PluginMenuItem(
                Text:             $"  ✓ {envBadge}{target.DisplayName}  — active ({FormatTimeRemaining(remaining)})",
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
                        Invoke: () => _ = ConfirmRevokeAsync(r)),
                });
        }

        // Already permanently whitelisted? If the caller's current IP is an
        // exact match for an existing firewall entry on this resource, there's
        // nothing to request — show it greyed like an active rule. Exact match
        // only (ip or ip/32); no CIDR-coverage evaluation.
        var callerIp = _callerIp;
        if (!string.IsNullOrEmpty(callerIp) &&
            (target.WhitelistedIps.Contains(callerIp) || target.WhitelistedIps.Contains(callerIp + "/32")))
        {
            return new PluginMenuItem(
                Text:             $"  ✓ {envBadge}{target.DisplayName}  — IP already allowed",
                IsEnabled:        false,
                Icon:             "✓",
                IsFavorite:       isFavorite,
                OnToggleFavorite: ToggleFavorite);
        }

        // Single-click target rows. Duration is asked via a ChoiceRequest
        // popup (same pattern as the PIM plugin's activation duration prompt).
        // The favorite star sits on the right of the row (toggled via
        // OnToggleFavorite) — no submenu, so a click on the row name goes
        // straight to the grant prompt.
        var targetPrefix = $"{target.TargetType}|{target.SubscriptionId}|{target.ResourceGroup}|{target.ResourceName}|";
        bool isBusy;
        lock (_busyLock) isBusy = _busyKeys.Any(k => k.StartsWith(targetPrefix, StringComparison.Ordinal));

        var isProd = string.Equals(target.Environment, "prod", StringComparison.OrdinalIgnoreCase);
        return new PluginMenuItem(
            Text:             $"  {envBadge}{target.DisplayName}",
            Icon:             isProd ? "⚠" : null,
            Invoke:           isBusy ? null : () => _ = PromptAndGrantAsync(target),
            IsEnabled:        !isBusy,
            IsBusy:           isBusy,
            KeepMenuOpen:     false,
            IsFavorite:       isFavorite,
            OnToggleFavorite: ToggleFavorite);
    }

    /// <summary>
    /// Single-click entry point on a target row. Pops a ChoiceRequest asking
    /// for the grant duration (same pattern as the PIM plugin's activation
    /// flow), then hands off to the existing grant flow.
    /// </summary>
    private async Task PromptAndGrantAsync(JitTarget target)
    {
        var context = _context;
        if (context is null) return;

        var durations = BuildDurationList(DefaultDurationHours, target.AllowedDurations);
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
                "JIT: unknown duration choice '{Choice}' for {ResourceName}.",
                picked, target.ResourceName);
            return;
        }

        var hours      = durations[idx];
        var requestKey = $"{target.TargetType}|{target.SubscriptionId}|{target.ResourceGroup}|{target.ResourceName}|{hours}";
        await GrantFromTargetAsync(target, hours, requestKey).ConfigureAwait(false);
    }

    // ── Grant flow ───────────────────────────────────────────────────────────

    private async Task GrantFromTargetAsync(JitTarget target, int durationHours, string requestKey)
    {
        var context = _context;
        var client  = _client;
        if (context is null || client is null) return;

        string? justification = null;
        if (target.RequiresJustification)
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
        var grantUrl = _urls.UrlForSubscription(target.SubscriptionId);
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
                .RequestAccessAsync(_tenantId, grantUrl, request, CancellationToken.None)
                .ConfigureAwait(false);

            _localStore?.Add(new ActiveRule(
                RuleId:         response.RuleId,
                TenantId:       _tenantId,
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

            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Granted ✓",
                    Message: $"{target.DisplayName} — {durationHours}h access granted.\n" +
                             $"Expires {response.ExpiresUtc:HH:mm} UTC  |  Rule: {response.RuleId}")
                { Severity = NotificationSeverity.Success },
                CancellationToken.None);

            _ = VerifyAndNotifyAsync(response, context);
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
            _rulesAt = DateTime.MinValue;
            _ = PollAsync();
        }
    }

    // ── Revoke flow ───────────────────────────────────────────────────────────

    private async Task ConfirmRevokeAsync(JitServerRule rule)
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
        // from. SourceFunctionAppUrl is tagged during PollAsync; fall back to
        // the per-sub map (then legacy) if it's somehow missing (e.g. a rule
        // from local-store fallback).
        var revokeUrl = !string.IsNullOrEmpty(rule.SourceFunctionAppUrl)
            ? rule.SourceFunctionAppUrl
            : _urls.UrlForSubscription(rule.SubscriptionId);

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
                .RevokeAsync(_tenantId, revokeUrl, rule.RuleId, CancellationToken.None)
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
            _rulesAt = DateTime.MinValue;
            _ = PollAsync();
        }
    }

    // ── ARM post-grant verification ───────────────────────────────────────────

    private async Task VerifyAndNotifyAsync(JitGrantResponse grant, IPluginContext context)
    {
        if (_verifier is null) return;

        var result = await _verifier.VerifyAsync(grant, _tenantId).ConfigureAwait(false);

        switch (result)
        {
            case VerificationResult.Confirmed:
                context.Logger.LogInformation(
                    "JIT ARM verification confirmed: rule {RuleId} visible in {ResourceName}.",
                    grant.RuleId, grant.ResourceName);
                _ = context.Notifier.ShowAsync(
                    new InformationRequest(
                        Title:   "✅ IP Whitelist Confirmed",
                        Message: $"Your IP ({grant.CallerIp}) is confirmed in the Azure resource.\n" +
                                 $"{grant.TargetType}: {grant.ResourceName}")
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
                break;
        }
    }

    // ── Tenant lifecycle ──────────────────────────────────────────────────────

    private void OnTenantReady(PluginTenant tenant)
    {
        if (string.IsNullOrWhiteSpace(_tenantId))
        {
            _context?.Logger.LogInformation(
                "JIT: TenantReady fired for {TenantId} ({DisplayName}); applying.",
                tenant.TenantId, tenant.DisplayName);
            _ = ApplyTenantAndDiscoverAsync(tenant, CancellationToken.None);
        }
        else
        {
            _context?.Logger.LogDebug(
                "JIT: TenantReady fired for {TenantId} ({DisplayName}); already using {Active} — ignored.",
                tenant.TenantId, tenant.DisplayName, _tenantId);
        }
    }

    private void OnTenantRemoved(string tenantId)
    {
        if (string.Equals(_tenantId, tenantId, StringComparison.OrdinalIgnoreCase))
        {
            _pollTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            // Reassign new empty lists rather than .Clear() — a concurrent poll
            // / menu build / badge read enumerates these, and clearing in place
            // can throw "collection modified". Reference swap is atomic.
            _serverRules = new();
            _targets     = new();
            _targetsAt   = DateTime.MinValue;
            _rulesAt     = DateTime.MinValue;
            _callerIp    = null;
            _tenantId    = string.Empty;
            _urls        = JitUrlDiscoveryResult.Empty;
            BadgeChanged?.Invoke();
            MenuChanged?.Invoke();
            _context?.Logger.LogWarning(
                "JIT: active tenant {TenantId} signed out. Plugin suspended until another tenant is ready.", tenantId);
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

    private static string TargetTypeLabel(string targetType) => targetType switch
    {
        "nsg"            => "NSG",
        "sqlServer"      => "SQL",
        "storageAccount" => "Storage",
        "keyVault"       => "Key Vault",
        _                => targetType,
    };

    private static int[] BuildDurationList(int defaultDuration, int[]? allowed)
    {
        var standard = allowed is { Length: > 0 } ? allowed : new[] { 1, 2, 4, 8 };
        return new[] { defaultDuration }
            .Concat(standard.Where(d => d != defaultDuration))
            .Distinct()
            .ToArray();
    }

}
