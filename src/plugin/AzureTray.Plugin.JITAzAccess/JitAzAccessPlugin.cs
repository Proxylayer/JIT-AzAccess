using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using AzureTray.Plugin.JITAzAccess.Models;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// AzureTray plugin for JIT-AzAccess.
///
/// Tray menu features:
///   • My Active Rules — server-side list with countdown timers and one-click Revoke.
///   • Browse Resources — server-controlled manifest of all enabled targets, searchable.
///     Already-active entries are greyed out with a ✓ and time-remaining label.
///   • Post-grant ARM verification — after the function app confirms a grant the plugin
///     independently calls ARM to verify the rule was written to the resource.
///   • Justification prompts — shown before granting when a target requires it.
///   • PIM gate — the server rejects calls without the JIT.Requester role in the token.
/// </summary>
public sealed class JitAzAccessPlugin : ITrayPlugin, IMenuChangeNotifier, IPluginConfigurable, IDisposable
{
    // ── Events ────────────────────────────────────────────────────────────────

    public event Action? MenuChanged;
    public event Action? ValuesChanged;

    // ── Input validation mirrors server-side rules in Request-JITAccess/run.ps1 ─

    private static readonly Regex GuidPattern = new(
        @"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$",
        RegexOptions.Compiled);

    private static readonly Regex ResourceGroupPattern = new(
        @"^[a-zA-Z0-9._\-()]{1,90}$",
        RegexOptions.Compiled);

    private static readonly Regex ResourceNamePattern = new(
        @"^[a-zA-Z0-9._\-]{1,90}$",
        RegexOptions.Compiled);

    private static readonly Regex PortPattern = new(
        @"^\d{1,5}(-\d{1,5})?$",
        RegexOptions.Compiled);

    // ── ITrayPlugin ───────────────────────────────────────────────────────────

    public string Id          => "net.proxylayer.AzureTray.Plugin.JITAzAccess";
    public string DisplayName => "JIT Azure Access";
    public string Version     => "0.1.0";
    public int    ApiVersion  => PluginApiVersion.Current;

    // ── IPluginConfigurable ───────────────────────────────────────────────────

    private const string KeyFunctionAppUrl  = "functionAppUrl";
    private const string KeyJitScope        = "jitScope";
    private const string KeyTenantId        = "tenantId";
    private const string KeyDefaultDuration = "defaultDurationHours";

    private string _functionAppUrl  = string.Empty;
    private string _jitScope        = "api://jit-azaccess/.default";
    private string _tenantId        = string.Empty;
    private int    _defaultDuration = 4;

    public IReadOnlyList<PluginOption> Options => new PluginOption[]
    {
        new(KeyFunctionAppUrl,
            "Function App URL",
            PluginOptionKind.Text,
            "Base URL of the JIT-AzAccess function app " +
            "(e.g. https://func-jitazaccess-xyz.azurewebsites.net)"),

        new(KeyJitScope,
            "JWT Audience Scope",
            PluginOptionKind.Text,
            "OAuth scope used to acquire the JIT bearer token " +
            "(e.g. api://jit-azaccess/.default)",
            DefaultValue: "api://jit-azaccess/.default"),

        new(KeyTenantId,
            "Azure Tenant ID",
            PluginOptionKind.Text,
            "Tenant ID that the JIT function app is deployed to"),

        new(KeyDefaultDuration,
            "Default Duration (hours)",
            PluginOptionKind.Number,
            "Default grant window in hours shown as the first option (1–24)",
            DefaultValue: 4),
    };

    public IReadOnlyDictionary<string, object?> Values => new Dictionary<string, object?>
    {
        [KeyFunctionAppUrl]  = _functionAppUrl,
        [KeyJitScope]        = _jitScope,
        [KeyTenantId]        = _tenantId,
        [KeyDefaultDuration] = (object?)_defaultDuration,
    };

    public void SetValue(string key, object? value)
    {
        switch (key)
        {
            case KeyFunctionAppUrl:
                _functionAppUrl = value as string ?? string.Empty;
                break;

            case KeyJitScope:
                _jitScope = string.IsNullOrWhiteSpace(value as string)
                    ? "api://jit-azaccess/.default"
                    : (string)value!;
                break;

            case KeyTenantId:
                _tenantId = value as string ?? string.Empty;
                break;

            case KeyDefaultDuration:
                _defaultDuration = value switch
                {
                    int    i => i,
                    long   l => (int)l,
                    double d => (int)d,
                    _        => 4,
                };
                break;
        }

        ValuesChanged?.Invoke();
        MenuChanged?.Invoke();
    }

    public object? BuildSettingsView() => null;

    // ── Internal state ────────────────────────────────────────────────────────

    private IPluginContext?   _context;
    private JitClient?        _client;
    private ArmVerifier?      _verifier;
    private ActiveRulesStore? _localStore;

    // Server-fetched data
    private List<JitTarget>     _targets     = new();
    private List<JitServerRule> _serverRules = new();
    private DateTime            _targetsAt   = DateTime.MinValue;
    private DateTime            _rulesAt     = DateTime.MinValue;

    // Busy-state for in-flight grant requests
    private readonly object          _busyLock = new();
    private readonly HashSet<string> _busyKeys = new(StringComparer.Ordinal);

    // Background refresh timer
    private Timer? _pollTimer;
    private static readonly TimeSpan TargetsTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RulesTtl   = TimeSpan.FromSeconds(90);

    private bool IsConfigured =>
        !string.IsNullOrWhiteSpace(_functionAppUrl) &&
        !string.IsNullOrWhiteSpace(_jitScope)       &&
        !string.IsNullOrWhiteSpace(_tenantId);

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public Task InitializeAsync(IPluginContext context, CancellationToken cancellationToken)
    {
        _context    = context;
        _client     = new JitClient(context);
        _verifier   = new ArmVerifier(context);
        _localStore = new ActiveRulesStore(context.DataDir);

        context.Logger.LogInformation(
            "JIT Azure Access plugin initialised. Configured: {IsConfigured}.", IsConfigured);

        if (IsConfigured)
        {
            // Kick off an immediate background fetch so the menu is populated quickly.
            _pollTimer = new Timer(_ => _ = PollAsync(), null,
                TimeSpan.Zero, TimeSpan.FromSeconds(90));
        }

        return Task.CompletedTask;
    }

    public async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        if (_pollTimer is not null)
        {
            await _pollTimer.DisposeAsync().ConfigureAwait(false);
            _pollTimer = null;
        }
        _context = null;
        _client  = null;
    }

    public void Dispose()
    {
        _pollTimer?.Dispose();
        _pollTimer = null;
    }

    // ── Background polling ────────────────────────────────────────────────────

    private async Task PollAsync()
    {
        var context = _context;
        var client  = _client;
        if (context is null || client is null || !IsConfigured) return;

        var now     = DateTime.UtcNow;
        var changed = false;

        if (now - _targetsAt > TargetsTtl)
        {
            try
            {
                var targets = await client
                    .GetTargetsAsync(_tenantId, _functionAppUrl, _jitScope, CancellationToken.None)
                    .ConfigureAwait(false);
                _targets   = targets;
                _targetsAt = now;
                changed    = true;
                context.Logger.LogDebug("JIT: refreshed {Count} target(s).", targets.Count);
            }
            catch (Exception ex)
            {
                context.Logger.LogWarning(ex, "JIT: target refresh failed.");
            }
        }

        if (now - _rulesAt > RulesTtl)
        {
            try
            {
                var rules = await client
                    .GetActiveRulesAsync(_tenantId, _functionAppUrl, _jitScope, CancellationToken.None)
                    .ConfigureAwait(false);
                _serverRules = rules;
                _rulesAt     = now;
                changed      = true;
                context.Logger.LogDebug("JIT: refreshed {Count} active rule(s).", rules.Count);
            }
            catch (Exception ex)
            {
                context.Logger.LogWarning(ex, "JIT: rules refresh failed.");
            }
        }

        if (changed) MenuChanged?.Invoke();
    }

    // ── Menu entry point ──────────────────────────────────────────────────────

    public IReadOnlyList<PluginMenuItem> GetMenuItems()
    {
        if (!IsConfigured)
        {
            return new[]
            {
                new PluginMenuItem(
                    "⚙ Configure JIT Azure Access in Settings → Plugins",
                    IsEnabled: false),
            };
        }

        return new PluginMenuItem[]
        {
            BuildActiveRulesItem(),
            PluginMenuItem.Separator,
            BuildBrowseItem(),
        };
    }

    // ── Active Rules submenu ──────────────────────────────────────────────────

    private PluginMenuItem BuildActiveRulesItem()
    {
        // Prefer server-side rules; fall back to locally-tracked store when offline.
        var rules  = _serverRules.Count > 0
            ? _serverRules.OrderBy(r => r.ExpiresUtc).ToList()
            : _localStore!.GetActive()
                          .Select(ToServerRule)
                          .OrderBy(r => r.ExpiresUtc)
                          .ToList();

        var label = rules.Count > 0
            ? $"🟢 My Active Rules ({rules.Count})"
            : "⚫ My Active Rules (none)";

        var children = new List<PluginMenuItem>();
        var now      = DateTime.UtcNow;

        foreach (var rule in rules)
        {
            var r         = rule;
            var remaining = r.ExpiresUtc - now;
            var timeLeft  = FormatTimeRemaining(remaining);

            var text = string.IsNullOrEmpty(r.Port)
                ? $"  {r.TargetType}: {r.ResourceName}  ({timeLeft})"
                : $"  {r.TargetType}: {r.ResourceName}:{r.Port}  ({timeLeft})";

            var ruleChildren = new List<PluginMenuItem>
            {
                new(
                    Text:         "  📋 Copy rule ID",
                    Invoke:       () => _context?.Clipboard.SetText(r.RuleId),
                    KeepMenuOpen: true),
                PluginMenuItem.Separator,
                new(
                    Text:   "  🗑 Revoke access",
                    Invoke: () => _ = ConfirmRevokeAsync(r)),
            };

            children.Add(new PluginMenuItem(
                Text:     text,
                Icon:     remaining.TotalMinutes < 30 ? "⚠" : null,
                Children: ruleChildren));
        }

        if (children.Count == 0)
            children.Add(new PluginMenuItem("  (none)", IsEnabled: false));

        children.Add(PluginMenuItem.Separator);
        children.Add(new PluginMenuItem(
            Text:         "↻ Refresh",
            Invoke:       () => _ = PollAsync(),
            Icon:         "↻",
            KeepMenuOpen: true));

        return new PluginMenuItem(Text: label, Children: children);
    }

    // ── Browse Resources submenu ──────────────────────────────────────────────

    private PluginMenuItem BuildBrowseItem()
    {
        if (_targets.Count == 0 && _targetsAt == DateTime.MinValue)
        {
            return new PluginMenuItem(
                Text:     "🔍 Browse Resources…",
                Children: new[] { new PluginMenuItem("  Loading targets…", IsEnabled: false) });
        }

        return new PluginMenuItem(
            Text:              "🔍 Browse Resources…",
            SearchProvider:    BuildTargetItems,
            SearchPlaceholder: "Filter by name or environment…");
    }

    private IReadOnlyList<PluginMenuItem> BuildTargetItems(string query)
    {
        if (_targets.Count == 0)
        {
            return new[]
            {
                new PluginMenuItem(
                    "  No targets configured — add entries to jit-config/targets.json in storage.",
                    IsEnabled: false),
            };
        }

        var filtered = string.IsNullOrWhiteSpace(query)
            ? _targets
            : _targets.Where(t =>
                t.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                t.ResourceName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                (t.Environment?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                t.TargetType.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();

        if (filtered.Count == 0)
            return new[] { new PluginMenuItem("  No matching resources.", IsEnabled: false) };

        return filtered
            .OrderBy(t => t.Environment)
            .ThenBy(t => t.DisplayName)
            .Select(BuildTargetItem)
            .ToList();
    }

    private PluginMenuItem BuildTargetItem(JitTarget target)
    {
        var envBadge  = string.IsNullOrEmpty(target.Environment) ? string.Empty : $"[{target.Environment.ToUpper()}] ";
        var typeLabel = TargetTypeLabel(target.TargetType);

        // Check if this target already has an active server-side rule.
        var activeRule = _serverRules.FirstOrDefault(r =>
            string.Equals(r.SubscriptionId, target.SubscriptionId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ResourceGroup,  target.ResourceGroup,  StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ResourceName,   target.ResourceName,   StringComparison.OrdinalIgnoreCase));

        if (activeRule is not null)
        {
            var remaining = activeRule.ExpiresUtc - DateTime.UtcNow;
            return new PluginMenuItem(
                Text:      $"  ✓ {envBadge}{typeLabel}: {target.DisplayName}  ({FormatTimeRemaining(remaining)})",
                IsEnabled: false,
                Icon:      "✓");
        }

        var durations = BuildDurationList(_defaultDuration, target.AllowedDurations);

        var children = durations.Select(h =>
        {
            var hours      = h;
            var requestKey = $"{target.TargetType}|{target.SubscriptionId}|{target.ResourceGroup}|{target.ResourceName}|{hours}";
            bool isBusy;
            lock (_busyLock) isBusy = _busyKeys.Contains(requestKey);

            return new PluginMenuItem(
                Text:         $"  Grant {hours}h access",
                Invoke:       isBusy ? null : () => _ = GrantFromTargetAsync(target, hours, requestKey),
                IsEnabled:    !isBusy,
                IsBusy:       isBusy,
                KeepMenuOpen: true);
        }).ToList();

        var isProd = string.Equals(target.Environment, "prod", StringComparison.OrdinalIgnoreCase);
        return new PluginMenuItem(
            Text:     $"  {envBadge}{typeLabel}: {target.DisplayName}",
            Icon:     isProd ? "⚠" : null,
            Children: children);
    }

    // ── Grant flow (target manifest path) ────────────────────────────────────

    private async Task GrantFromTargetAsync(JitTarget target, int durationHours, string requestKey)
    {
        var context = _context;
        var client  = _client;
        if (context is null || client is null) return;

        // Optional justification prompt.
        string? justification = null;
        if (target.RequiresJustification)
        {
            var result = await context.Notifier.ShowAsync(
                new TextInputRequest(
                    Title:       "Justification Required",
                    Message:     $"Provide a reason for requesting access to \"{target.DisplayName}\".",
                    Placeholder: "e.g. Investigating incident #12345"),
                CancellationToken.None).ConfigureAwait(false);

            if (result is not TextInputResult { Text: { Length: > 0 } text }) return;
            justification = text;
        }

        // Extra confirmation for production.
        var isProd = string.Equals(target.Environment, "prod", StringComparison.OrdinalIgnoreCase);
        if (isProd)
        {
            var confirm = await context.Notifier.ShowAsync(
                new YesNoRequest(
                    Title:   "⚠ Production Resource",
                    Message: $"You are about to grant yourself {durationHours}h access to the PRODUCTION resource " +
                             $"\"{target.DisplayName}\" ({target.TargetType}: {target.ResourceName}).\n\nContinue?"),
                CancellationToken.None).ConfigureAwait(false);

            if (confirm is not YesNoResult { Accepted: true }) return;
        }

        lock (_busyLock)
        {
            if (!_busyKeys.Add(requestKey)) return;
        }
        MenuChanged?.Invoke();

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
                .RequestAccessAsync(_tenantId, _functionAppUrl, _jitScope, request, CancellationToken.None)
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
                             $"Expires {response.ExpiresUtc:HH:mm} UTC  |  Rule: {response.RuleId}"),
                CancellationToken.None);

            // ARM verification is fire-and-forget; shows a follow-up toast.
            _ = VerifyAndNotifyAsync(response, context);
        }
        catch (Exception ex)
        {
            context.Logger.LogError(ex, "JIT grant failed for {ResourceName}.", target.ResourceName);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Failed",
                    Message: $"{target.DisplayName} — {ex.Message}"),
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

        if (confirm is not YesNoResult { Accepted: true }) return;

        try
        {
            await client
                .RevokeAsync(_tenantId, _functionAppUrl, _jitScope, rule.RuleId, CancellationToken.None)
                .ConfigureAwait(false);

            context.Logger.LogInformation("JIT rule revoked: {RuleId}.", rule.RuleId);

            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "JIT Access Revoked",
                    Message: $"{rule.TargetType}: {rule.ResourceName} — rule {rule.RuleId} removed."),
                CancellationToken.None);
        }
        catch (Exception ex)
        {
            context.Logger.LogError(ex, "JIT revoke failed for {RuleId}.", rule.RuleId);
            _ = context.Notifier.ShowAsync(
                new InformationRequest(
                    Title:   "Revoke Failed",
                    Message: $"Could not revoke rule {rule.RuleId}: {ex.Message}"),
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
                        Message: $"Your IP ({grant.CallerIp}) was verified in the Azure resource.\n" +
                                 $"{grant.TargetType}: {grant.ResourceName}"),
                    CancellationToken.None);
                break;

            case VerificationResult.NotFound:
                context.Logger.LogWarning(
                    "JIT ARM verification: rule {RuleId} NOT found in {ResourceName} after grant.",
                    grant.RuleId, grant.ResourceName);
                _ = context.Notifier.ShowAsync(
                    new InformationRequest(
                        Title:   "⚠ Whitelist Verification Failed",
                        Message: $"The function app confirmed the grant, but the rule was not yet visible via ARM.\n" +
                                 $"Access may still propagate — wait 30s and retry if needed.\n" +
                                 $"Rule: {grant.RuleId}"),
                    CancellationToken.None);
                break;

            case VerificationResult.Timeout:
                context.Logger.LogWarning("JIT ARM verification timed out for rule {RuleId}.", grant.RuleId);
                break;

            // Skipped / Error — silent; the grant success toast was already shown.
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

    private static JitServerRule ToServerRule(ActiveRule r) => new()
    {
        RuleId         = r.RuleId,
        TargetType     = r.TargetType,
        SubscriptionId = r.SubscriptionId,
        ResourceGroup  = r.ResourceGroup,
        ResourceName   = r.ResourceName,
        Port           = r.Port,
        CallerIp       = string.Empty,
        RequestedBy    = string.Empty,
        ExpiresUtc     = r.ExpiryUtc,
    };
}