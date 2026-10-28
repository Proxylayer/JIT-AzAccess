using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using AzureTray.Plugin.JITAzAccess.Models;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// After a JIT grant succeeds, makes a read-only ARM call to confirm the
/// firewall/network rule was actually written to the resource.
///
/// This catches silent failures where the function app returned 200 but the
/// underlying Azure resource mutation failed or was rolled back.
/// </summary>
internal sealed class ArmVerifier
{
    // ARM API versions — use the latest stable version for each provider.
    private const string NsgApi          = "2024-03-01";
    private const string SqlApi          = "2021-11-01";
    private const string StorageApi      = "2023-01-01";
    private const string KeyVaultApi     = "2023-07-01";
    private const string PostgresApi     = "2024-08-01";
    private const string MySqlApi        = "2023-12-30";
    private const string RedisApi        = "2024-11-01";
    private const string SynapseApi      = "2021-06-01";
    private const string ArmBase         = "https://management.azure.com";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly IPluginContext _context;

    public ArmVerifier(IPluginContext context) => _context = context;

    /// <summary>
    /// Returns <see cref="VerificationResult.Confirmed"/> when the rule/IP is
    /// visible in the resource's current configuration via ARM.
    /// Times out after <paramref name="timeoutMs"/> ms and returns
    /// <see cref="VerificationResult.Timeout"/> rather than blocking the menu.
    /// </summary>
    public async Task<VerificationResult> VerifyAsync(
        JitGrantResponse grant,
        string           tenantId,
        int              timeoutMs = 8_000,
        CancellationToken ct       = default)
    {
        using var timeoutCts = new CancellationTokenSource(timeoutMs);
        using var linked     = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        _context.Logger.LogDebug(
            "JIT ARM verify: starting for {TargetType} {ResourceName} (rule {RuleId}).",
            grant.TargetType, grant.ResourceName, grant.RuleId);

        try
        {
            var result = grant.TargetType switch
            {
                "nsg"            => await VerifyNsgRuleAsync(grant, tenantId, linked.Token),
                "sqlServer"      => await VerifySqlRuleAsync(grant, tenantId, linked.Token),
                "storageAccount" => await VerifyStorageRuleAsync(grant, tenantId, linked.Token),
                "keyVault"       => await VerifyKeyVaultRuleAsync(grant, tenantId, linked.Token),
                "postgresqlFlexibleServer" => await VerifyPostgresRuleAsync(grant, tenantId, linked.Token),

                // Child firewallRules types — a GET of the named rule under the
                // parent resource: 200 => Confirmed, 404 => NotFound.
                "mysqlFlexibleServer" => await VerifyChildFirewallRuleAsync(
                    grant, tenantId, "Microsoft.DBforMySQL/flexibleServers", MySqlApi, linked.Token),
                "redis" => await VerifyChildFirewallRuleAsync(
                    grant, tenantId, "Microsoft.Cache/Redis", RedisApi, linked.Token),
                "synapse" => await VerifyChildFirewallRuleAsync(
                    grant, tenantId, "Microsoft.Synapse/workspaces", SynapseApi, linked.Token),

                // Array/property-based resources (cosmosDb, containerRegistry,
                // aiSearch, cognitiveServices, kusto, iotHub, signalR, eventHub,
                // serviceBus, appService, aks) model their firewall as an ipRules
                // array or an access-restrictions property on the parent rather
                // than an addressable child rule, so there is no child GET to
                // confirm a single rule by id. We deliberately return Skipped
                // rather than fabricate a Confirmed/NotFound. (A parent GET +
                // ipRules scan, as storage/key vault do, is possible later but
                // out of scope here.)
                _                => VerificationResult.Skipped,
            };

            if (result == VerificationResult.Skipped)
                _context.Logger.LogDebug(
                    "JIT ARM verify: no implementation for target type {TargetType} — skipped.",
                    grant.TargetType);

            return result;
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            return VerificationResult.Timeout;
        }
        catch (Exception ex)
        {
            _context.Logger.LogWarning(ex,
                "JIT ARM verify: unexpected error for {TargetType} {ResourceName} (rule {RuleId}).",
                grant.TargetType, grant.ResourceName, grant.RuleId);
            return VerificationResult.Error;
        }
    }

    // ── NSG — check security rule by name ─────────────────────────────────────

    private async Task<VerificationResult> VerifyNsgRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        // GET individual security rule — 200 = exists, 404 = not found.
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.Network/networkSecurityGroups/{grant.ResourceName}" +
                  $"/securityRules/{grant.RuleId}?api-version={NsgApi}";

        using var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return ClassifyRuleProbe(response, url);
    }

    // ── Azure SQL Server — check firewall rule by name ────────────────────────

    private async Task<VerificationResult> VerifySqlRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.Sql/servers/{grant.ResourceName}" +
                  $"/firewallRules/{grant.RuleId}?api-version={SqlApi}";

        using var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return ClassifyRuleProbe(response, url);
    }

    // ── Azure Database for PostgreSQL Flexible Server — check firewall rule by name ──

    private async Task<VerificationResult> VerifyPostgresRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.DBforPostgreSQL/flexibleServers/{grant.ResourceName}" +
                  $"/firewallRules/{grant.RuleId}?api-version={PostgresApi}";

        using var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return ClassifyRuleProbe(response, url);
    }

    // ── Child firewallRules types (MySQL / Redis / Synapse) ───────────────────

    /// <summary>
    /// Verifies a firewall rule that exists as an addressable child resource:
    /// GET <c>.../{armType}/{name}/firewallRules/{ruleId}</c>, classified by
    /// <see cref="ClassifyRuleProbe"/>. <paramref name="armType"/> is the
    /// provider-cased type, e.g. <c>Microsoft.Cache/Redis</c>.
    /// </summary>
    private async Task<VerificationResult> VerifyChildFirewallRuleAsync(
        JitGrantResponse grant, string tenantId, string armType, string apiVersion, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/{armType}/{grant.ResourceName}" +
                  $"/firewallRules/{grant.RuleId}?api-version={apiVersion}";

        using var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return ClassifyRuleProbe(response, url);
    }

    // ── Storage Account — check IP rule by value ──────────────────────────────

    private async Task<VerificationResult> VerifyStorageRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.Storage/storageAccounts/{grant.ResourceName}" +
                  $"?api-version={StorageApi}";

        using var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            _context.Logger.LogWarning(
                "JIT ARM verify (storage): GET {Url} returned {Status}.",
                url, (int)response.StatusCode);
            return VerificationResult.Error;
        }

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);

        if (!doc.RootElement.TryGetProperty("properties", out var props) ||
            !props.TryGetProperty("networkAcls", out var acls))
        {
            _context.Logger.LogWarning(
                "JIT ARM verify (storage): unexpected response shape for {ResourceName} — missing properties.networkAcls.",
                grant.ResourceName);
            return VerificationResult.Error;
        }
        if (!acls.TryGetProperty("ipRules", out var ipRules)) return VerificationResult.NotFound;

        // Exact match only. A prefix match confirms the wrong rule: caller IP
        // 10.1.1.1 "matches" an existing 10.1.1.10 entry, so the user is told
        // their grant landed when nothing was written for them. Storage
        // normalises a /32 away, but accept both spellings rather than depend
        // on that.
        foreach (var rule in ipRules.EnumerateArray())
        {
            if (!rule.TryGetProperty("value", out var v)) continue;
            var value = v.GetString();
            if (string.Equals(value, grant.CallerIp, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, grant.CallerIp + "/32", StringComparison.OrdinalIgnoreCase))
                return VerificationResult.Confirmed;
        }

        return VerificationResult.NotFound;
    }

    // ── Key Vault — check IP rule (CIDR /32) ──────────────────────────────────

    private async Task<VerificationResult> VerifyKeyVaultRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.KeyVault/vaults/{grant.ResourceName}" +
                  $"?api-version={KeyVaultApi}";

        using var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            _context.Logger.LogWarning(
                "JIT ARM verify (keyVault): GET {Url} returned {Status}.",
                url, (int)response.StatusCode);
            return VerificationResult.Error;
        }

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);

        if (!doc.RootElement.TryGetProperty("properties", out var props) ||
            !props.TryGetProperty("networkAcls", out var acls))
        {
            _context.Logger.LogWarning(
                "JIT ARM verify (keyVault): unexpected response shape for {ResourceName} — missing properties.networkAcls.",
                grant.ResourceName);
            return VerificationResult.Error;
        }
        if (!acls.TryGetProperty("ipRules", out var ipRules)) return VerificationResult.NotFound;

        // Key Vault stores the caller IP as a /32 CIDR; accept the bare address
        // too so a server-side normalisation change can't turn every grant into
        // a "verification failed" toast.
        foreach (var rule in ipRules.EnumerateArray())
        {
            if (!rule.TryGetProperty("value", out var v)) continue;
            var value = v.GetString();
            if (string.Equals(value, grant.CallerIp + "/32", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, grant.CallerIp, StringComparison.OrdinalIgnoreCase))
                return VerificationResult.Confirmed;
        }

        return VerificationResult.NotFound;
    }

    // ── Shared ARM helpers ────────────────────────────────────────────────────

    private async Task<HttpResponseMessage> ArmGetAsync(
        string tenantId, string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        return await _context.GetHttpClient(tenantId)
            .SendAsync(PluginHttpClientNames.Arm, _context.ArmScope, request, ct)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Maps the status of a "GET the rule by name" probe to a verification
    /// result.
    /// </summary>
    /// <remarks>
    /// Only a 404 means the rule is genuinely absent. A 403 (no ARM read on the
    /// resource), 429 (throttled) or 5xx says we could not look — and reporting
    /// that as <see cref="VerificationResult.NotFound"/> tells the user their
    /// grant did not take effect when it very likely did. That is a false alarm
    /// on the safe side, but it trains people to ignore the warning, which is
    /// not. Anything that is not a clear yes or a clear no is an Error.
    /// </remarks>
    private VerificationResult ClassifyRuleProbe(HttpResponseMessage response, string url)
    {
        if (response.IsSuccessStatusCode)                   return VerificationResult.Confirmed;
        if (response.StatusCode == HttpStatusCode.NotFound) return VerificationResult.NotFound;

        _context.Logger.LogWarning(
            "JIT ARM verify: GET {Url} returned {Status} — cannot tell whether the rule exists.",
            url, (int)response.StatusCode);
        return VerificationResult.Error;
    }
}

public enum VerificationResult
{
    /// <summary>The rule was found in the resource's current config via ARM.</summary>
    Confirmed,
    /// <summary>The ARM lookup returned but the rule was not present.</summary>
    NotFound,
    /// <summary>The resource type has no ARM verification implementation.</summary>
    Skipped,
    /// <summary>The verification timed out — result unknown.</summary>
    Timeout,
    /// <summary>An error occurred during verification — result unknown.</summary>
    Error,
}
