using System;
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

        var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return response.IsSuccessStatusCode ? VerificationResult.Confirmed : VerificationResult.NotFound;
    }

    // ── Azure SQL Server — check firewall rule by name ────────────────────────

    private async Task<VerificationResult> VerifySqlRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.Sql/servers/{grant.ResourceName}" +
                  $"/firewallRules/{grant.RuleId}?api-version={SqlApi}";

        var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return response.IsSuccessStatusCode ? VerificationResult.Confirmed : VerificationResult.NotFound;
    }

    // ── Azure Database for PostgreSQL Flexible Server — check firewall rule by name ──

    private async Task<VerificationResult> VerifyPostgresRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.DBforPostgreSQL/flexibleServers/{grant.ResourceName}" +
                  $"/firewallRules/{grant.RuleId}?api-version={PostgresApi}";

        var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return response.IsSuccessStatusCode ? VerificationResult.Confirmed : VerificationResult.NotFound;
    }

    // ── Child firewallRules types (MySQL / Redis / Synapse) ───────────────────

    /// <summary>
    /// Verifies a firewall rule that exists as an addressable child resource:
    /// GET <c>.../{armType}/{name}/firewallRules/{ruleId}</c> — 200 = Confirmed,
    /// anything else (typically 404) = NotFound. <paramref name="armType"/> is
    /// the provider-cased type, e.g. <c>Microsoft.Cache/Redis</c>.
    /// </summary>
    private async Task<VerificationResult> VerifyChildFirewallRuleAsync(
        JitGrantResponse grant, string tenantId, string armType, string apiVersion, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/{armType}/{grant.ResourceName}" +
                  $"/firewallRules/{grant.RuleId}?api-version={apiVersion}";

        var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
        return response.IsSuccessStatusCode ? VerificationResult.Confirmed : VerificationResult.NotFound;
    }

    // ── Storage Account — check IP rule by value ──────────────────────────────

    private async Task<VerificationResult> VerifyStorageRuleAsync(
        JitGrantResponse grant, string tenantId, CancellationToken ct)
    {
        var url = $"{ArmBase}/subscriptions/{grant.SubscriptionId}/resourceGroups/{grant.ResourceGroup}" +
                  $"/providers/Microsoft.Storage/storageAccounts/{grant.ResourceName}" +
                  $"?api-version={StorageApi}";

        var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
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

        foreach (var rule in ipRules.EnumerateArray())
        {
            if (rule.TryGetProperty("value", out var v) &&
                v.GetString()?.StartsWith(grant.CallerIp) == true)
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

        var response = await ArmGetAsync(tenantId, url, ct).ConfigureAwait(false);
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

        var expected = $"{grant.CallerIp}/32";
        foreach (var rule in ipRules.EnumerateArray())
        {
            if (rule.TryGetProperty("value", out var v) && v.GetString() == expected)
                return VerificationResult.Confirmed;
        }

        return VerificationResult.NotFound;
    }

    // ── Shared ARM helper ──────────────────────────────────────────────────────

    private Task<HttpResponseMessage> ArmGetAsync(
        string tenantId, string url, CancellationToken ct)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        return _context.GetHttpClient(tenantId).SendAsync(
            PluginHttpClientNames.Arm, _context.ArmScope, request, ct);
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
