using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using AzureTray.Plugin.JITAzAccess.Models;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Discovers JIT-eligible resources by querying ARM Resource Graph using the
/// signed-in user's ARM token. Returns one <see cref="JitTarget"/> per
/// resource of the four supported types (NSG, SQL Server, Storage Account,
/// Key Vault) across every subscription the user can see.
///
/// One Resource Graph query covers all subscriptions — no per-sub fan-out.
/// The user only sees resources they themselves have ARM read access to,
/// so this naturally respects existing RBAC.
/// </summary>
internal sealed class ResourceDiscovery
{
    private const string ResourceGraphUrl =
        "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01";

    /// <summary>
    /// Resource Graph query: every supported resource type, projecting the
    /// fields we map onto JitTarget. Sorted client-side later.
    /// </summary>
    private const string Kql = @"
Resources
| where type in~ (
    'microsoft.network/networksecuritygroups',
    'microsoft.sql/servers',
    'microsoft.storage/storageaccounts',
    'microsoft.keyvault/vaults')
| extend jitFw = case(
    type =~ 'microsoft.storage/storageaccounts', properties.networkAcls.ipRules,
    type =~ 'microsoft.keyvault/vaults', properties.networkAcls.ipRules,
    type =~ 'microsoft.network/networksecuritygroups', properties.securityRules,
    dynamic([]))
| project id, name, type, resourceGroup, subscriptionId, location, tags, jitFw
";

    private readonly IPluginContext _context;

    public ResourceDiscovery(IPluginContext context) => _context = context;

    public async Task<List<JitTarget>> DiscoverAsync(string tenantId, CancellationToken ct)
    {
        var all = new List<JitTarget>();

        // Resource Graph pages by skipToken when results > $top (default 100,
        // max 1000). Loop until exhausted.
        string? skipToken = null;
        do
        {
            var body = new
            {
                query   = Kql,
                options = new { resultFormat = "objectArray", top = 1000, skipToken = (string?)skipToken },
            };

            var json = JsonSerializer.Serialize(body);
            using var req = new HttpRequestMessage(HttpMethod.Post, ResourceGraphUrl)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };

            _context.Logger.LogDebug("JIT: querying Resource Graph (skipToken={Skip}).", skipToken ?? "(none)");

            HttpResponseMessage response;
            try
            {
                response = await _context.GetHttpClient(tenantId)
                    .SendAsync(PluginHttpClientNames.Arm, _context.ArmScope, req, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _context.Logger.LogWarning(ex, "JIT: Resource Graph request failed.");
                return all;
            }

            var responseBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _context.Logger.LogWarning(
                    "JIT: Resource Graph returned {Status}: {Body}", (int)response.StatusCode, responseBody);
                return all;
            }

            try
            {
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                {
                    foreach (var row in data.EnumerateArray())
                    {
                        var t = MapToTarget(row);
                        if (t is not null) all.Add(t);
                    }
                }

                skipToken = root.TryGetProperty("$skipToken", out var st) && st.ValueKind == JsonValueKind.String
                    ? st.GetString()
                    : null;
            }
            catch (Exception ex)
            {
                _context.Logger.LogWarning(ex, "JIT: failed to parse Resource Graph response.");
                return all;
            }
        }
        while (!string.IsNullOrEmpty(skipToken));

        _context.Logger.LogInformation("JIT: discovered {Count} JIT-eligible resource(s) via Resource Graph.", all.Count);
        return all;
    }

    private static JitTarget? MapToTarget(JsonElement row)
    {
        if (!row.TryGetProperty("type", out var typeEl) || typeEl.ValueKind != JsonValueKind.String) return null;
        var armType = typeEl.GetString()!.ToLowerInvariant();
        var targetType = armType switch
        {
            "microsoft.network/networksecuritygroups" => "nsg",
            "microsoft.sql/servers"                   => "sqlServer",
            "microsoft.storage/storageaccounts"       => "storageAccount",
            "microsoft.keyvault/vaults"               => "keyVault",
            _                                         => null,
        };
        if (targetType is null) return null;

        var id   = TryGetString(row, "id")             ?? string.Empty;
        var name = TryGetString(row, "name")           ?? string.Empty;
        var rg   = TryGetString(row, "resourceGroup")  ?? string.Empty;
        var sub  = TryGetString(row, "subscriptionId") ?? string.Empty;

        var (environment, requiresJustification) = ReadTags(row);

        return new JitTarget
        {
            Id                    = id,
            DisplayName           = name,
            TargetType            = targetType,
            SubscriptionId        = sub,
            ResourceGroup         = rg,
            ResourceName          = name,
            Environment           = environment,
            DefaultPort           = targetType == "nsg" ? "443" : null,
            AllowedPorts          = null,
            AllowedDurations      = null,
            Enabled               = true,
            RequiresJustification = requiresJustification,
            WhitelistedIps        = ExtractWhitelistedIps(row, targetType),
        };
    }

    /// <summary>
    /// Pulls the IP/CIDR values already present in the resource's firewall from
    /// the projected <c>jitFw</c> column. Storage/Key Vault expose
    /// <c>ipRules[].value</c>; NSGs expose <c>securityRules</c>, from which we
    /// take the source prefixes of inbound Allow rules. SQL firewall rules are
    /// child resources not present here, so SQL targets get an empty set (a
    /// missed optimization, never a false "already allowed").
    /// </summary>
    private static HashSet<string> ExtractWhitelistedIps(JsonElement row, string targetType)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!row.TryGetProperty("jitFw", out var fw) || fw.ValueKind != JsonValueKind.Array)
            return set;

        if (targetType is "storageAccount" or "keyVault")
        {
            foreach (var rule in fw.EnumerateArray())
            {
                if (rule.ValueKind == JsonValueKind.Object &&
                    rule.TryGetProperty("value", out var v) &&
                    v.ValueKind == JsonValueKind.String)
                {
                    var s = v.GetString();
                    if (!string.IsNullOrWhiteSpace(s)) set.Add(s.Trim());
                }
            }
        }
        else if (targetType == "nsg")
        {
            foreach (var rule in fw.EnumerateArray())
            {
                if (rule.ValueKind != JsonValueKind.Object) continue;
                if (!rule.TryGetProperty("properties", out var p) || p.ValueKind != JsonValueKind.Object) continue;
                if (!PropEquals(p, "access", "Allow"))     continue;
                if (!PropEquals(p, "direction", "Inbound")) continue;

                if (p.TryGetProperty("sourceAddressPrefix", out var sp) && sp.ValueKind == JsonValueKind.String)
                {
                    var s = sp.GetString();
                    if (!string.IsNullOrWhiteSpace(s)) set.Add(s.Trim());
                }
                if (p.TryGetProperty("sourceAddressPrefixes", out var sps) && sps.ValueKind == JsonValueKind.Array)
                {
                    foreach (var e in sps.EnumerateArray())
                    {
                        if (e.ValueKind != JsonValueKind.String) continue;
                        var s = e.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) set.Add(s.Trim());
                    }
                }
            }
        }

        return set;
    }

    private static bool PropEquals(JsonElement obj, string prop, string expected)
        => obj.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
           && string.Equals(v.GetString(), expected, StringComparison.OrdinalIgnoreCase);

    private static (string? environment, bool requiresJustification) ReadTags(JsonElement row)
    {
        string? environment = null;
        var requiresJustification = false;

        if (row.TryGetProperty("tags", out var tags) && tags.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in tags.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.String) continue;
                var key = prop.Name.ToLowerInvariant();
                var val = prop.Value.GetString();
                if (string.IsNullOrEmpty(val)) continue;

                switch (key)
                {
                    case "environment":
                    case "env":
                        environment = val.ToLowerInvariant();
                        if (environment is "prod" or "production") requiresJustification = true;
                        break;

                    case "jit-requires-justification":
                        requiresJustification = val.Equals("true", StringComparison.OrdinalIgnoreCase);
                        break;
                }
            }
        }

        return (environment, requiresJustification);
    }

    private static string? TryGetString(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
