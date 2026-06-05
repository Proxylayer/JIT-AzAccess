using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Discovers JIT function-app base URLs by reading the AzureTray host's
/// app-registration tags via Microsoft Graph.
///
/// Each JIT function-app deployment writes one tag in the shape
///   <c>jit-baseurl:&lt;subscriptionId&gt;=&lt;https-url&gt;</c>
/// on every cold start (see profile.ps1). The tag array is used instead of
/// the notes field so a human-authored description in notes is preserved,
/// and multiple deployments coexist as separate entries.
/// </summary>
internal sealed class JitUrlDiscovery
{
    private const string GraphBase = "https://graph.microsoft.com";
    private const string DefaultAppRegistrationName = "AzureTray";
    private const string TagPrefix = "jit-baseurl:";

    private readonly IPluginContext _context;

    public JitUrlDiscovery(IPluginContext context) => _context = context;

    /// <summary>
    /// Looks up the JIT function-app URLs from the AzureTray host's app
    /// registration tags. Returns a snapshot keyed by subscription ID.
    /// </summary>
    public async Task<JitUrlDiscoveryResult> DiscoverAsync(
        string            tenantId,
        string            appRegistrationName,
        CancellationToken ct)
    {
        var name = string.IsNullOrWhiteSpace(appRegistrationName)
            ? DefaultAppRegistrationName
            : appRegistrationName;

        var url = $"{GraphBase}/v1.0/applications" +
                  $"?$filter=displayName+eq+'{Uri.EscapeDataString(name)}'" +
                  $"&$select=tags";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        HttpResponseMessage response;
        try
        {
            response = await _context.GetHttpClient(tenantId)
                .SendAsync(PluginHttpClientNames.Graph, _context.GraphScope, request, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _context.Logger.LogWarning(ex,
                "JIT: Graph discovery request failed for app registration '{Name}'.", name);
            return JitUrlDiscoveryResult.Empty;
        }

        if (!response.IsSuccessStatusCode)
        {
            _context.Logger.LogWarning(
                "JIT: Graph discovery returned {Status} when looking up app registration '{Name}'.",
                (int)response.StatusCode, name);
            return JitUrlDiscoveryResult.Empty;
        }

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        try
        {
            using var doc = JsonDocument.Parse(body);

            if (!doc.RootElement.TryGetProperty("value", out var values) ||
                values.GetArrayLength() == 0)
            {
                _context.Logger.LogWarning(
                    "JIT: no app registration found with displayName '{Name}' in tenant {TenantId}.",
                    name, tenantId);
                return JitUrlDiscoveryResult.Empty;
            }

            var app = values[0];

            if (!app.TryGetProperty("tags", out var tagsEl) ||
                tagsEl.ValueKind != JsonValueKind.Array ||
                tagsEl.GetArrayLength() == 0)
            {
                _context.Logger.LogWarning(
                    "JIT: '{Name}' app reg has no tags — has any JIT function app been deployed and started?",
                    name);
                return JitUrlDiscoveryResult.Empty;
            }

            var perSub = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var tagEl in tagsEl.EnumerateArray())
            {
                if (tagEl.ValueKind != JsonValueKind.String) continue;
                var tag = tagEl.GetString();
                if (string.IsNullOrEmpty(tag) || !tag.StartsWith(TagPrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                var rest = tag.Substring(TagPrefix.Length);
                var eq   = rest.IndexOf('=');
                if (eq <= 0 || eq == rest.Length - 1) continue;

                var subId  = rest.Substring(0, eq);
                var jitUrl = rest.Substring(eq + 1).TrimEnd('/');
                if (!string.IsNullOrWhiteSpace(jitUrl))
                    perSub[subId] = jitUrl;
            }

            if (perSub.Count == 0)
            {
                _context.Logger.LogWarning(
                    "JIT: '{Name}' app reg has tags but none in the '{Prefix}<sub>=<url>' format. " +
                    "Ensure a JIT function app has been deployed and started at least once.",
                    name, TagPrefix);
                return JitUrlDiscoveryResult.Empty;
            }

            _context.Logger.LogInformation(
                "JIT: discovered {Count} function-app URL(s) from '{Name}' app reg tags.",
                perSub.Count, name);

            return new JitUrlDiscoveryResult(perSub);
        }
        catch (Exception ex)
        {
            _context.Logger.LogWarning(ex, "JIT: failed to parse Graph discovery response.");
            return JitUrlDiscoveryResult.Empty;
        }
    }
}

/// <summary>
/// Snapshot of what was discovered from the AzureTray app reg tags.
/// </summary>
/// <param name="PerSubscription">subscription-id → function-app URL.</param>
internal sealed record JitUrlDiscoveryResult(
    IReadOnlyDictionary<string, string> PerSubscription)
{
    public static readonly JitUrlDiscoveryResult Empty =
        new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    public bool IsEmpty => PerSubscription.Count == 0;

    /// <summary>Every unique URL we should poll.</summary>
    public IEnumerable<string> AllUrls
    {
        get
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var u in PerSubscription.Values)
            {
                if (seen.Add(u)) yield return u;
            }
        }
    }

    /// <summary>Pick the function app URL responsible for a given subscription.</summary>
    public string? UrlForSubscription(string subscriptionId)
    {
        if (!string.IsNullOrEmpty(subscriptionId) &&
            PerSubscription.TryGetValue(subscriptionId, out var url))
        {
            return url;
        }
        return null;
    }
}
