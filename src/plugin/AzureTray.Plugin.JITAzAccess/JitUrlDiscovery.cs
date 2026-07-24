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
/// Self-discovers JIT function-app base URLs by scanning the tags of every app
/// registration the signed-in user can read via Microsoft Graph. No operator
/// supplies an app-registration name: the plugin enumerates all readable
/// applications and collects the JIT URL tags from whichever one carries them.
///
/// Each JIT function-app deployment writes one tag in the shape
///   <c>jit-baseurl:&lt;subscriptionId&gt;=&lt;https-url&gt;</c>
/// on every cold start (see profile.ps1) — normally onto the single "AzureTray"
/// app registration, but the name is not assumed. The tag array is used instead
/// of the notes field so a human-authored description in notes is preserved, and
/// multiple deployments coexist as separate entries.
/// </summary>
internal sealed class JitUrlDiscovery
{
    private const string GraphBase = "https://graph.microsoft.com";
    private const string TagPrefix = "jit-baseurl:";

    // Opt-out tag: when any readable app registration carries this tag the
    // per-grant justification prompt becomes optional (the server still enforces
    // authoritatively — this only relaxes the matching client-side UX).
    private const string JustificationOptOutTag = "JustificationRequired:false";

    // Cap the number of pages walked so a directory with a large number of app
    // registrations can't turn discovery into an unbounded crawl.
    private const int MaxPages = 20;

    private readonly IPluginContext _context;

    public JitUrlDiscovery(IPluginContext context) => _context = context;

    /// <summary>
    /// Scans every app registration the caller can read for <c>jit-baseurl:</c>
    /// tags and merges them into a snapshot keyed by subscription ID.
    /// </summary>
    public async Task<JitUrlDiscoveryResult> DiscoverAsync(
        string            tenantId,
        CancellationToken ct)
    {
        var perSub = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var justificationOptional = false;
        var nextUrl = $"{GraphBase}/v1.0/applications?$select=id,appId,displayName,tags&$top=100";
        var pages   = 0;

        while (!string.IsNullOrEmpty(nextUrl) && pages < MaxPages)
        {
            pages++;

            using var request = new HttpRequestMessage(HttpMethod.Get, nextUrl);

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
                    "JIT: Graph applications request failed for tenant {TenantId}.", tenantId);
                return JitUrlDiscoveryResult.Empty;
            }

            if (!response.IsSuccessStatusCode)
            {
                _context.Logger.LogWarning(
                    "JIT: Graph applications query returned {Status} for tenant {TenantId}.",
                    (int)response.StatusCode, tenantId);
                return JitUrlDiscoveryResult.Empty;
            }

            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                if (root.TryGetProperty("value", out var values) &&
                    values.ValueKind == JsonValueKind.Array)
                {
                    foreach (var app in values.EnumerateArray())
                    {
                        if (CollectTags(app, perSub))
                            justificationOptional = true;
                    }
                }

                nextUrl = root.TryGetProperty("@odata.nextLink", out var nextEl) &&
                          nextEl.ValueKind == JsonValueKind.String
                    ? nextEl.GetString()
                    : null;
            }
            catch (Exception ex)
            {
                _context.Logger.LogWarning(ex, "JIT: failed to parse Graph applications response.");
                return JitUrlDiscoveryResult.Empty;
            }
        }

        if (perSub.Count == 0)
        {
            _context.Logger.LogWarning(
                "JIT: no readable app registration carries a '{Prefix}<sub>=<url>' tag in tenant {TenantId}. " +
                "Ensure a JIT function app has been deployed and started at least once.",
                TagPrefix, tenantId);
            return JitUrlDiscoveryResult.Empty;
        }

        _context.Logger.LogInformation(
            "JIT: discovered {Count} function-app URL(s) from app registration tags in tenant {TenantId} " +
            "(justification {Mode}).",
            perSub.Count, tenantId, justificationOptional ? "optional" : "required");

        return new JitUrlDiscoveryResult(perSub, justificationOptional);
    }

    // Scans one application's tag array for jit-baseurl entries and merges them
    // into <paramref name="perSub"/>. The first URL seen for a given
    // subscription wins; a later app advertising the same subscription is
    // logged and ignored (normally only one app reg carries these tags).
    // Returns true if this app carries the JustificationRequired:false opt-out
    // tag (case-insensitive, trimmed).
    private bool CollectTags(JsonElement app, Dictionary<string, string> perSub)
    {
        if (!app.TryGetProperty("tags", out var tagsEl) ||
            tagsEl.ValueKind != JsonValueKind.Array)
            return false;

        var justificationOptional = false;

        foreach (var tagEl in tagsEl.EnumerateArray())
        {
            if (tagEl.ValueKind != JsonValueKind.String) continue;
            var tag = tagEl.GetString();
            if (string.IsNullOrEmpty(tag)) continue;

            if (string.Equals(tag.Trim(), JustificationOptOutTag, StringComparison.OrdinalIgnoreCase))
            {
                justificationOptional = true;
                continue;
            }

            if (!tag.StartsWith(TagPrefix, StringComparison.OrdinalIgnoreCase))
                continue;

            var rest = tag.Substring(TagPrefix.Length);
            var eq   = rest.IndexOf('=');
            if (eq <= 0 || eq == rest.Length - 1) continue;

            var subId  = rest.Substring(0, eq);
            var jitUrl = rest.Substring(eq + 1).TrimEnd('/');
            if (string.IsNullOrWhiteSpace(jitUrl)) continue;

            if (perSub.TryGetValue(subId, out var existing))
            {
                if (!string.Equals(existing, jitUrl, StringComparison.OrdinalIgnoreCase))
                    _context.Logger.LogWarning(
                        "JIT: subscription {SubId} is advertised by more than one app registration " +
                        "(keeping '{Existing}', ignoring '{Ignored}').", subId, existing, jitUrl);
                continue;
            }

            perSub[subId] = jitUrl;
        }

        return justificationOptional;
    }
}

/// <summary>
/// Snapshot of what was discovered from the AzureTray app reg tags.
/// </summary>
/// <param name="PerSubscription">subscription-id → function-app URL.</param>
/// <param name="JustificationOptional">
/// True when a readable app registration carries the
/// <c>JustificationRequired:false</c> opt-out tag, relaxing the per-grant
/// justification prompt (the server still enforces authoritatively).
/// </param>
internal sealed record JitUrlDiscoveryResult(
    IReadOnlyDictionary<string, string> PerSubscription,
    bool JustificationOptional = false)
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
