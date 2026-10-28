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

    /// <summary>
    /// Default egress allowlist for a discovered backend. JIT function apps are
    /// Azure Functions, so their hostname lives under this suffix.
    /// </summary>
    internal const string DefaultAllowedHostSuffixes = ".azurewebsites.net";

    private readonly IPluginContext _context;
    private readonly Func<IReadOnlyList<string>> _allowedHostSuffixes;

    public JitUrlDiscovery(IPluginContext context, Func<IReadOnlyList<string>>? allowedHostSuffixes = null)
    {
        _context = context;
        _allowedHostSuffixes = allowedHostSuffixes
            ?? (() => ParseHostSuffixes(DefaultAllowedHostSuffixes));
    }

    /// <summary>
    /// Parses a comma/semicolon/whitespace-separated allowlist. An entry
    /// starting with '.' matches any host under that suffix; anything else is
    /// matched as an exact hostname.
    /// </summary>
    internal static IReadOnlyList<string> ParseHostSuffixes(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return new[] { DefaultAllowedHostSuffixes };

        // Separators are comma and semicolon; surrounding whitespace is
        // handled by the Trim below, so no whitespace chars are needed here.
        var parts = raw.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
        var list = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            var trimmed = part.Trim().TrimEnd('/');
            if (trimmed.Length > 0) list.Add(trimmed);
        }
        return list.Count > 0 ? list : new[] { DefaultAllowedHostSuffixes };
    }

    /// <summary>
    /// Decides whether a <c>jit-baseurl:</c> tag value may be used as a backend.
    /// </summary>
    /// <remarks>
    /// THIS IS A SECURITY BOUNDARY, not input tidying. The tag is read from any
    /// app registration the signed-in user can read, and Entra lets ordinary
    /// users register applications by default — so the value is attacker-
    /// controllable. Whatever comes back from here is handed to
    /// <see cref="JitClient"/>, which sends it the host-acquired ARM bearer
    /// token on every grant, revoke and poll. An unvalidated value is therefore
    /// a direct route for exfiltrating a user's ARM token, which is exactly what
    /// <c>IPluginHttpClient</c>'s own contract warns plugins to prevent.
    ///
    /// Required: absolute, https, a host on the allowlist, no embedded
    /// credentials, the default port, and no query or fragment.
    /// </remarks>
    internal static bool IsAllowedBackendUrl(
        string?                raw,
        IReadOnlyList<string>  allowedHostSuffixes,
        out Uri?               parsed,
        out string             rejectReason)
    {
        parsed       = null;
        rejectReason = string.Empty;

        if (string.IsNullOrWhiteSpace(raw))
        {
            rejectReason = "value is empty";
            return false;
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            rejectReason = "not an absolute URI";
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            rejectReason = $"scheme '{uri.Scheme}' is not https";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            rejectReason = "URI carries embedded credentials";
            return false;
        }

        if (!uri.IsDefaultPort)
        {
            rejectReason = $"non-default port {uri.Port}";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            rejectReason = "URI carries a query or fragment";
            return false;
        }

        var host    = uri.Host;
        var allowed = false;
        foreach (var entry in allowedHostSuffixes)
        {
            if (entry.StartsWith(".", StringComparison.Ordinal))
            {
                if (host.EndsWith(entry, StringComparison.OrdinalIgnoreCase)) { allowed = true; break; }
            }
            else if (string.Equals(host, entry, StringComparison.OrdinalIgnoreCase))
            {
                allowed = true;
                break;
            }
        }

        if (!allowed)
        {
            rejectReason = $"host '{host}' is not on the backend allowlist";
            return false;
        }

        parsed = uri;
        return true;
    }

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
        var allowedHosts = _allowedHostSuffixes();
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
                        if (CollectTags(app, perSub, allowedHosts))
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

    // Scans one application's tag array for jit-baseurl entries and merges the
    // ones that pass IsAllowedBackendUrl into <paramref name="perSub"/>. The
    // first URL seen for a given subscription wins; a later app advertising the
    // same subscription is logged and ignored (normally only one app reg
    // carries these tags).
    //
    // Returns true only if this app both carries the
    // JustificationRequired:false opt-out tag AND contributed at least one
    // VALID jit-baseurl tag. Without that pairing any app registration in the
    // tenant — including one an ordinary user just created — could switch off
    // the justification prompt for every AzureTray user. (The server enforces
    // justification authoritatively regardless; this keeps the client-side
    // control from being trivially flipped.)
    private bool CollectTags(
        JsonElement                app,
        Dictionary<string, string> perSub,
        IReadOnlyList<string>      allowedHosts)
    {
        if (!app.TryGetProperty("tags", out var tagsEl) ||
            tagsEl.ValueKind != JsonValueKind.Array)
            return false;

        var sawOptOut        = false;
        var contributedValid = false;

        foreach (var tagEl in tagsEl.EnumerateArray())
        {
            if (tagEl.ValueKind != JsonValueKind.String) continue;
            var tag = tagEl.GetString();
            if (string.IsNullOrEmpty(tag)) continue;

            if (string.Equals(tag.Trim(), JustificationOptOutTag, StringComparison.OrdinalIgnoreCase))
            {
                sawOptOut = true;
                continue;
            }

            if (!tag.StartsWith(TagPrefix, StringComparison.OrdinalIgnoreCase))
                continue;

            var rest = tag.Substring(TagPrefix.Length);
            var eq   = rest.IndexOf('=');
            if (eq <= 0 || eq == rest.Length - 1) continue;

            var subId  = rest.Substring(0, eq);
            var jitUrl = rest.Substring(eq + 1).Trim().TrimEnd('/');

            if (!IsAllowedBackendUrl(jitUrl, allowedHosts, out var uri, out var reason))
            {
                _context.Logger.LogWarning(
                    "JIT: REJECTED backend URL '{Url}' advertised for subscription {SubId} by app " +
                    "registration '{AppName}' ({AppId}) — {Reason}. No request will be sent to it.",
                    jitUrl, subId, DescribeApp(app, "displayName"), DescribeApp(app, "appId"), reason);
                continue;
            }

            contributedValid = true;

            // Normalise through the parsed Uri so what we store is what was
            // validated, not the raw tag text.
            var normalised = uri!.GetLeftPart(UriPartial.Path).TrimEnd('/');

            if (perSub.TryGetValue(subId, out var existing))
            {
                if (!string.Equals(existing, normalised, StringComparison.OrdinalIgnoreCase))
                    _context.Logger.LogWarning(
                        "JIT: subscription {SubId} is advertised by more than one app registration " +
                        "(keeping '{Existing}', ignoring '{Ignored}').", subId, existing, normalised);
                continue;
            }

            perSub[subId] = normalised;
        }

        if (sawOptOut && !contributedValid)
        {
            _context.Logger.LogWarning(
                "JIT: ignoring the '{Tag}' opt-out on app registration '{AppName}' ({AppId}) — it " +
                "advertises no valid JIT backend, so it is not a JIT deployment.",
                JustificationOptOutTag, DescribeApp(app, "displayName"), DescribeApp(app, "appId"));
        }

        return sawOptOut && contributedValid;
    }

    private static string DescribeApp(JsonElement app, string property) =>
        app.TryGetProperty(property, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString() ?? "(unknown)"
            : "(unknown)";
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
