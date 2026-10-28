using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using AzureTray.Plugin.JITAzAccess.Models;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Typed HTTP client for the JIT-AzAccess function app endpoints.
///
/// The function app accepts ARM-audience bearer tokens (no custom scope), and
/// gates authorization on the caller's "JIT-Requester" custom RBAC role
/// assignment on the function app site resource.  So the plugin uses the host's
/// ARM named client + ArmScope — exactly what other plugins (e.g. PIM) use.
/// </summary>
internal sealed class JitClient
{
    private static readonly JsonSerializerOptions SerializeOptions = new()
    {
        PropertyNamingPolicy   = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly JsonSerializerOptions DeserializeOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly IPluginContext _context;

    public JitClient(IPluginContext context) => _context = context;

    // ── POST /api/Request-JITAccess ───────────────────────────────────────────

    public async Task<JitGrantResponse> RequestAccessAsync(
        string            tenantId,
        string            functionAppUrl,
        JitRequest        request,
        CancellationToken ct)
    {
        var url  = $"{functionAppUrl.TrimEnd('/')}/api/Request-JITAccess";
        var body = JsonSerializer.Serialize(request, SerializeOptions);

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

        _context.Logger.LogDebug(
            "JIT: POST {Url} (targetType={TargetType}, resource={ResourceName}, hours={DurationHours}).",
            url, request.TargetType, request.ResourceName, request.DurationHours);

        using var response = await _context.GetHttpClient(tenantId)
            .SendAsync(PluginHttpClientNames.Arm, _context.ArmScope, httpRequest, ct)
            .ConfigureAwait(false);

        var responseBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var serverError = TryExtractError(responseBody);
            // Debug only: the thrown JitHttpException carries the same info and
            // the catch site decides how loudly to log it (once-then-quiet).
            _context.Logger.LogDebug(
                "JIT: POST {Url} returned {Status}.", url, (int)response.StatusCode);
            throw new JitHttpException(
                (int)response.StatusCode,
                "Request-JITAccess",
                serverError,
                $"JIT grant failed ({(int)response.StatusCode}): {serverError ?? responseBody}");
        }

        return JsonSerializer.Deserialize<JitGrantResponse>(responseBody, DeserializeOptions)
               ?? throw new InvalidOperationException("Empty response from JIT function app.");
    }

    // ── GET /api/Get-JITRules ─────────────────────────────────────────────────

    public async Task<ActiveRulesResult> GetActiveRulesAsync(
        string            tenantId,
        string            functionAppUrl,
        CancellationToken ct)
    {
        var url = $"{functionAppUrl.TrimEnd('/')}/api/Get-JITRules";
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, url);

        _context.Logger.LogDebug("JIT: GET {Url}", url);

        using var response = await _context.GetHttpClient(tenantId)
            .SendAsync(PluginHttpClientNames.Arm, _context.ArmScope, httpRequest, ct)
            .ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var serverError = TryExtractError(body);
            // Debug only: the thrown JitHttpException carries the same info and
            // the catch site decides how loudly to log it (once-then-quiet).
            _context.Logger.LogDebug(
                "JIT: GET {Url} returned {Status}.", url, (int)response.StatusCode);
            throw new JitHttpException(
                (int)response.StatusCode,
                "Get-JITRules",
                serverError,
                $"Get-JITRules failed ({(int)response.StatusCode}): {serverError ?? body}");
        }

        // The function reports the caller's current public IP (the exact IP a
        // grant would whitelist) in this header, so the plugin can flag
        // resources whose firewall already allows it.
        string? callerIp = null;
        if (response.Headers.TryGetValues("X-JIT-Caller-IP", out var ipValues))
            callerIp = ipValues.FirstOrDefault();

        var rules = JsonSerializer.Deserialize<List<JitServerRule>>(body, DeserializeOptions)
                    ?? new List<JitServerRule>();

        return new ActiveRulesResult(rules, callerIp);
    }

    // ── DELETE /api/Revoke-JITAccess/{ruleId} ────────────────────────────────

    public async Task RevokeAsync(
        string            tenantId,
        string            functionAppUrl,
        string            ruleId,
        CancellationToken ct)
    {
        var url = $"{functionAppUrl.TrimEnd('/')}/api/Revoke-JITAccess/{Uri.EscapeDataString(ruleId)}";
        using var httpRequest = new HttpRequestMessage(HttpMethod.Delete, url);

        _context.Logger.LogDebug("JIT: DELETE {Url}", url);

        using var response = await _context.GetHttpClient(tenantId)
            .SendAsync(PluginHttpClientNames.Arm, _context.ArmScope, httpRequest, ct)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var serverError = TryExtractError(body);
            // Debug only: the thrown JitHttpException carries the same info and
            // the catch site decides how loudly to log it (once-then-quiet).
            _context.Logger.LogDebug(
                "JIT: DELETE {Url} returned {Status}.", url, (int)response.StatusCode);
            throw new JitHttpException(
                (int)response.StatusCode,
                "Revoke-JITAccess",
                serverError,
                $"Revoke failed ({(int)response.StatusCode}): {serverError ?? body}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string? TryExtractError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            var error = root.TryGetProperty("error", out var el) ? el.GetString() : null;

            // The function app attaches the underlying exception text in a
            // "detail" field on 500s (e.g. the ARM error behind a failed NSG
            // write). Surface it — without it the caller only sees the generic
            // "Failed to modify nsg…" message and can't tell an RBAC denial
            // from a real bug.
            var detail = root.TryGetProperty("detail", out var de) ? de.GetString() : null;

            if (!string.IsNullOrWhiteSpace(error) && !string.IsNullOrWhiteSpace(detail))
                return $"{error} — {detail}";

            return error ?? detail;
        }
        catch { return null; }
    }
}

/// <summary>
/// Result of <see cref="JitClient.GetActiveRulesAsync"/>: the caller's active
/// rules plus the current public IP the function observed (from the
/// X-JIT-Caller-IP header), used to detect already-allowed resources.
/// </summary>
internal sealed record ActiveRulesResult(List<JitServerRule> Rules, string? CallerIp);
