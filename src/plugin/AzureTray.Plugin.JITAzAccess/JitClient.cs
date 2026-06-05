using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using AzureTray.Plugin.JITAzAccess.Models;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Typed HTTP client for all JIT-AzAccess function app endpoints.
/// Uses the host's ARM named client for resilience while supplying the
/// custom JIT audience scope for token acquisition.
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
        string            jitScope,
        JitRequest        request,
        CancellationToken ct)
    {
        var url  = $"{functionAppUrl.TrimEnd('/')}/api/Request-JITAccess";
        var body = JsonSerializer.Serialize(request, SerializeOptions);

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

        var response = await _context.Http
            .SendAsync(PluginHttpClientNames.Arm, tenantId, jitScope, httpRequest, ct)
            .ConfigureAwait(false);

        var responseBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"JIT grant failed ({(int)response.StatusCode}): {TryExtractError(responseBody) ?? responseBody}");

        return JsonSerializer.Deserialize<JitGrantResponse>(responseBody, DeserializeOptions)
               ?? throw new InvalidOperationException("Empty response from JIT function app.");
    }

    // ── GET /api/Get-JITTargets ───────────────────────────────────────────────

    public async Task<List<JitTarget>> GetTargetsAsync(
        string            tenantId,
        string            functionAppUrl,
        string            jitScope,
        CancellationToken ct)
    {
        var url = $"{functionAppUrl.TrimEnd('/')}/api/Get-JITTargets";
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, url);

        var response = await _context.Http
            .SendAsync(PluginHttpClientNames.Arm, tenantId, jitScope, httpRequest, ct)
            .ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Get-JITTargets failed ({(int)response.StatusCode}): {TryExtractError(body) ?? body}");

        return JsonSerializer.Deserialize<List<JitTarget>>(body, DeserializeOptions)
               ?? new List<JitTarget>();
    }

    // ── GET /api/Get-JITRules ─────────────────────────────────────────────────

    public async Task<List<JitServerRule>> GetActiveRulesAsync(
        string            tenantId,
        string            functionAppUrl,
        string            jitScope,
        CancellationToken ct)
    {
        var url = $"{functionAppUrl.TrimEnd('/')}/api/Get-JITRules";
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, url);

        var response = await _context.Http
            .SendAsync(PluginHttpClientNames.Arm, tenantId, jitScope, httpRequest, ct)
            .ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Get-JITRules failed ({(int)response.StatusCode}): {TryExtractError(body) ?? body}");

        return JsonSerializer.Deserialize<List<JitServerRule>>(body, DeserializeOptions)
               ?? new List<JitServerRule>();
    }

    // ── DELETE /api/Revoke-JITAccess/{ruleId} ────────────────────────────────

    public async Task RevokeAsync(
        string            tenantId,
        string            functionAppUrl,
        string            jitScope,
        string            ruleId,
        CancellationToken ct)
    {
        var url = $"{functionAppUrl.TrimEnd('/')}/api/Revoke-JITAccess/{Uri.EscapeDataString(ruleId)}";
        using var httpRequest = new HttpRequestMessage(HttpMethod.Delete, url);

        var response = await _context.Http
            .SendAsync(PluginHttpClientNames.Arm, tenantId, jitScope, httpRequest, ct)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new InvalidOperationException(
                $"Revoke failed ({(int)response.StatusCode}): {TryExtractError(body) ?? body}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string? TryExtractError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("error", out var el) ? el.GetString() : null;
        }
        catch { return null; }
    }
}
