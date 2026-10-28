using System;
using System.Text.Json.Serialization;

namespace AzureTray.Plugin.JITAzAccess.Models;

/// <summary>
/// An active JIT rule as returned by GET /api/Get-JITRules. The server is the
/// only source of truth for what is currently granted, so these reflect rules
/// granted from any machine or session.
/// </summary>
public sealed record JitServerRule
{
    [JsonPropertyName("ruleId")]
    public string RuleId { get; init; } = string.Empty;

    [JsonPropertyName("targetType")]
    public string TargetType { get; init; } = string.Empty;

    [JsonPropertyName("subscriptionId")]
    public string SubscriptionId { get; init; } = string.Empty;

    [JsonPropertyName("resourceGroup")]
    public string ResourceGroup { get; init; } = string.Empty;

    [JsonPropertyName("resourceName")]
    public string ResourceName { get; init; } = string.Empty;

    [JsonPropertyName("ruleIdentifier")]
    public string RuleIdentifier { get; init; } = string.Empty;

    [JsonPropertyName("callerIp")]
    public string CallerIp { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public string? Port { get; init; }

    [JsonPropertyName("requestedBy")]
    public string RequestedBy { get; init; } = string.Empty;

    [JsonPropertyName("expiresUtc")]
    [JsonConverter(typeof(UtcDateTimeConverter))]
    public DateTime ExpiresUtc { get; init; }

    [JsonPropertyName("justification")]
    public string? Justification { get; init; }

    /// <summary>
    /// Client-only: the JIT function-app URL this rule was fetched from. Used
    /// to route Revoke calls to the correct deployment in multi-function-app
    /// setups. Not serialised back to the server.
    /// </summary>
    [JsonIgnore]
    public string SourceFunctionAppUrl { get; init; } = string.Empty;
}
