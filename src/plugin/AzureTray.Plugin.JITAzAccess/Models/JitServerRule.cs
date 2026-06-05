using System;
using System.Text.Json.Serialization;

namespace AzureTray.Plugin.JITAzAccess.Models;

/// <summary>
/// An active JIT rule as returned by GET /api/Get-JITRules.
/// Unlike the locally-tracked <see cref="ActiveRule"/>, this comes from the server
/// and therefore reflects rules granted from any machine or session.
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
    public DateTime ExpiresUtc { get; init; }

    [JsonPropertyName("justification")]
    public string? Justification { get; init; }
}
