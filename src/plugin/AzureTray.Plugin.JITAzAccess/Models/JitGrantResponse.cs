using System;
using System.Text.Json.Serialization;

namespace AzureTray.Plugin.JITAzAccess.Models;

/// <summary>
/// Deserialised from the 200 OK body of POST /api/Request-JITAccess.
/// </summary>
public sealed record JitGrantResponse
{
    [JsonPropertyName("ruleId")]
    public string RuleId { get; init; } = string.Empty;

    [JsonPropertyName("ruleIdentifier")]
    public string RuleIdentifier { get; init; } = string.Empty;

    [JsonPropertyName("targetType")]
    public string TargetType { get; init; } = string.Empty;

    /// <summary>ARM-style resource path, e.g. /subscriptions/{sub}/resourceGroups/{rg}/{name}</summary>
    [JsonPropertyName("resource")]
    public string Resource { get; init; } = string.Empty;

    [JsonPropertyName("callerIp")]
    public string CallerIp { get; init; } = string.Empty;

    /// <summary>Port or port-range, or null for non-NSG targets.</summary>
    [JsonPropertyName("port")]
    public string? Port { get; init; }

    [JsonPropertyName("expiresUtc")]
    [JsonConverter(typeof(UtcDateTimeConverter))]
    public DateTime ExpiresUtc { get; init; }

    [JsonPropertyName("requestedBy")]
    public string RequestedBy { get; init; } = string.Empty;

    // These parallel the request body fields and are needed by ArmVerifier.
    [JsonPropertyName("subscriptionId")]
    public string SubscriptionId { get; init; } = string.Empty;

    [JsonPropertyName("resourceGroup")]
    public string ResourceGroup { get; init; } = string.Empty;

    [JsonPropertyName("resourceName")]
    public string ResourceName { get; init; } = string.Empty;
}
