using System.Text.Json.Serialization;

namespace AzureTray.Plugin.JITAzAccess.Models;

/// <summary>
/// Request body sent to POST /api/Request-JITAccess.
/// Property names match the PowerShell function app's expected JSON keys exactly.
/// </summary>
public sealed record JitRequest(
    [property: JsonPropertyName("targetType")]    string  TargetType,
    [property: JsonPropertyName("subscriptionId")] string SubscriptionId,
    [property: JsonPropertyName("resourceGroup")]  string ResourceGroup,
    [property: JsonPropertyName("resourceName")]   string ResourceName,
    [property: JsonPropertyName("durationHours")]  int    DurationHours,
    [property: JsonPropertyName("port")]           string? Port          = null,
    [property: JsonPropertyName("justification")]  string? Justification = null);
