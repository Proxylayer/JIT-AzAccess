using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace AzureTray.Plugin.JITAzAccess.Models;

/// <summary>
/// A JIT target the user can request access to. Discovered client-side from
/// the signed-in user's own ARM resources (see <see cref="ResourceDiscovery"/>),
/// so the browse list reflects whatever resources the caller can already see.
/// </summary>
public sealed record JitTarget
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string DisplayName { get; init; } = string.Empty;

    /// <summary>nsg | sqlServer | storageAccount | keyVault</summary>
    [JsonPropertyName("targetType")]
    public string TargetType { get; init; } = string.Empty;

    [JsonPropertyName("subscriptionId")]
    public string SubscriptionId { get; init; } = string.Empty;

    [JsonPropertyName("resourceGroup")]
    public string ResourceGroup { get; init; } = string.Empty;

    [JsonPropertyName("resourceName")]
    public string ResourceName { get; init; } = string.Empty;

    /// <summary>dev | staging | prod — used for visual badges and confirmation prompts.</summary>
    [JsonPropertyName("environment")]
    public string? Environment { get; init; }

    /// <summary>Pre-filled port suggestion (NSG only).</summary>
    [JsonPropertyName("defaultPort")]
    public string? DefaultPort { get; init; }

    /// <summary>Ports the server will accept for this NSG target. Null = any.</summary>
    [JsonPropertyName("allowedPorts")]
    public string[]? AllowedPorts { get; init; }

    /// <summary>Duration options (hours) to show in the grant submenu. Null = use plugin default list.</summary>
    [JsonPropertyName("allowedDurations")]
    public int[]? AllowedDurations { get; init; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    /// <summary>When true the plugin prompts for a justification string before granting.</summary>
    [JsonPropertyName("requiresJustification")]
    public bool RequiresJustification { get; init; }

    /// <summary>
    /// IP/CIDR values already present in this resource's firewall (discovered
    /// from ARM, not server-supplied). Used to detect when the caller's IP is
    /// already permanently allowed. Case-insensitive set for O(1) exact-match.
    /// </summary>
    [JsonIgnore]
    public IReadOnlySet<string> WhitelistedIps { get; init; } =
        new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
}
