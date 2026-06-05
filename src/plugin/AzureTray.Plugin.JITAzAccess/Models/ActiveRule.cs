using System;

namespace AzureTray.Plugin.JITAzAccess.Models;

/// <summary>
/// A locally-tracked JIT grant. Persisted to DataDir/active-rules.json so
/// the plugin can show countdowns across host restarts.
/// </summary>
public sealed record ActiveRule(
    string   RuleId,
    string   TenantId,
    string   TargetType,
    string   SubscriptionId,
    string   ResourceGroup,
    string   ResourceName,
    string?  Port,
    int      DurationHours,
    DateTime GrantedUtc,
    DateTime ExpiryUtc);
