# ServiceBus.ps1
#region ── Azure Service Bus namespace ─────────────────────────────────────────
# https://learn.microsoft.com/rest/api/servicebus/namespaces (networkRuleSets)
#
# Same singleton-child model as Event Hubs: the allowlist lives on the
# networkRuleSets/default child. We GET that child, add/remove one entry in
# properties.ipRules[] (entries shaped { action: "Allow", ipMask: "<ip>" }), and
# PUT the whole child back. The child carries defaultAction, so its presence
# marks a restricted namespace (mirror Storage). The write is SYNCHRONOUS. We
# route through the shared ETag read-modify-write helper for optimistic
# concurrency across simultaneous grants. RuleIdentifier stored = caller IP;
# removal matches on ipMask.
#
# NOTE: network rule sets require the Standard tier (or higher). A Basic-tier
# namespace has no networkRuleSets/default child (the GET 404s) — such a grant
# surfaces as a target-modification failure, which is correct (no firewall to
# manage). Set defaultAction = "Deny" at the set level for the allowlist to bite.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:ServiceBusApi = '2024-01-01'   # Microsoft.ServiceBus/namespaces

function Add-JITServiceBusRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.ServiceBus/namespaces/$ResourceName/networkRuleSets/default"

    # Distinguishes the two no-write outcomes (SkippedOpen vs AlreadyPresent).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:ServiceBusApi -WriteMethod PUT -Modify {
        param($resource)
        $props = if ($resource.properties) { $resource.properties } else { $null }
        if (-not $props) { $outcome.Reason = 'SkippedOpen'; return $false }

        $ipRules = @()
        if ($props.ipRules) { $ipRules = @($props.ipRules) }
        if ($ipRules | Where-Object { $_.ipMask -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        $hprops = ConvertTo-Hashtable $props
        $hprops.ipRules = @($ipRules) + @(@{ action = 'Allow'; ipMask = $CallerIp })
        $resource.properties = $hprops
        return $resource
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (not restricted or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITServiceBusRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Service Bus row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.ServiceBus/namespaces/$($Row.ResourceName)/networkRuleSets/default"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:ServiceBusApi -WriteMethod PUT -Modify {
        param($resource)
        $props = if ($resource.properties) { $resource.properties } else { $null }
        if (-not ($props -and $props.ipRules)) { return $false }   # already gone

        $ipRules   = @($props.ipRules)
        $remaining = @($ipRules | Where-Object { $_.ipMask -ne $ipValue })
        if ($remaining.Count -eq $ipRules.Count) { return $false }   # already gone

        $hprops = ConvertTo-Hashtable $props
        $hprops.ipRules = $remaining
        $resource.properties = $hprops
        return $resource
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
