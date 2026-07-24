# ContainerRegistry.ps1
#region ── Azure Container Registry ────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/containerregistry/registries/update
#
# The IP allowlist lives under properties.networkRuleSet.ipRules[] with entries
# shaped { action: "Allow", value: "<ip>" }. networkRuleSet carries a
# defaultAction, so its presence marks a network-restricted registry (mirror of
# Storage/Key Vault): if there is no networkRuleSet we leave the registry
# untouched (access already open). We re-send the WHOLE networkRuleSet with only
# ipRules changed so defaultAction is preserved. Update is long-running (202) —
# the shared RMW helper polls to completion. RuleIdentifier stored = caller IP.
#
# NOTE: the ACR firewall requires the Premium SKU and defaultAction = Deny to
# have any effect.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:ContainerRegistryApi = '2023-07-01'   # Microsoft.ContainerRegistry/registries

function Add-JITContainerRegistryRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.ContainerRegistry/registries/$ResourceName"

    # Distinguishes the two no-write outcomes (SkippedOpen vs AlreadyPresent).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:ContainerRegistryApi -WriteMethod PATCH -Modify {
        param($resource)
        $nrs = if ($resource.properties) { $resource.properties.networkRuleSet } else { $null }
        if (-not $nrs) { $outcome.Reason = 'SkippedOpen'; return $false }   # not network-restricted; access already open

        $ipRules = @()
        if ($nrs.ipRules) { $ipRules = @($nrs.ipRules) }
        if ($ipRules | Where-Object { $_.value -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        $h = ConvertTo-Hashtable $nrs
        $h.ipRules = @($ipRules) + @(@{ action = 'Allow'; value = $CallerIp })
        return @{ properties = @{ networkRuleSet = $h } }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (not restricted or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITContainerRegistryRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Container Registry row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.ContainerRegistry/registries/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:ContainerRegistryApi -WriteMethod PATCH -Modify {
        param($resource)
        $nrs = if ($resource.properties) { $resource.properties.networkRuleSet } else { $null }
        if (-not ($nrs -and $nrs.ipRules)) { return $false }   # already gone

        $ipRules   = @($nrs.ipRules)
        $remaining = @($ipRules | Where-Object { $_.value -ne $ipValue })
        if ($remaining.Count -eq $ipRules.Count) { return $false }   # already gone

        $h = ConvertTo-Hashtable $nrs
        $h.ipRules = $remaining
        return @{ properties = @{ networkRuleSet = $h } }
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
