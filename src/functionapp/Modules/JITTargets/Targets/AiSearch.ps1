# AiSearch.ps1
#region ── Azure AI Search (searchServices) ────────────────────────────────────
# https://learn.microsoft.com/rest/api/searchmanagement/services/update
#
# The IP allowlist lives under properties.networkRuleSet.ipRules[] with entries
# shaped { value: "<ip>" }. The search service networkRuleSet has no defaultAction
# — an EMPTY ipRules (with publicNetworkAccess enabled) means the service is open,
# so adding the first entry would restrict it. We therefore only add when the
# allowlist is already configured (ipRules non-empty), never creating restriction
# where none exists. RuleIdentifier stored = caller IP.
#
# searchServices has NO PATCH — the update is a whole-resource CreateOrUpdate
# (PUT), so we GET-modify-PUT the entire resource (preserving sku/location and
# the rest of networkRuleSet). The write is SYNCHRONOUS (no 202); the change
# settles via provisioningState, consistent with array types being described as
# eventually-consistent.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:AiSearchApi = '2023-11-01'   # Microsoft.Search/searchServices

function Add-JITAiSearchRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.Search/searchServices/$ResourceName"

    # Distinguishes the two no-write outcomes (SkippedOpen vs AlreadyPresent).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:AiSearchApi -WriteMethod PUT -Modify {
        param($resource)
        $nrs = if ($resource.properties) { $resource.properties.networkRuleSet } else { $null }
        $ipRules = @()
        if ($nrs -and $nrs.ipRules) { $ipRules = @($nrs.ipRules) }

        # Empty => not restricted (open). Do not create restriction.
        if ($ipRules.Count -eq 0) { $outcome.Reason = 'SkippedOpen'; return $false }
        if ($ipRules | Where-Object { $_.value -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        $h = ConvertTo-Hashtable $nrs
        $h.ipRules = @($ipRules) + @(@{ value = $CallerIp })
        $resource.properties.networkRuleSet = $h   # whole-resource PUT (no PATCH exists)
        return $resource
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (not restricted or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITAiSearchRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  AI Search row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Search/searchServices/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:AiSearchApi -WriteMethod PUT -Modify {
        param($resource)
        $nrs = if ($resource.properties) { $resource.properties.networkRuleSet } else { $null }
        if (-not ($nrs -and $nrs.ipRules)) { return $false }   # already gone

        $ipRules   = @($nrs.ipRules)
        $remaining = @($ipRules | Where-Object { $_.value -ne $ipValue })
        if ($remaining.Count -eq $ipRules.Count) { return $false }   # already gone

        $h = ConvertTo-Hashtable $nrs
        $h.ipRules = $remaining
        $resource.properties.networkRuleSet = $h   # whole-resource PUT (no PATCH exists)
        return $resource
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
