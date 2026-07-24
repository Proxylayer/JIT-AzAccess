# CognitiveServices.ps1
#region ── Azure AI Services / Cognitive Services (incl. Azure OpenAI) ──────────
# https://learn.microsoft.com/rest/api/aiservices/accountmanagement/accounts/update
#
# The IP allowlist lives under properties.networkAcls.ipRules[] with entries
# shaped { value: "<ip>" }. networkAcls carries a defaultAction, so its presence
# marks a restricted account (mirror of Storage/Key Vault): no networkAcls =>
# access already open, leave untouched. We re-send the WHOLE networkAcls with
# only ipRules changed so defaultAction / virtualNetworkRules are preserved.
# This covers Azure OpenAI (same Microsoft.CognitiveServices/accounts type).
# RuleIdentifier stored = caller IP.
#
# NOTE: the firewall only takes effect when publicNetworkAccess = Enabled and
# networkAcls.defaultAction = Deny.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:CognitiveServicesApi = '2024-10-01'   # Microsoft.CognitiveServices/accounts

function Add-JITCognitiveServicesRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.CognitiveServices/accounts/$ResourceName"

    # Distinguishes the two no-write outcomes (SkippedOpen vs AlreadyPresent).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:CognitiveServicesApi -WriteMethod PATCH -Modify {
        param($resource)
        $acls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }
        if (-not $acls) { $outcome.Reason = 'SkippedOpen'; return $false }   # not network-restricted; access already open

        $ipRules = @()
        if ($acls.ipRules) { $ipRules = @($acls.ipRules) }
        if ($ipRules | Where-Object { $_.value -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        $h = ConvertTo-Hashtable $acls
        $h.ipRules = @($ipRules) + @(@{ value = $CallerIp })
        return @{ properties = @{ networkAcls = $h } }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (not restricted or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITCognitiveServicesRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Cognitive Services row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.CognitiveServices/accounts/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:CognitiveServicesApi -WriteMethod PATCH -Modify {
        param($resource)
        $acls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }
        if (-not ($acls -and $acls.ipRules)) { return $false }   # already gone

        $ipRules   = @($acls.ipRules)
        $remaining = @($ipRules | Where-Object { $_.value -ne $ipValue })
        if ($remaining.Count -eq $ipRules.Count) { return $false }   # already gone

        $h = ConvertTo-Hashtable $acls
        $h.ipRules = $remaining
        return @{ properties = @{ networkAcls = $h } }
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
