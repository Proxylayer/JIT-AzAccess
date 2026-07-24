# SignalR.ps1
#region ── Azure SignalR Service ───────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/signalr/signal-r/update
#
# The IP allowlist lives under properties.networkACLs.ipRules[] with entries
# shaped { value: "<ip>", action: "Allow" }. networkACLs also holds defaultAction,
# publicNetwork, and privateEndpoints ACLs that MUST be preserved — we re-send the
# WHOLE networkACLs with only ipRules changed so those siblings are never reset.
# Its presence marks a restricted resource (mirror Storage): no networkACLs =>
# access already open, leave untouched. Update is long-running (202) — the shared
# RMW helper polls to completion. RuleIdentifier stored = caller IP.
#
# NOTE: network ACLs require the Standard tier (or higher).

# ── ARM API version ───────────────────────────────────────────────────────────
$script:SignalRApi = '2024-03-01'   # Microsoft.SignalRService/signalR

function Add-JITSignalRRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.SignalRService/signalR/$ResourceName"

    # Distinguishes the two no-write outcomes (SkippedOpen vs AlreadyPresent).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:SignalRApi -WriteMethod PATCH -Modify {
        param($resource)
        $acls = if ($resource.properties) { $resource.properties.networkACLs } else { $null }
        if (-not $acls) { $outcome.Reason = 'SkippedOpen'; return $false }   # not network-restricted; access already open

        $ipRules = @()
        if ($acls.ipRules) { $ipRules = @($acls.ipRules) }
        if ($ipRules | Where-Object { $_.value -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        $h = ConvertTo-Hashtable $acls   # preserves defaultAction / publicNetwork / privateEndpoints
        $h.ipRules = @($ipRules) + @(@{ value = $CallerIp; action = 'Allow' })
        return @{ properties = @{ networkACLs = $h } }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (not restricted or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITSignalRRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  SignalR row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.SignalRService/signalR/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:SignalRApi -WriteMethod PATCH -Modify {
        param($resource)
        $acls = if ($resource.properties) { $resource.properties.networkACLs } else { $null }
        if (-not ($acls -and $acls.ipRules)) { return $false }   # already gone

        $ipRules   = @($acls.ipRules)
        $remaining = @($ipRules | Where-Object { $_.value -ne $ipValue })
        if ($remaining.Count -eq $ipRules.Count) { return $false }   # already gone

        $h = ConvertTo-Hashtable $acls
        $h.ipRules = $remaining
        return @{ properties = @{ networkACLs = $h } }
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
