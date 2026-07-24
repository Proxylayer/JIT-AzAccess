# IotHub.ps1
#region ── Azure IoT Hub ───────────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/iothub/iot-hub-resource/create-or-update
#
# The IP allowlist lives under properties.networkRuleSets.ipRules[] with entries
# shaped { filterName: "<unique>", action: "Allow", ipMask: "<ip>" }. IoT Hub has
# no PATCH for network rule sets — the update is a full CreateOrUpdate (PUT) of
# the whole resource, which is long-running (202). networkRuleSets carries a
# defaultAction, so its presence marks a restricted hub (mirror Storage): no
# networkRuleSets => access already open, leave untouched. filterName must be
# unique per entry — we use the JIT rule id. RuleIdentifier stored = caller IP;
# removal matches on ipMask.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:IotHubApi = '2023-06-30'   # Microsoft.Devices/IotHubs

function Add-JITIotHubRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.Devices/IotHubs/$ResourceName"

    # Distinguishes the two no-write outcomes (SkippedOpen vs AlreadyPresent).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:IotHubApi -WriteMethod PUT -Modify {
        param($resource)
        $nrs = if ($resource.properties) { $resource.properties.networkRuleSets } else { $null }
        if (-not $nrs) { $outcome.Reason = 'SkippedOpen'; return $false }   # not network-restricted; access already open

        $ipRules = @()
        if ($nrs.ipRules) { $ipRules = @($nrs.ipRules) }
        if ($ipRules | Where-Object { $_.ipMask -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        $h = ConvertTo-Hashtable $nrs
        $h.ipRules = @($ipRules) + @(@{ filterName = $RuleId; action = 'Allow'; ipMask = $CallerIp })
        # Reassign the existing networkRuleSets property, then PUT the whole resource.
        $resource.properties.networkRuleSets = $h
        return $resource
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (not restricted or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITIotHubRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  IoT Hub row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Devices/IotHubs/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:IotHubApi -WriteMethod PUT -Modify {
        param($resource)
        $nrs = if ($resource.properties) { $resource.properties.networkRuleSets } else { $null }
        if (-not ($nrs -and $nrs.ipRules)) { return $false }   # already gone

        $ipRules   = @($nrs.ipRules)
        $remaining = @($ipRules | Where-Object { $_.ipMask -ne $ipValue })
        if ($remaining.Count -eq $ipRules.Count) { return $false }   # already gone

        $h = ConvertTo-Hashtable $nrs
        $h.ipRules = $remaining
        $resource.properties.networkRuleSets = $h
        return $resource
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
