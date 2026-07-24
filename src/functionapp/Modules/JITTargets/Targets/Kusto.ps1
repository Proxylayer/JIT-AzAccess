# Kusto.ps1
#region ── Azure Data Explorer (Kusto) clusters ────────────────────────────────
# https://learn.microsoft.com/rest/api/azurerekusto/clusters/update
#
# The IP allowlist is a BARE STRING array: properties.allowedIpRangeList[] holds
# plain "<ip>" strings (NOT objects). There is no defaultAction — an EMPTY list
# means the cluster is open, so adding the first entry would restrict it; we only
# add when the list is already configured (non-empty). Cluster update is
# long-running (202) — the shared RMW helper polls to completion.
# RuleIdentifier stored = caller IP.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:KustoApi = '2024-04-13'   # Microsoft.Kusto/clusters

function Add-JITKustoRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.Kusto/clusters/$ResourceName"

    # Distinguishes the two no-write outcomes (SkippedOpen vs AlreadyPresent).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:KustoApi -WriteMethod PATCH -Modify {
        param($resource)
        $props = if ($resource.properties) { $resource.properties } else { $null }
        $list  = @()
        if ($props -and $props.allowedIpRangeList) { $list = @($props.allowedIpRangeList) }

        # Empty => not restricted (open). Do not create restriction.
        if ($list.Count -eq 0) { $outcome.Reason = 'SkippedOpen'; return $false }
        if ($list -contains $CallerIp) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        $newList = @($list) + @($CallerIp)
        return @{ properties = @{ allowedIpRangeList = $newList } }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (not restricted or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITKustoRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Kusto row has neither RuleIdentifier nor CallerIp — cannot identify entry to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Kusto/clusters/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:KustoApi -WriteMethod PATCH -Modify {
        param($resource)
        $props = if ($resource.properties) { $resource.properties } else { $null }
        $list  = @()
        if ($props -and $props.allowedIpRangeList) { $list = @($props.allowedIpRangeList) }

        $remaining = @($list | Where-Object { $_ -ne $ipValue })
        if ($remaining.Count -eq $list.Count) { return $false }   # already gone
        return @{ properties = @{ allowedIpRangeList = $remaining } }
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
