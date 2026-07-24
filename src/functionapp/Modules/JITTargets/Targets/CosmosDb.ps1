# CosmosDb.ps1
#region ── Azure Cosmos DB (databaseAccounts) ──────────────────────────────────
# https://learn.microsoft.com/rest/api/cosmos-db-resource-provider/database-accounts/update
#
# The IP allowlist is an ARRAY on the account: properties.ipRules[] with entries
# shaped { ipAddressOrRange: "<ip>" }. There is no defaultAction — an EMPTY
# ipRules means the firewall is not configured (account open). Adding the first
# entry would RESTRICT the account, a posture change we must never make, so we
# only add when the firewall is already configured (ipRules already non-empty).
#
# Concurrent grants racing on the same array are handled by the shared ETag
# read-modify-write helper. Account update is long-running (202); the helper
# polls to completion. RuleIdentifier stored is the caller IP (like Storage).

# ── ARM API version ───────────────────────────────────────────────────────────
$script:CosmosDbApi = '2024-11-15'   # Microsoft.DocumentDB/databaseAccounts

function Add-JITCosmosDbRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.DocumentDB/databaseAccounts/$ResourceName"

    # Set by the -Modify block to distinguish the two no-write outcomes
    # (SkippedOpen = firewall not configured; AlreadyPresent = IP already listed).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:CosmosDbApi -WriteMethod PATCH -Modify {
        param($resource)
        $props   = if ($resource.properties) { $resource.properties } else { $null }
        $ipRules = @()
        if ($props -and $props.ipRules) { $ipRules = @($props.ipRules) }

        # Empty => firewall not configured (open). Do not restrict.
        if ($ipRules.Count -eq 0) { $outcome.Reason = 'SkippedOpen'; return $false }
        # Already present => idempotent no-op.
        if ($ipRules | Where-Object { $_.ipAddressOrRange -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }

        $newRules = @($ipRules) + @(@{ ipAddressOrRange = $CallerIp })
        return @{ properties = @{ ipRules = $newRules } }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (firewall not configured or already present)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITCosmosDbRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Cosmos DB row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.DocumentDB/databaseAccounts/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:CosmosDbApi -WriteMethod PATCH -Modify {
        param($resource)
        $props   = if ($resource.properties) { $resource.properties } else { $null }
        $ipRules = @()
        if ($props -and $props.ipRules) { $ipRules = @($props.ipRules) }

        $remaining = @($ipRules | Where-Object { $_.ipAddressOrRange -ne $ipValue })
        if ($remaining.Count -eq $ipRules.Count) { return $false }   # already gone
        return @{ properties = @{ ipRules = $remaining } }
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
