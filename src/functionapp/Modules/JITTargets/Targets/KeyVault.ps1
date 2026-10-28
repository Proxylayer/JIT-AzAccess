# KeyVault.ps1
#region -- Key Vault ----------------------------------------------------------
# https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/update
# Vault network ACLs are also a property on the vault, similar PATCH model.
#
# Same array-on-resource race as Storage: a plain GET + PATCH lets two
# concurrent grants drop one another's IP. Routed through the shared ETag
# read-modify-write helper (If-Match + 412 re-read/retry).

# -- ARM API version -----------------------------------------------------------
$script:KeyVaultApi = '2023-07-01'   # Microsoft.KeyVault/vaults

function Add-JITKeyVaultNetworkRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path     = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                "/providers/Microsoft.KeyVault/vaults/$ResourceName"
    $newValue = "$CallerIp/32"

    $outcome = @{ Reason = 'SkippedOpen'; Note = 'no network restrictions; access already open' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:KeyVaultApi -WriteMethod PATCH -Modify {
        param($resource)
        $networkAcls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }

        # No networkAcls => vault isn't network-restricted; don't create one
        # (would require a defaultAction). Caller already has access.
        if (-not $networkAcls) {
            $outcome.Reason = 'SkippedOpen'
            $outcome.Note   = 'no network restrictions; access already open'
            return $false
        }

        $ipRules = @()
        if ($networkAcls.ipRules) { $ipRules = @($networkAcls.ipRules) }

        if ($ipRules | Where-Object { $_.value -eq $newValue -or $_.value -eq $CallerIp }) {
            $outcome.Reason = 'AlreadyPresent'
            $outcome.Note   = 'already present'
            return $false
        }

        # Re-send the whole networkAcls with only ipRules changed (preserve
        # defaultAction / bypass / virtualNetworkRules).
        $acl = ConvertTo-Hashtable $networkAcls
        $acl.ipRules = @($ipRules) + @(@{ value = $newValue })

        return @{ properties = @{ networkAcls = $acl } }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $newValue; Status = $outcome.Reason; Details = @{ note = $outcome.Note } }
    }
    return @{ RuleIdentifier = $newValue; Status = 'Created'; Details = @{} }
}

function Remove-JITKeyVaultNetworkRule {
    param([Parameter(Mandatory)]$Row)

    # For Key Vault, RuleIdentifier is stored as "$ip/32". Fall back to
    # CallerIp (bare) when null, and match either form below.
    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Key Vault row has neither RuleIdentifier nor CallerIp - cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }
    $bareIp = ($ipValue -split '/')[0]

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.KeyVault/vaults/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:KeyVaultApi -WriteMethod PATCH -Modify {
        param($resource)
        $networkAcls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }
        if (-not ($networkAcls -and $networkAcls.ipRules)) { return $false }

        $ipRules   = @($networkAcls.ipRules)
        $remaining = @($ipRules | Where-Object {
            $_.value -ne $bareIp -and $_.value -ne "$bareIp/32"
        })

        if ($remaining.Count -eq $ipRules.Count) { return $false }

        # Preserve the whole networkAcls (defaultAction etc.); only ipRules changes.
        $acl = ConvertTo-Hashtable $networkAcls
        $acl.ipRules = $remaining

        return @{ properties = @{ networkAcls = $acl } }
    }

    if (-not $r.Changed) {
        Write-Host "  Key Vault network rule '$ipValue' not found - already removed."
        return @{ Status = 'NotFound'; Details = @{} }
    }
    return @{ Status = 'Removed'; Details = @{} }
}

#endregion
