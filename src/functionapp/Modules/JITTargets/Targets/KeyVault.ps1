# KeyVault.ps1
#region ── Key Vault ──────────────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/update
# Vault network ACLs are also a property on the vault, similar PATCH model.

# ── ARM API version ───────────────────────────────────────────────────────────
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

    $vault       = Invoke-ArmRest -Path $path -ApiVersion $script:KeyVaultApi
    $networkAcls = if ($vault.properties) { $vault.properties.networkAcls } else { $null }

    # No networkAcls => vault isn't network-restricted; don't create one (would
    # require a defaultAction). Caller already has access.
    if (-not $networkAcls) {
        return @{ RuleIdentifier = $newValue; Status = 'SkippedOpen'; Details = @{ note = 'no network restrictions; access already open' } }
    }

    $ipRules = @()
    if ($networkAcls.ipRules) { $ipRules = @($networkAcls.ipRules) }

    if ($ipRules | Where-Object { $_.value -eq $newValue -or $_.value -eq $CallerIp }) {
        return @{ RuleIdentifier = $newValue; Status = 'AlreadyPresent'; Details = @{ note = 'already present' } }
    }

    # Re-send the whole networkAcls with only ipRules changed (preserve
    # defaultAction / bypass / virtualNetworkRules).
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = @($ipRules) + @(@{ value = $newValue })

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:KeyVaultApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null

    return @{ RuleIdentifier = $newValue; Status = 'Created'; Details = @{} }
}

function Remove-JITKeyVaultNetworkRule {
    param([Parameter(Mandatory)]$Row)

    # For Key Vault, RuleIdentifier is stored as "$ip/32". Fall back to
    # CallerIp (bare) when null, and match either form below.
    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Key Vault row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }
    $bareIp = ($ipValue -split '/')[0]

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.KeyVault/vaults/$($Row.ResourceName)"

    $vault       = Invoke-ArmRest -Path $path -ApiVersion $script:KeyVaultApi
    $networkAcls = if ($vault.properties) { $vault.properties.networkAcls } else { $null }
    if (-not ($networkAcls -and $networkAcls.ipRules)) {
        Write-Host "  Key Vault network rule '$ipValue' not found — already removed."
        return @{ Status = 'NotFound'; Details = @{} }
    }

    $ipRules   = @($networkAcls.ipRules)
    $remaining = @($ipRules | Where-Object {
        $_.value -ne $bareIp -and $_.value -ne "$bareIp/32"
    })

    if ($remaining.Count -eq $ipRules.Count) {
        Write-Host "  Key Vault network rule '$ipValue' not found — already removed."
        return @{ Status = 'NotFound'; Details = @{} }
    }

    # Preserve the whole networkAcls (defaultAction etc.); only ipRules changes.
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = $remaining

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:KeyVaultApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null

    return @{ Status = 'Removed'; Details = @{} }
}

#endregion
