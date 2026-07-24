# StorageAccount.ps1
#region ── Storage Account ────────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/storagerp/storage-accounts/update
# Storage account network ACLs aren't a child resource — they're a property
# on the account. We GET the whole account, PATCH the networkAcls.ipRules list.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:StorageMgmtApi = '2023-01-01'   # Microsoft.Storage/storageAccounts

function Add-JITStorageNetworkRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.Storage/storageAccounts/$ResourceName"

    $account     = Invoke-ArmRest -Path $path -ApiVersion $script:StorageMgmtApi
    $networkAcls = if ($account.properties) { $account.properties.networkAcls } else { $null }

    # No networkAcls => the account isn't network-restricted (open). Creating
    # one would require a defaultAction and change the resource's posture, which
    # we must never do — the caller already has access.
    if (-not $networkAcls) {
        return @{ RuleIdentifier = $CallerIp; Status = 'SkippedOpen'; Details = @{ note = 'no network restrictions; access already open' } }
    }

    $ipRules = @()
    if ($networkAcls.ipRules) { $ipRules = @($networkAcls.ipRules) }

    # Skip if already present (match bare IP or /32 form).
    if ($ipRules | Where-Object { $_.value -eq $CallerIp -or $_.value -eq "$CallerIp/32" }) {
        return @{ RuleIdentifier = $CallerIp; Status = 'AlreadyPresent'; Details = @{ note = 'already present' } }
    }

    # Re-send the ENTIRE existing networkAcls with only ipRules changed, so
    # defaultAction / bypass / virtualNetworkRules / resourceAccessRules are
    # preserved exactly as-is.
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = @($ipRules) + @(@{ value = $CallerIp; action = 'Allow' })

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:StorageMgmtApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null

    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITStorageNetworkRule {
    param([Parameter(Mandatory)]$Row)

    # For Storage, RuleIdentifier is the IP value (bare). Fall back to CallerIp
    # (same data) when an older row stored null. See Remove-JITNsgRule.
    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Storage row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Storage/storageAccounts/$($Row.ResourceName)"

    $account     = Invoke-ArmRest -Path $path -ApiVersion $script:StorageMgmtApi
    $networkAcls = if ($account.properties) { $account.properties.networkAcls } else { $null }
    if (-not ($networkAcls -and $networkAcls.ipRules)) {
        Write-Host "  Storage network rule for '$ipValue' not found — already removed."
        return @{ Status = 'NotFound'; Details = @{} }
    }

    $ipRules    = @($networkAcls.ipRules)
    # Match either bare IP or "$ip/32" since Add-* may have stored either form.
    $remaining  = @($ipRules | Where-Object {
        $_.value -ne $ipValue -and $_.value -ne "$ipValue/32"
    })

    if ($remaining.Count -eq $ipRules.Count) {
        Write-Host "  Storage network rule for '$ipValue' not found — already removed."
        return @{ Status = 'NotFound'; Details = @{} }
    }

    # Preserve the whole networkAcls (defaultAction etc.); only ipRules changes.
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = $remaining

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:StorageMgmtApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null

    return @{ Status = 'Removed'; Details = @{} }
}

#endregion
