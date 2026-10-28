# StorageAccount.ps1
#region -- Storage Account ----------------------------------------------------
# https://learn.microsoft.com/rest/api/storagerp/storage-accounts/update
# Storage account network ACLs aren't a child resource - they're a property
# on the account. We GET the whole account, PATCH the networkAcls.ipRules list.
#
# Because the allowlist is an ARRAY on the resource, two concurrent grants that
# both GET, append their IP and write back will have the second write silently
# drop the first IP. This used to be a plain Invoke-ArmRest GET + PATCH, i.e.
# exactly that race; it now goes through the shared ETag read-modify-write
# helper (If-Match + 412 re-read/retry) like every other array-on-resource type.

# -- ARM API version -----------------------------------------------------------
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

    # Set by the -Modify block to distinguish the two no-write outcomes
    # (SkippedOpen = not network-restricted; AlreadyPresent = IP already listed).
    $outcome = @{ Reason = 'SkippedOpen'; Note = 'no network restrictions; access already open' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:StorageMgmtApi -WriteMethod PATCH -Modify {
        param($resource)
        $networkAcls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }

        # No networkAcls => the account isn't network-restricted (open).
        # Creating one would require a defaultAction and change the resource's
        # posture, which we must never do - the caller already has access.
        if (-not $networkAcls) {
            $outcome.Reason = 'SkippedOpen'
            $outcome.Note   = 'no network restrictions; access already open'
            return $false
        }

        $ipRules = @()
        if ($networkAcls.ipRules) { $ipRules = @($networkAcls.ipRules) }

        # Skip if already present (match bare IP or /32 form).
        if ($ipRules | Where-Object { $_.value -eq $CallerIp -or $_.value -eq "$CallerIp/32" }) {
            $outcome.Reason = 'AlreadyPresent'
            $outcome.Note   = 'already present'
            return $false
        }

        # Re-send the ENTIRE existing networkAcls with only ipRules changed, so
        # defaultAction / bypass / virtualNetworkRules / resourceAccessRules are
        # preserved exactly as-is.
        $acl = ConvertTo-Hashtable $networkAcls
        $acl.ipRules = @($ipRules) + @(@{ value = $CallerIp; action = 'Allow' })

        return @{ properties = @{ networkAcls = $acl } }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = $outcome.Note } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITStorageNetworkRule {
    param([Parameter(Mandatory)]$Row)

    # For Storage, RuleIdentifier is the IP value (bare). Fall back to CallerIp
    # (same data) when an older row stored null. See Remove-JITNsgRule.
    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Storage row has neither RuleIdentifier nor CallerIp - cannot identify ipRule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Storage/storageAccounts/$($Row.ResourceName)"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:StorageMgmtApi -WriteMethod PATCH -Modify {
        param($resource)
        $networkAcls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }
        if (-not ($networkAcls -and $networkAcls.ipRules)) { return $false }

        $ipRules = @($networkAcls.ipRules)
        # Match either bare IP or "$ip/32" since Add-* may have stored either form.
        $remaining = @($ipRules | Where-Object {
            $_.value -ne $ipValue -and $_.value -ne "$ipValue/32"
        })

        if ($remaining.Count -eq $ipRules.Count) { return $false }

        # Preserve the whole networkAcls (defaultAction etc.); only ipRules changes.
        $acl = ConvertTo-Hashtable $networkAcls
        $acl.ipRules = $remaining

        return @{ properties = @{ networkAcls = $acl } }
    }

    if (-not $r.Changed) {
        Write-Host "  Storage network rule for '$ipValue' not found - already removed."
        return @{ Status = 'NotFound'; Details = @{} }
    }
    return @{ Status = 'Removed'; Details = @{} }
}

#endregion
