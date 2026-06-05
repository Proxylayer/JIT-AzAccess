# JITTargets.psm1
# Per-resource-type Add/Remove handlers for JIT IP whitelisting.
#
# 100% REST via Invoke-ArmRest — no Az.* PowerShell modules. Each Add-*
# returns a hashtable with RuleIdentifier and Details. Each Remove-*
# accepts the row from Table Storage and cleans up.
#
# IMPORTANT: HttpHelpers and JITHelpers must already be loaded in global
# scope before any JITTargets function is invoked. Each endpoint's run.ps1
# imports them in the right order. We do NOT Import-Module them here, since
# nested Import-Module -Force wipes the inner module's ExportedCommands.

function script:ConvertTo-Hashtable {
    # Shallow-clones a PSCustomObject (e.g. from Invoke-RestMethod) into a
    # hashtable so we can change ONE property and PATCH the whole object back,
    # preserving every other field. Critical for networkAcls: a PATCH that
    # sends only ipRules resets defaultAction/bypass/virtualNetworkRules to
    # ARM defaults — which can flip a resource to public. We never want that.
    param($InputObject)
    $h = @{}
    if ($null -eq $InputObject) { return $h }
    foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

#region ── NSG ────────────────────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/virtualnetwork/security-rules

$script:NsgApi = '2024-03-01'

function Add-JITNsgRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId,
        [string]$Port        = '*',
        [int]   $PriorityMin = 1000,
        [int]   $PriorityMax = 3900
    )

    $nsgPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
               "/providers/Microsoft.Network/networkSecurityGroups/$ResourceName"

    # GET current NSG to pick a free priority.
    $nsg      = Invoke-ArmRest -Path $nsgPath -ApiVersion $script:NsgApi
    $priority = Get-AvailableNsgPriority `
                    -Nsg @{ SecurityRules = @($nsg.properties.securityRules | ForEach-Object {
                            [pscustomobject]@{ Direction = $_.properties.direction; Priority = $_.properties.priority }
                        }) } `
                    -Min $PriorityMin -Max $PriorityMax

    # PUT the individual security rule — Azure merges this into the NSG.
    # This is an IP whitelist: open ANY source port to ANY destination port for
    # the caller's IP (all protocols). The requested $Port is ignored for the
    # rule itself and kept only for the audit record.
    $ruleBody = @{
        properties = @{
            protocol                  = '*'
            sourcePortRange           = '*'
            destinationPortRange      = '*'
            sourceAddressPrefix       = $CallerIp
            destinationAddressPrefix  = '*'
            access                    = 'Allow'
            priority                  = $priority
            direction                 = 'Inbound'
        }
    }
    Invoke-ArmRest -Method PUT `
        -Path       "$nsgPath/securityRules/$RuleId" `
        -ApiVersion $script:NsgApi `
        -Body       $ruleBody | Out-Null

    return @{ RuleIdentifier = $RuleId; Details = @{ priority = $priority; port = $Port } }
}

function Remove-JITNsgRule {
    param([Parameter(Mandatory)]$Row)

    # RuleIdentifier should equal RowKey for NSG rules (Add-JITNsgRule returns
    # RuleIdentifier = $RuleId), but older builds could write null here when
    # the lock scriptblock swallowed $result. Fall back to RowKey so cleanup
    # never strands a rule due to a missing column.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  NSG row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return
    }

    $rulePath = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
                "/providers/Microsoft.Network/networkSecurityGroups/$($Row.ResourceName)" +
                "/securityRules/$ruleName"

    try {
        Invoke-ArmRest -Method DELETE -Path $rulePath -ApiVersion $script:NsgApi | Out-Null
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  NSG rule '$ruleName' not found — already removed."
        } else { throw }
    }
}

#endregion

#region ── Azure SQL Server ───────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/sql/firewall-rules

$script:SqlApi = '2021-11-01'

function Add-JITSqlFirewallRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.Sql/servers/$ResourceName/firewallRules/$RuleId"

    Invoke-ArmRest -Method PUT -Path $path -ApiVersion $script:SqlApi -Body @{
        properties = @{
            startIpAddress = $CallerIp
            endIpAddress   = $CallerIp
        }
    } | Out-Null

    return @{ RuleIdentifier = $RuleId; Details = @{} }
}

function Remove-JITSqlFirewallRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the rationale — fall back to RowKey when an
    # older row has a null RuleIdentifier.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  SQL row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Sql/servers/$($Row.ResourceName)/firewallRules/$ruleName"

    try {
        Invoke-ArmRest -Method DELETE -Path $path -ApiVersion $script:SqlApi | Out-Null
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  SQL firewall rule '$ruleName' not found — already removed."
        } else { throw }
    }
}

#endregion

#region ── Storage Account ────────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/storagerp/storage-accounts/update
# Storage account network ACLs aren't a child resource — they're a property
# on the account. We GET the whole account, PATCH the networkAcls.ipRules list.

$script:StorageMgmtApi = '2023-01-01'

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
        return @{ RuleIdentifier = $CallerIp; Details = @{ note = 'no network restrictions; access already open' } }
    }

    $ipRules = @()
    if ($networkAcls.ipRules) { $ipRules = @($networkAcls.ipRules) }

    # Skip if already present (match bare IP or /32 form).
    if ($ipRules | Where-Object { $_.value -eq $CallerIp -or $_.value -eq "$CallerIp/32" }) {
        return @{ RuleIdentifier = $CallerIp; Details = @{ note = 'already present' } }
    }

    # Re-send the ENTIRE existing networkAcls with only ipRules changed, so
    # defaultAction / bypass / virtualNetworkRules / resourceAccessRules are
    # preserved exactly as-is.
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = @($ipRules) + @(@{ value = $CallerIp; action = 'Allow' })

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:StorageMgmtApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null

    return @{ RuleIdentifier = $CallerIp; Details = @{} }
}

function Remove-JITStorageNetworkRule {
    param([Parameter(Mandatory)]$Row)

    # For Storage, RuleIdentifier is the IP value (bare). Fall back to CallerIp
    # (same data) when an older row stored null. See Remove-JITNsgRule.
    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Storage row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Storage/storageAccounts/$($Row.ResourceName)"

    $account     = Invoke-ArmRest -Path $path -ApiVersion $script:StorageMgmtApi
    $networkAcls = if ($account.properties) { $account.properties.networkAcls } else { $null }
    if (-not ($networkAcls -and $networkAcls.ipRules)) {
        Write-Host "  Storage network rule for '$ipValue' not found — already removed."
        return
    }

    $ipRules    = @($networkAcls.ipRules)
    # Match either bare IP or "$ip/32" since Add-* may have stored either form.
    $remaining  = @($ipRules | Where-Object {
        $_.value -ne $ipValue -and $_.value -ne "$ipValue/32"
    })

    if ($remaining.Count -eq $ipRules.Count) {
        Write-Host "  Storage network rule for '$ipValue' not found — already removed."
        return
    }

    # Preserve the whole networkAcls (defaultAction etc.); only ipRules changes.
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = $remaining

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:StorageMgmtApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null
}

#endregion

#region ── Key Vault ──────────────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/update
# Vault network ACLs are also a property on the vault, similar PATCH model.

$script:KeyVaultApi = '2023-07-01'

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
        return @{ RuleIdentifier = $newValue; Details = @{ note = 'no network restrictions; access already open' } }
    }

    $ipRules = @()
    if ($networkAcls.ipRules) { $ipRules = @($networkAcls.ipRules) }

    if ($ipRules | Where-Object { $_.value -eq $newValue -or $_.value -eq $CallerIp }) {
        return @{ RuleIdentifier = $newValue; Details = @{ note = 'already present' } }
    }

    # Re-send the whole networkAcls with only ipRules changed (preserve
    # defaultAction / bypass / virtualNetworkRules).
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = @($ipRules) + @(@{ value = $newValue })

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:KeyVaultApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null

    return @{ RuleIdentifier = $newValue; Details = @{} }
}

function Remove-JITKeyVaultNetworkRule {
    param([Parameter(Mandatory)]$Row)

    # For Key Vault, RuleIdentifier is stored as "$ip/32". Fall back to
    # CallerIp (bare) when null, and match either form below.
    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  Key Vault row has neither RuleIdentifier nor CallerIp — cannot identify ipRule to remove."
        return
    }
    $bareIp = ($ipValue -split '/')[0]

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.KeyVault/vaults/$($Row.ResourceName)"

    $vault       = Invoke-ArmRest -Path $path -ApiVersion $script:KeyVaultApi
    $networkAcls = if ($vault.properties) { $vault.properties.networkAcls } else { $null }
    if (-not ($networkAcls -and $networkAcls.ipRules)) {
        Write-Host "  Key Vault network rule '$ipValue' not found — already removed."
        return
    }

    $ipRules   = @($networkAcls.ipRules)
    $remaining = @($ipRules | Where-Object {
        $_.value -ne $bareIp -and $_.value -ne "$bareIp/32"
    })

    if ($remaining.Count -eq $ipRules.Count) {
        Write-Host "  Key Vault network rule '$ipValue' not found — already removed."
        return
    }

    # Preserve the whole networkAcls (defaultAction etc.); only ipRules changes.
    $acl = ConvertTo-Hashtable $networkAcls
    $acl.ipRules = $remaining

    Invoke-ArmRest -Method PATCH -Path $path -ApiVersion $script:KeyVaultApi -Body @{
        properties = @{ networkAcls = $acl }
    } | Out-Null
}

#endregion

Export-ModuleMember -Function @(
    'Add-JITNsgRule';           'Remove-JITNsgRule'
    'Add-JITSqlFirewallRule';   'Remove-JITSqlFirewallRule'
    'Add-JITStorageNetworkRule';'Remove-JITStorageNetworkRule'
    'Add-JITKeyVaultNetworkRule';'Remove-JITKeyVaultNetworkRule'
)
