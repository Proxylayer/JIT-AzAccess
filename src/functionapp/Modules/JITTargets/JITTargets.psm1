# JITTargets.psm1
# Per-resource-type Add/Remove handlers for JIT IP whitelisting.
# Each Add-* returns a hashtable with RuleIdentifier and Details.
# Each Remove-* accepts the row from Table Storage and cleans up.

#region ── NSG ────────────────────────────────────────────────────────────────

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

    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    $nsg      = Get-AzNetworkSecurityGroup -Name $ResourceName -ResourceGroupName $ResourceGroup -ErrorAction Stop
    $priority = Get-AvailableNsgPriority   -Nsg $nsg -Min $PriorityMin -Max $PriorityMax

    $nsg | Add-AzNetworkSecurityRuleConfig `
            -Name                     $RuleId `
            -Protocol                 '*' `
            -SourceAddressPrefix      $CallerIp `
            -SourcePortRange          '*' `
            -DestinationAddressPrefix '*' `
            -DestinationPortRange     $Port `
            -Access                   Allow `
            -Priority                 $priority `
            -Direction                Inbound `
        | Set-AzNetworkSecurityGroup | Out-Null

    return @{ RuleIdentifier = $RuleId; Details = @{ priority = $priority; port = $Port } }
}

function Remove-JITNsgRule {
    param([Parameter(Mandatory)]$Row)

    Set-AzContext -SubscriptionId $Row.SubscriptionId -ErrorAction Stop | Out-Null

    $nsg = Get-AzNetworkSecurityGroup -Name $Row.ResourceName -ResourceGroupName $Row.ResourceRg -ErrorAction Stop

    if ($nsg.SecurityRules | Where-Object { $_.Name -eq $Row.RuleIdentifier }) {
        $nsg | Remove-AzNetworkSecurityRuleConfig -Name $Row.RuleIdentifier -ErrorAction Stop `
            | Set-AzNetworkSecurityGroup | Out-Null
    }
    else {
        Write-Host "  NSG rule '$($Row.RuleIdentifier)' not found — already removed."
    }
}

#endregion

#region ── Azure SQL Server ───────────────────────────────────────────────────

function Add-JITSqlFirewallRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    New-AzSqlServerFirewallRule `
        -ResourceGroupName $ResourceGroup `
        -ServerName        $ResourceName `
        -FirewallRuleName  $RuleId `
        -StartIpAddress    $CallerIp `
        -EndIpAddress      $CallerIp `
        -ErrorAction       Stop | Out-Null

    return @{ RuleIdentifier = $RuleId; Details = @{} }
}

function Remove-JITSqlFirewallRule {
    param([Parameter(Mandatory)]$Row)

    Set-AzContext -SubscriptionId $Row.SubscriptionId -ErrorAction Stop | Out-Null

    $exists = Get-AzSqlServerFirewallRule `
                  -ResourceGroupName $Row.ResourceRg `
                  -ServerName        $Row.ResourceName `
                  -FirewallRuleName  $Row.RuleIdentifier `
                  -ErrorAction       SilentlyContinue

    if ($exists) {
        Remove-AzSqlServerFirewallRule `
            -ResourceGroupName $Row.ResourceRg `
            -ServerName        $Row.ResourceName `
            -FirewallRuleName  $Row.RuleIdentifier `
            -Force             -ErrorAction Stop
    }
    else {
        Write-Host "  SQL firewall rule '$($Row.RuleIdentifier)' not found — already removed."
    }
}

#endregion

#region ── Storage Account ────────────────────────────────────────────────────

function Add-JITStorageNetworkRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    Add-AzStorageAccountNetworkRule `
        -ResourceGroupName  $ResourceGroup `
        -Name               $ResourceName `
        -IPAddressOrRange   $CallerIp `
        -ErrorAction        Stop | Out-Null

    # Storage rules are identified by IP, not a name — store the IP as the identifier
    return @{ RuleIdentifier = $CallerIp; Details = @{} }
}

function Remove-JITStorageNetworkRule {
    param([Parameter(Mandatory)]$Row)

    Set-AzContext -SubscriptionId $Row.SubscriptionId -ErrorAction Stop | Out-Null

    $account = Get-AzStorageAccount -ResourceGroupName $Row.ResourceRg -Name $Row.ResourceName -ErrorAction Stop
    $existing = $account.NetworkRuleSet.IpRules | Where-Object { $_.IPAddressOrRange -eq $Row.RuleIdentifier }

    if ($existing) {
        Remove-AzStorageAccountNetworkRule `
            -ResourceGroupName $Row.ResourceRg `
            -Name              $Row.ResourceName `
            -IPAddressOrRange  $Row.RuleIdentifier `
            -ErrorAction       Stop | Out-Null
    }
    else {
        Write-Host "  Storage network rule for '$($Row.RuleIdentifier)' not found — already removed."
    }
}

#endregion

#region ── Key Vault ──────────────────────────────────────────────────────────

function Add-JITKeyVaultNetworkRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    # Key Vault network rules require CIDR notation
    Add-AzKeyVaultNetworkRule `
        -VaultName         $ResourceName `
        -ResourceGroupName $ResourceGroup `
        -IpAddressRange    "$CallerIp/32" `
        -ErrorAction       Stop | Out-Null

    # Key Vault rules are identified by IP CIDR, not a name
    return @{ RuleIdentifier = "$CallerIp/32"; Details = @{} }
}

function Remove-JITKeyVaultNetworkRule {
    param([Parameter(Mandatory)]$Row)

    Set-AzContext -SubscriptionId $Row.SubscriptionId -ErrorAction Stop | Out-Null

    $vault    = Get-AzKeyVault -VaultName $Row.ResourceName -ResourceGroupName $Row.ResourceRg -ErrorAction Stop
    $existing = $vault.NetworkAcls.IpAddressRanges | Where-Object { $_ -eq $Row.RuleIdentifier }

    if ($existing) {
        Remove-AzKeyVaultNetworkRule `
            -VaultName         $Row.ResourceName `
            -ResourceGroupName $Row.ResourceRg `
            -IpAddressRange    $Row.RuleIdentifier `
            -ErrorAction       Stop | Out-Null
    }
    else {
        Write-Host "  Key Vault network rule '$($Row.RuleIdentifier)' not found — already removed."
    }
}

#endregion

Export-ModuleMember -Function @(
    'Add-JITNsgRule';           'Remove-JITNsgRule'
    'Add-JITSqlFirewallRule';   'Remove-JITSqlFirewallRule'
    'Add-JITStorageNetworkRule';'Remove-JITStorageNetworkRule'
    'Add-JITKeyVaultNetworkRule';'Remove-JITKeyVaultNetworkRule'
)
