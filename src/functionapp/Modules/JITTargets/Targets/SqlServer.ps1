# SqlServer.ps1
#region ── Azure SQL Server ───────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/sql/firewall-rules

# ── ARM API version ───────────────────────────────────────────────────────────
$script:SqlApi = '2021-11-01'   # Microsoft.Sql/servers/firewallRules

function Add-JITSqlFirewallRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $serverPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                  "/providers/Microsoft.Sql/servers/$ResourceName"

    # Idempotent add: if an existing firewall rule already allows this IP
    # (start <= ip <= end), don't create a duplicate.
    $existing = Invoke-ArmRest -Path "$serverPath/firewallRules" -ApiVersion $script:SqlApi
    if (Test-JITFirewallRuleCoversIp -Rules $existing.value -CallerIp $CallerIp) {
        return @{ RuleIdentifier = $RuleId; Status = 'AlreadyPresent'; Details = @{ note = 'caller IP already allowed by an existing firewall rule' } }
    }

    Invoke-ArmRest -Method PUT -Path "$serverPath/firewallRules/$RuleId" -ApiVersion $script:SqlApi -Body @{
        properties = @{
            startIpAddress = $CallerIp
            endIpAddress   = $CallerIp
        }
    } | Out-Null

    return @{ RuleIdentifier = $RuleId; Status = 'Created'; Details = @{} }
}

function Remove-JITSqlFirewallRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the rationale — fall back to RowKey when an
    # older row has a null RuleIdentifier.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  SQL row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Sql/servers/$($Row.ResourceName)/firewallRules/$ruleName"

    try {
        Invoke-ArmRest -Method DELETE -Path $path -ApiVersion $script:SqlApi | Out-Null
        return @{ Status = 'Removed'; Details = @{} }
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  SQL firewall rule '$ruleName' not found — already removed."
            return @{ Status = 'NotFound'; Details = @{} }
        } else { throw }
    }
}

#endregion
