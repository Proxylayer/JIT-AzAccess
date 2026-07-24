# MysqlFlexibleServer.ps1
#region ── Azure Database for MySQL Flexible Server ────────────────────────────
# https://learn.microsoft.com/rest/api/mysql/flexibleserver/firewall-rules
#
# Same child-firewall-rule model as PostgreSQL flexible server: PUT/DELETE a
# firewallRules/{ruleName} child with body {properties:{startIpAddress,endIpAddress}}
# (single IP => start == end). Firewall-rule create/delete are long-running, so
# we tolerate a 202 Accepted and poll to completion via Wait-JITArmAsyncOperation
# (and still accept a synchronous 200/201/204 if the API returns one).

# ── ARM API version ───────────────────────────────────────────────────────────
$script:MysqlApi = '2023-12-30'   # Microsoft.DBforMySQL/flexibleServers

# ── LRO poll bounds ───────────────────────────────────────────────────────────
$script:MysqlLroTimeoutSeconds     = 180
$script:MysqlLroDefaultPollSeconds = 5

function Add-JITMysqlFlexibleServerRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $serverPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                  "/providers/Microsoft.DBforMySQL/flexibleServers/$ResourceName"

    # Idempotent add: skip if an existing rule already allows this IP.
    $existing = Invoke-ArmRest -Path "$serverPath/firewallRules" -ApiVersion $script:MysqlApi
    if (Test-JITFirewallRuleCoversIp -Rules $existing.value -CallerIp $CallerIp) {
        return @{ RuleIdentifier = $RuleId; Status = 'AlreadyPresent'; Details = @{ note = 'caller IP already allowed by an existing firewall rule' } }
    }

    $resp = Invoke-ArmRestRaw -Method PUT -Path "$serverPath/firewallRules/$RuleId" -ApiVersion $script:MysqlApi -Body @{
        properties = @{
            startIpAddress = $CallerIp
            endIpAddress   = $CallerIp
        }
    }

    if ($resp.StatusCode -eq 202) {
        Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
            -TimeoutSeconds     $script:MysqlLroTimeoutSeconds `
            -DefaultPollSeconds $script:MysqlLroDefaultPollSeconds
    }

    return @{ RuleIdentifier = $RuleId; Status = 'Created'; Details = @{} }
}

function Remove-JITMysqlFlexibleServerRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the RowKey fallback rationale.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  MySQL row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.DBforMySQL/flexibleServers/$($Row.ResourceName)" +
            "/firewallRules/$ruleName"

    try {
        $resp = Invoke-ArmRestRaw -Method DELETE -Path $path -ApiVersion $script:MysqlApi
        if ($resp.StatusCode -eq 202) {
            Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
                -TimeoutSeconds     $script:MysqlLroTimeoutSeconds `
                -DefaultPollSeconds $script:MysqlLroDefaultPollSeconds
        }
        return @{ Status = 'Removed'; Details = @{} }
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  MySQL firewall rule '$ruleName' not found — already removed."
            return @{ Status = 'NotFound'; Details = @{} }
        } else { throw }
    }
}

#endregion
