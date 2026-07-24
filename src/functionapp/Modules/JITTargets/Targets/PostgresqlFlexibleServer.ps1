# PostgresqlFlexibleServer.ps1
#region ── Azure Database for PostgreSQL Flexible Server ───────────────────────
# https://learn.microsoft.com/rest/api/postgresql/firewall-rules
#
# Two differences vs Azure SQL:
#   1. Firewall-rule PUT/DELETE are LONG-RUNNING — they reply 202 Accepted with
#      an Azure-AsyncOperation header we must poll to completion (via the generic
#      Wait-JITArmAsyncOperation in _Shared.ps1, to which we pass our own LRO
#      bounds below).
#   2. A private-access / VNet-integrated flexible server has NO firewall rules,
#      so a firewall-rule grant can never apply. We pre-flight the server's
#      networking and reject those with a distinguishable error the dispatcher
#      surfaces as a clean client denial (not a generic 500), using the sentinel
#      prefix ($script:PostgresPrivateRejectPrefix) defined below.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:PostgresApi = '2024-08-01'   # Microsoft.DBforPostgreSQL/flexibleServers

# ── Private-server rejection sentinel ─────────────────────────────────────────
# Sentinel prefix on the pre-flight rejection message so Request-JITAccess/run.ps1
# can distinguish a private-server denial from a genuine failure and return a
# clean 4xx + JITDenied audit event instead of a 500. Keep this literal in sync
# with the match in Request-JITAccess/run.ps1.
$script:PostgresPrivateRejectPrefix = 'PRIVATE_SERVER_REJECTED:'

# ── LRO poll bounds ───────────────────────────────────────────────────────────
# Firewall-rule ops normally complete in a few seconds; the cap protects the
# (synchronous) HTTP request and the timer worker from hanging. Passed to the
# generic Wait-JITArmAsyncOperation poller on each call.
$script:PostgresLroTimeoutSeconds     = 180
$script:PostgresLroDefaultPollSeconds = 5

function Add-JITPostgresFirewallRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $serverPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                  "/providers/Microsoft.DBforPostgreSQL/flexibleServers/$ResourceName"

    # ── Pre-flight: reject private-access / VNet-integrated servers ────────────
    # Such a server has no public firewall, so a firewall-rule grant is
    # inapplicable. Reject BEFORE the PUT with a distinguishable error.
    $server  = Invoke-ArmRest -Path $serverPath -ApiVersion $script:PostgresApi
    $network = if ($server.properties) { $server.properties.network } else { $null }
    $publicAccess    = if ($network) { $network.publicNetworkAccess }       else { $null }
    $delegatedSubnet = if ($network) { $network.delegatedSubnetResourceId } else { $null }

    if (($publicAccess -eq 'Disabled') -or $delegatedSubnet) {
        throw "$script:PostgresPrivateRejectPrefix PostgreSQL flexible server '$ResourceName' uses private/VNet networking; firewall-rule JIT access is not applicable."
    }

    # ── Idempotent add: skip if an existing rule already allows this IP ────────
    $existing = Invoke-ArmRest -Path "$serverPath/firewallRules" -ApiVersion $script:PostgresApi
    if (Test-JITFirewallRuleCoversIp -Rules $existing.value -CallerIp $CallerIp) {
        return @{ RuleIdentifier = $RuleId; Status = 'AlreadyPresent'; Details = @{ note = 'caller IP already allowed by an existing firewall rule' } }
    }

    # ── Create the firewall rule (single IP => start == end) ──────────────────
    # PUT is a long-running operation: 202 + Azure-AsyncOperation. Poll to
    # completion. Tolerate a synchronous 200/201 in case the API ever returns it.
    $resp = Invoke-ArmRestRaw -Method PUT `
        -Path       "$serverPath/firewallRules/$RuleId" `
        -ApiVersion $script:PostgresApi `
        -Body       @{
            properties = @{
                startIpAddress = $CallerIp
                endIpAddress   = $CallerIp
            }
        }

    if ($resp.StatusCode -eq 202) {
        Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
            -TimeoutSeconds     $script:PostgresLroTimeoutSeconds `
            -DefaultPollSeconds $script:PostgresLroDefaultPollSeconds
    }

    return @{ RuleIdentifier = $RuleId; Status = 'Created'; Details = @{} }
}

function Remove-JITPostgresFirewallRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the RowKey fallback rationale.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  PostgreSQL row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.DBforPostgreSQL/flexibleServers/$($Row.ResourceName)" +
            "/firewallRules/$ruleName"

    try {
        $resp = Invoke-ArmRestRaw -Method DELETE -Path $path -ApiVersion $script:PostgresApi
        # 204 No Content => already gone / synchronous delete — idempotent success,
        # no poll needed. 202 Accepted => long-running; poll to completion so a
        # failure/timeout throws (and the caller preserves the table row).
        if ($resp.StatusCode -eq 202) {
            Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
                -TimeoutSeconds     $script:PostgresLroTimeoutSeconds `
                -DefaultPollSeconds $script:PostgresLroDefaultPollSeconds
        }
        return @{ Status = 'Removed'; Details = @{} }
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  PostgreSQL firewall rule '$ruleName' not found — already removed."
            return @{ Status = 'NotFound'; Details = @{} }
        } else { throw }
    }
}

#endregion
