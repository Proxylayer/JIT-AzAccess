# Redis.ps1
#region ── Azure Cache for Redis ───────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/redis/firewall-rules
#
# Child-firewall-rule model, but the body uses DIFFERENT IP field names than
# SQL/PostgreSQL/MySQL: `startIP` / `endIP` (not startIpAddress/endIpAddress).
# Firewall-rule create/delete are synchronous; we still tolerate a 202 + poll
# defensively so a future async switch wouldn't strand a grant.
#
# NOTE: firewall rules require a Standard tier (or higher) cache — a Basic-tier
# cache has no firewall to write to.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:RedisApi = '2024-11-01'   # Microsoft.Cache/Redis

# ── LRO poll bounds (defensive — Redis firewall ops are normally synchronous) ─
$script:RedisLroTimeoutSeconds     = 180
$script:RedisLroDefaultPollSeconds = 5

function Add-JITRedisRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $cachePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                 "/providers/Microsoft.Cache/Redis/$ResourceName"

    # Idempotent add: skip if an existing rule already allows this IP. Redis uses
    # startIP/endIP (not startIpAddress/endIpAddress).
    $existing = Invoke-ArmRest -Path "$cachePath/firewallRules" -ApiVersion $script:RedisApi
    if (Test-JITFirewallRuleCoversIp -Rules $existing.value -CallerIp $CallerIp -StartField 'startIP' -EndField 'endIP') {
        return @{ RuleIdentifier = $RuleId; Status = 'AlreadyPresent'; Details = @{ note = 'caller IP already allowed by an existing firewall rule' } }
    }

    $resp = Invoke-ArmRestRaw -Method PUT -Path "$cachePath/firewallRules/$RuleId" -ApiVersion $script:RedisApi -Body @{
        properties = @{
            startIP = $CallerIp
            endIP   = $CallerIp
        }
    }

    if ($resp.StatusCode -eq 202) {
        Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
            -TimeoutSeconds     $script:RedisLroTimeoutSeconds `
            -DefaultPollSeconds $script:RedisLroDefaultPollSeconds
    }

    return @{ RuleIdentifier = $RuleId; Status = 'Created'; Details = @{} }
}

function Remove-JITRedisRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the RowKey fallback rationale.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  Redis row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Cache/Redis/$($Row.ResourceName)" +
            "/firewallRules/$ruleName"

    # Existence-reconciling idempotent delete — see Remove-JITChildRuleWithLro.
    return Remove-JITChildRuleWithLro `
        -Path               $path `
        -ApiVersion         $script:RedisApi `
        -RuleName           $ruleName `
        -TypeLabel          'Redis firewall' `
        -TimeoutSeconds     $script:RedisLroTimeoutSeconds `
        -DefaultPollSeconds $script:RedisLroDefaultPollSeconds
}

#endregion
