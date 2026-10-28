# Nsg.ps1
#region ── NSG ────────────────────────────────────────────────────────────────
# https://learn.microsoft.com/rest/api/virtualnetwork/security-rules

# ── ARM API version ───────────────────────────────────────────────────────────
$script:NsgApi = '2024-03-01'   # Microsoft.Network/networkSecurityGroups

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

    # Best-effort already-present detection: if an existing inbound Allow rule
    # already names this exact source IP (bare or /32), treat it as present and
    # skip creating a duplicate. LIMITATION: this matches only an exact single-IP
    # source — it does NOT evaluate CIDR ranges, 'sourceAddressPrefixes' arrays,
    # service tags, or per-port scope, so a caller IP covered by a broader rule is
    # still (conservatively) treated as not-present and a new JIT rule is created.
    $existingAllow = @($nsg.properties.securityRules | Where-Object {
        $_.properties.direction -eq 'Inbound' -and
        $_.properties.access    -eq 'Allow'    -and
        ($_.properties.sourceAddressPrefix -eq $CallerIp -or $_.properties.sourceAddressPrefix -eq "$CallerIp/32")
    })
    if ($existingAllow.Count -gt 0) {
        return @{ RuleIdentifier = $RuleId; Status = 'AlreadyPresent'; Details = @{ note = 'caller IP already allowed by an existing inbound security rule'; matchedRule = $existingAllow[0].name } }
    }

    $priority = Get-AvailableNsgPriority `
                    -Nsg @{ SecurityRules = @($nsg.properties.securityRules | ForEach-Object {
                            [pscustomobject]@{ Direction = $_.properties.direction; Priority = $_.properties.priority }
                        }) } `
                    -Min $PriorityMin -Max $PriorityMax

    # PUT the individual security rule — Azure merges this into the NSG.
    #
    # NOT YET PORT-SCOPED. This opens ANY source port to ANY destination port
    # on ALL protocols for the caller's IP. The caller's requested $Port is
    # accepted, validated and recorded on the audit row, but it is NOT applied
    # to the rule — so a request for 443 grants the caller's IP the NSG's
    # entire inbound surface while the audit trail reads "443".
    #
    # Do not assume the port is enforced. Enforcing it (writing
    # destinationPortRange from $Port, '*' only when no port was given) is a
    # deliberate follow-up: it narrows access for anyone currently relying on
    # the all-ports behaviour, so it needs a rollout decision rather than a
    # quiet change. Documented in src/README.md and docs/TECHNICAL-REFERENCE.md.
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

    return @{ RuleIdentifier = $RuleId; Status = 'Created'; Details = @{ priority = $priority; port = $Port } }
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
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $rulePath = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
                "/providers/Microsoft.Network/networkSecurityGroups/$($Row.ResourceName)" +
                "/securityRules/$ruleName"

    try {
        Invoke-ArmRest -Method DELETE -Path $rulePath -ApiVersion $script:NsgApi | Out-Null
        return @{ Status = 'Removed'; Details = @{} }
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  NSG rule '$ruleName' not found — already removed."
            return @{ Status = 'NotFound'; Details = @{} }
        } else { throw }
    }
}

#endregion
