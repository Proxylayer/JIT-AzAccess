# Synapse.ps1
#region ── Azure Synapse Analytics Workspace ───────────────────────────────────
# https://learn.microsoft.com/rest/api/synapse/firewall-rules
#
# Child-firewall-rule model like SQL/PostgreSQL: PUT/DELETE a
# firewallRules/{ruleName} child with {properties:{startIpAddress,endIpAddress}}.
# Workspace firewall-rule create/delete are long-running (202 + Azure-Async-
# Operation); we poll to completion (and still accept a synchronous response).

# ── ARM API version ───────────────────────────────────────────────────────────
$script:SynapseApi = '2021-06-01'   # Microsoft.Synapse/workspaces

# ── LRO poll bounds ───────────────────────────────────────────────────────────
$script:SynapseLroTimeoutSeconds     = 180
$script:SynapseLroDefaultPollSeconds = 5

function Add-JITSynapseRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $workspacePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                     "/providers/Microsoft.Synapse/workspaces/$ResourceName"

    # Idempotent add: skip if an existing rule already allows this IP.
    $existing = Invoke-ArmRest -Path "$workspacePath/firewallRules" -ApiVersion $script:SynapseApi
    if (Test-JITFirewallRuleCoversIp -Rules $existing.value -CallerIp $CallerIp) {
        return @{ RuleIdentifier = $RuleId; Status = 'AlreadyPresent'; Details = @{ note = 'caller IP already allowed by an existing firewall rule' } }
    }

    $resp = Invoke-ArmRestRaw -Method PUT -Path "$workspacePath/firewallRules/$RuleId" -ApiVersion $script:SynapseApi -Body @{
        properties = @{
            startIpAddress = $CallerIp
            endIpAddress   = $CallerIp
        }
    }

    if ($resp.StatusCode -eq 202) {
        Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
            -TimeoutSeconds     $script:SynapseLroTimeoutSeconds `
            -DefaultPollSeconds $script:SynapseLroDefaultPollSeconds
    }

    return @{ RuleIdentifier = $RuleId; Status = 'Created'; Details = @{} }
}

function Remove-JITSynapseRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the RowKey fallback rationale.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  Synapse row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Synapse/workspaces/$($Row.ResourceName)" +
            "/firewallRules/$ruleName"

    try {
        $resp = Invoke-ArmRestRaw -Method DELETE -Path $path -ApiVersion $script:SynapseApi
        if ($resp.StatusCode -eq 202) {
            Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
                -TimeoutSeconds     $script:SynapseLroTimeoutSeconds `
                -DefaultPollSeconds $script:SynapseLroDefaultPollSeconds
        }
        return @{ Status = 'Removed'; Details = @{} }
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  Synapse firewall rule '$ruleName' not found — already removed."
            return @{ Status = 'NotFound'; Details = @{} }
        } else { throw }
    }
}

#endregion
