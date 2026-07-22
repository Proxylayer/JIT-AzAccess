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

#region ── Azure Database for PostgreSQL Flexible Server ───────────────────────
# https://learn.microsoft.com/rest/api/postgresql/firewall-rules
#
# Two differences vs Azure SQL:
#   1. Firewall-rule PUT/DELETE are LONG-RUNNING — they reply 202 Accepted with
#      an Azure-AsyncOperation header we must poll to completion.
#   2. A private-access / VNet-integrated flexible server has NO firewall rules,
#      so a firewall-rule grant can never apply. We pre-flight the server's
#      networking and reject those with a distinguishable error the dispatcher
#      surfaces as a clean client denial (not a generic 500).

$script:PostgresApi = '2024-08-01'

# Sentinel prefix on the pre-flight rejection message so Request-JITAccess/run.ps1
# can distinguish a private-server denial from a genuine failure and return a
# clean 4xx + JITDenied audit event instead of a 500. Keep this literal in sync
# with the match in Request-JITAccess/run.ps1.
$script:PostgresPrivateRejectPrefix = 'PRIVATE_SERVER_REJECTED:'

# LRO poll bounds. Firewall-rule ops normally complete in a few seconds; the cap
# protects the (synchronous) HTTP request and the timer worker from hanging.
$script:PostgresLroTimeoutSeconds     = 180
$script:PostgresLroDefaultPollSeconds = 5

function script:Get-HeaderValue {
    # Case-insensitive lookup against the normalized header hashtable returned by
    # Invoke-ArmRestRaw (server casing is preserved, so match ordinal-ignorecase).
    param([hashtable]$Headers, [string]$Name)
    if (-not $Headers) { return $null }
    foreach ($k in $Headers.Keys) {
        if ([string]::Equals($k, $Name, [StringComparison]::OrdinalIgnoreCase)) { return $Headers[$k] }
    }
    return $null
}

function Wait-JITArmAsyncOperation {
    <#
    .SYNOPSIS
        Polls an Azure async (long-running) operation to completion.

    .DESCRIPTION
        Given the response headers from a 202 Accepted reply, GETs the
        Azure-AsyncOperation URL (falling back to Location) with the MI ARM
        token, honoring each response's Retry-After header between polls, until
        the operation JSON `status` is:
          • Succeeded            -> returns
          • Failed / Canceled    -> throws with the operation's error detail
          • (still running)       -> keeps polling
        or the overall timeout elapses (throws a timeout error).

    .PARAMETER ResponseHeaders
        The normalized header hashtable from the initiating 202 response
        (as returned by Invoke-ArmRestRaw).
    #>
    param(
        [Parameter(Mandatory)][hashtable]$ResponseHeaders,
        [int]$TimeoutSeconds = $script:PostgresLroTimeoutSeconds
    )

    $asyncUrl = Get-HeaderValue $ResponseHeaders 'Azure-AsyncOperation'
    if (-not $asyncUrl) { $asyncUrl = Get-HeaderValue $ResponseHeaders 'Location' }
    if (-not $asyncUrl) {
        throw "Async operation returned 202 but no Azure-AsyncOperation or Location header to poll."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $headers  = $ResponseHeaders
    $poll     = 0

    while ([DateTime]::UtcNow -lt $deadline) {
        # Honor Retry-After from the most recent response before the next poll;
        # clamp to a sane range so a bad header can't stall or busy-loop us.
        $retryAfter = Get-HeaderValue $headers 'Retry-After'
        $waitSec    = $script:PostgresLroDefaultPollSeconds
        if ($retryAfter -and ($retryAfter -match '^\d+$')) { $waitSec = [int]$retryAfter }
        if ($waitSec -lt 1)  { $waitSec = 1 }
        if ($waitSec -gt 30) { $waitSec = 30 }

        Start-Sleep -Seconds $waitSec
        $poll++

        $raw     = Invoke-ArmRestRaw -Path $asyncUrl -Method GET
        $headers = $raw.Headers
        $status  = $null
        if ($raw.Content) {
            try { $status = ($raw.Content | ConvertFrom-Json -ErrorAction Stop).status } catch { $status = $null }
        }

        Write-Host "  PostgreSQL LRO poll #$poll -> status=$status"

        switch ($status) {
            'Succeeded' { return }
            'Failed'    { throw "Async operation failed: $($raw.Content)" }
            'Canceled'  { throw "Async operation was canceled: $($raw.Content)" }
            'Cancelled' { throw "Async operation was canceled: $($raw.Content)" }
            default     { }   # InProgress / Running / Accepted / null — keep polling
        }
    }

    throw "Async operation did not complete within $TimeoutSeconds seconds (timeout)."
}

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
        Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers
    }

    return @{ RuleIdentifier = $RuleId; Details = @{} }
}

function Remove-JITPostgresFirewallRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the RowKey fallback rationale.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  PostgreSQL row has neither RuleIdentifier nor RowKey — cannot identify rule to delete."
        return
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
            Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers
        }
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  PostgreSQL firewall rule '$ruleName' not found — already removed."
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
    'Add-JITPostgresFirewallRule'; 'Remove-JITPostgresFirewallRule'
    'Add-JITStorageNetworkRule';'Remove-JITStorageNetworkRule'
    'Add-JITKeyVaultNetworkRule';'Remove-JITKeyVaultNetworkRule'
)
