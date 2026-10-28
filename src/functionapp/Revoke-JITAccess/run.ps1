# Revoke-JITAccess/run.ps1
#
# HTTP DELETE /api/Revoke-JITAccess/{ruleId}
#
# Removes an active JIT rule before its natural expiry.
# The caller can only revoke rules they personally requested.
#
# Authorization: Bearer <AAD ARM token>; caller must hold the "JIT-Requester"
# RBAC role within the subscription the rule targets.

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

$tenantId  = Get-JitTenantId
$tableName = if ($env:JIT_TABLE_NAME) { $env:JIT_TABLE_NAME } else { 'JITRules' }

# Correlation id for this request. Internal failure detail is logged against
# it and only the id goes back to the caller.
$correlationId = [guid]::NewGuid().ToString('N').Substring(0, 12)

function Write-JsonResponse {
    param([HttpStatusCode]$Status, [hashtable]$Body)
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $Status
        Body       = (ConvertTo-Json -InputObject $Body -Compress)
        Headers    = @{ 'Content-Type' = 'application/json' }
    })
}

#region ── 1. Validate token + authz ──────────────────────────────────────────

$authHeader = $Request.Headers['Authorization']
if (-not $authHeader -or -not $authHeader.ToString().StartsWith('Bearer ')) {
    Write-JsonResponse -Status Unauthorized -Body @{ error = 'Missing or invalid Authorization header.' }
    return
}

$token  = $authHeader.ToString().Substring(7)
$claims = Invoke-JwtValidation -Token $token -TenantId $tenantId

if (-not $claims) {
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token validation failed.' }
    return
}

$callerObjectId = $claims.oid
if (-not $callerObjectId) {
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token has no oid claim.' }
    return
}

$requestedBy = if ($claims.upn)         { $claims.upn }
               elseif ($claims.unique_name) { $claims.unique_name }
               else                         { $claims.sub }

# NB: the JIT-Requester RBAC role check is deferred until after the rule is
# looked up (region 2) — it is evaluated against the subscription the rule
# targets, not the function app's own host subscription.

#endregion

#region ── 2. Look up the rule ────────────────────────────────────────────────

# Accept both the legacy id shape (jit-<8hex>) and the username-tagged shape
# (jit-<username>-<8hex>). The charset stays restricted to lowercase
# alphanumerics + hyphens, so $ruleId is still safe to interpolate into the
# OData filter below (no quotes possible).
$ruleId = $Request.Params.ruleId
if (-not $ruleId -or $ruleId -notmatch '^jit-([a-z0-9]{1,20}-)?[0-9a-fA-F]{8}$') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Invalid or missing ruleId in URL path.' }
    return
}

try {
    Get-JITTableName -TableName $tableName | Out-Null
    # RowKey equals the ruleId; partition key is the subscriptionId which we don't know without a scan.
    $row = Get-JITTableRows -TableName $tableName -Filter "RowKey eq '$ruleId'" |
               Select-Object -First 1
}
catch {
    Write-Error "Revoke-JITAccess: rules table query failed [correlationId=$correlationId]: $_"
    Write-JsonResponse -Status InternalServerError -Body @{
        error         = 'Failed to query the rules table.'
        correlationId = $correlationId
    }
    return
}

if (-not $row) {
    Write-JsonResponse -Status NotFound -Body @{
        error = "Rule '$ruleId' not found. It may have already expired or been revoked."
    }
    return
}

# A reservation, not a grant: Request-JITAccess has claimed this slot and is
# mid-flight against ARM. Removing it now would race that request - we could
# delete the tracking row while the rule is still being created, which is
# exactly the untracked-rule case the reservation exists to prevent. The row
# carries a short expiry, so refusing here cannot strand anything.
if ($row.State -eq 'Pending') {
    Write-JsonResponse -Status Conflict -Body @{
        error  = "Rule '$ruleId' is still being granted. Retry in a moment."
        status = 'InProgress'
    }
    return
}

# Ownership check — callers can only revoke rules they personally requested.
if ($row.RequestedBy -ne $requestedBy) {
    Write-JsonResponse -Status Forbidden -Body @{
        error = 'You can only revoke rules you personally requested.'
    }
    return
}

# Authorization — caller must hold the 'JIT-Requester' RBAC role within the
# subscription the rule targets (the same subscription they held it in to grant).
if (-not (Test-CallerHasJitRequesterRole -CallerObjectId $callerObjectId -SubscriptionId $row.SubscriptionId)) {
    Write-JsonResponse -Status Forbidden -Body @{
        error        = "Caller does not hold the 'JIT-Requester' RBAC role in subscription '$($row.SubscriptionId)'."
        requiredRole = 'JIT-Requester'
    }
    return
}

#endregion

#region ── 3. Remove the firewall / network rule ──────────────────────────────

try {
    $removeResult = switch ($row.TargetType) {
        'nsg'                      { Remove-JITNsgRule                  -Row $row }
        'sqlServer'                { Remove-JITSqlFirewallRule          -Row $row }
        'postgresqlFlexibleServer' { Remove-JITPostgresFirewallRule     -Row $row }
        'storageAccount'           { Remove-JITStorageNetworkRule       -Row $row }
        'keyVault'                 { Remove-JITKeyVaultNetworkRule      -Row $row }
        'mysqlFlexibleServer'      { Remove-JITMysqlFlexibleServerRule  -Row $row }
        'redis'                    { Remove-JITRedisRule                -Row $row }
        'synapse'                  { Remove-JITSynapseRule              -Row $row }
        'cosmosDb'                 { Remove-JITCosmosDbRule             -Row $row }
        'containerRegistry'        { Remove-JITContainerRegistryRule    -Row $row }
        'aiSearch'                 { Remove-JITAiSearchRule             -Row $row }
        'cognitiveServices'        { Remove-JITCognitiveServicesRule    -Row $row }
        'kusto'                    { Remove-JITKustoRule                -Row $row }
        'iotHub'                   { Remove-JITIotHubRule               -Row $row }
        'signalR'                  { Remove-JITSignalRRule              -Row $row }
        'eventHub'                 { Remove-JITEventHubRule             -Row $row }
        'serviceBus'               { Remove-JITServiceBusRule           -Row $row }
        'appService'               { Remove-JITAppServiceRule           -Row $row }
        'aks'                      { Remove-JITAksRule                  -Row $row }
        default {
            Write-Warning "Unknown targetType '$($row.TargetType)' — skipping resource removal."
        }
    }
}
catch {
    # Log the detail; return only the correlation id. Exception text can carry
    # ARM URLs, resource ids and raw resource-provider error bodies.
    Write-Error "Revoke-JITAccess: failed to remove rule '$ruleId' from resource [correlationId=$correlationId]: $_"
    Write-JsonResponse -Status InternalServerError -Body @{
        error         = 'Failed to remove the rule from the target resource. The table record has NOT been deleted.'
        correlationId = $correlationId
    }
    return
}

#endregion

#region ── 4. Branch on the remove Status ─────────────────────────────────────

# Remove handlers return a Status: Removed | NotFound | Refused. A handler that
# returns no Status (unknown/legacy targetType) is treated as Removed so the
# stale record is still cleaned up.
$removeStatus = if ($removeResult -and $removeResult.Status) { $removeResult.Status } else { 'Removed' }
# Per-resource outcome detail from the handler (App Service reports the site
# plus every deployment slot, and flags a slot enumeration failure). Carried
# onto the audit rows below so a partial revoke is auditable rather than
# visible only as a warning in the function logs.
$removeDetails = if ($removeResult) { $removeResult.Details } else { $null }

if ($removeStatus -eq 'Refused') {
    # AKS only: removing the caller IP would leave authorizedIPRanges empty and
    # open the API server, so the handler refused. Keep the JITRules row (the IP
    # stays tracked/visible) and do NOT return success.
    Write-Warning "Revoke refused for '$ruleId': removing it would open the $($row.TargetType) API server. Table record retained."
    Write-JITAuditEvent -EventType JITRemoveFailed `
        -Caller $requestedBy -TargetType $row.TargetType `
        -ResourceName $row.ResourceName -ResourceGroup $row.ResourceRg `
        -SubscriptionId $row.SubscriptionId -RuleId $ruleId -CallerIp $row.CallerIp `
        -Extra @{ reason = 'refused-would-open-cluster' }
    try {
        Add-JITAuditRow -Action 'RemoveFailed' `
            -SubscriptionId $row.SubscriptionId -TargetType $row.TargetType `
            -ResourceName $row.ResourceName -ResourceRg $row.ResourceRg `
            -RuleIdentifier $row.RuleIdentifier -CallerIp $row.CallerIp `
            -Port $row.Port -RequestedBy $row.RequestedBy `
            -ExpiryUtc $row.ExpiryUtc -Justification $row.Justification `
            -Extra @{ reason = 'refused-would-open-cluster' } `
            -Details $removeDetails
    }
    catch {
        Write-Warning "JITRulesAudit write failed for refused revoke '$ruleId': $_"
    }
    Write-JsonResponse -Status Conflict -Body @{
        status = 'Refused'
        error  = "Cannot revoke '$ruleId': removing the last authorized IP range would open the $($row.TargetType) API server to the internet. The rule has been left in place."
    }
    return
}

# Removed OR NotFound — the rule is gone from the resource (either we removed it,
# or the user had already deleted it manually). Clean up the stale tracking row.
$notFound = ($removeStatus -eq 'NotFound')

Write-JITAuditEvent -EventType JITRevoked `
    -Caller        $requestedBy `
    -TargetType    $row.TargetType `
    -ResourceName  $row.ResourceName `
    -ResourceGroup $row.ResourceRg `
    -SubscriptionId $row.SubscriptionId `
    -RuleId        $ruleId `
    -CallerIp      $row.CallerIp `
    -Extra         @{ notFound = $notFound }

# Append a lifecycle event to the audit history table before the active-rule
# record is deleted. Best-effort — a JITRulesAudit write failure must NEVER
# fail the revoke.
try {
    $revokeExtra = if ($notFound) { @{ notFound = $true } } else { @{} }
    Add-JITAuditRow -Action 'Revoke' `
        -SubscriptionId $row.SubscriptionId -TargetType $row.TargetType `
        -ResourceName $row.ResourceName -ResourceRg $row.ResourceRg `
        -RuleIdentifier $row.RuleIdentifier -CallerIp $row.CallerIp `
        -Port $row.Port -RequestedBy $row.RequestedBy `
        -ExpiryUtc $row.ExpiryUtc -Justification $row.Justification `
        -Extra $revokeExtra `
        -Details $removeDetails
}
catch {
    Write-Warning "JITRulesAudit write failed for revoke '$ruleId' (revoke itself succeeded): $_"
}

try {
    Remove-JITTableRow -TableName $tableName `
                       -PartitionKey $row.PartitionKey `
                       -RowKey       $row.RowKey
}
catch {
    Write-Warning "Rule was removed from the resource but the table record deletion failed for '$ruleId': $_"
}

Write-Host "JIT rule revoked: $ruleId ($($row.TargetType) $($row.ResourceName)) by $requestedBy"

Write-JsonResponse -Status OK -Body @{
    status       = $removeStatus
    ruleId       = $ruleId
    revokedBy    = $requestedBy
    targetType   = $row.TargetType
    resourceName = $row.ResourceName
}

#endregion
