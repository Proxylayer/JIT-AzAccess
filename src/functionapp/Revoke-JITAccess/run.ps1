# Revoke-JITAccess/run.ps1
#
# HTTP DELETE /api/Revoke-JITAccess/{ruleId}
#
# Removes an active JIT rule before its natural expiry.
# The caller can only revoke rules they personally requested.
#
# Authorization: Bearer <AAD ARM token>; caller must hold the "JIT Requester"
# RBAC role on the function app site resource.

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

$tenantId             = $env:AZURE_TENANT_ID
$siteResourceId       = $env:JIT_SITE_RESOURCE_ID
$jitRequesterRoleName = if ($env:JIT_REQUESTER_ROLE_NAME) { $env:JIT_REQUESTER_ROLE_NAME } else { 'JIT Requester' }
$tableName            = if ($env:JIT_TABLE_NAME)          { $env:JIT_TABLE_NAME }          else { 'JITRules' }

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

if (-not $siteResourceId) {
    Write-JsonResponse -Status InternalServerError -Body @{ error = 'Function app is misconfigured: JIT_SITE_RESOURCE_ID is not set.' }
    return
}

$callerObjectId = $claims.oid
if (-not $callerObjectId) {
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token has no oid claim.' }
    return
}

if (-not (Test-CallerHasJitRequesterRole -CallerObjectId $callerObjectId `
            -SiteResourceId $siteResourceId -RoleDefinitionName $jitRequesterRoleName)) {
    Write-JsonResponse -Status Forbidden -Body @{
        error        = "Caller does not hold the '$jitRequesterRoleName' RBAC role on this function app."
        requiredRole = $jitRequesterRoleName
    }
    return
}

$requestedBy = if ($claims.upn)         { $claims.upn }
               elseif ($claims.unique_name) { $claims.unique_name }
               else                         { $claims.sub }

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
    Write-JsonResponse -Status InternalServerError -Body @{ error = "Failed to query table: $_" }
    return
}

if (-not $row) {
    Write-JsonResponse -Status NotFound -Body @{
        error = "Rule '$ruleId' not found. It may have already expired or been revoked."
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

#endregion

#region ── 3. Remove the firewall / network rule ──────────────────────────────

try {
    switch ($row.TargetType) {
        'nsg'            { Remove-JITNsgRule            -Row $row }
        'sqlServer'      { Remove-JITSqlFirewallRule     -Row $row }
        'storageAccount' { Remove-JITStorageNetworkRule  -Row $row }
        'keyVault'       { Remove-JITKeyVaultNetworkRule -Row $row }
        default {
            Write-Warning "Unknown targetType '$($row.TargetType)' — skipping resource removal."
        }
    }

    Write-JITAuditEvent -EventType JITRevoked `
        -Caller        $requestedBy `
        -TargetType    $row.TargetType `
        -ResourceName  $row.ResourceName `
        -ResourceGroup $row.ResourceRg `
        -SubscriptionId $row.SubscriptionId `
        -RuleId        $ruleId `
        -CallerIp      $row.CallerIp
}
catch {
    Write-Error "Revoke-JITAccess: failed to remove rule '$ruleId' from resource — $_"
    Write-JsonResponse -Status InternalServerError -Body @{
        error  = 'Failed to remove the rule from the target resource. The table record has NOT been deleted.'
        detail = $_.ToString()
    }
    return
}

#endregion

#region ── 4. Delete table record ────────────────────────────────────────────

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
    ruleId     = $ruleId
    revokedBy  = $requestedBy
    targetType = $row.TargetType
    resourceName = $row.ResourceName
}

#endregion
