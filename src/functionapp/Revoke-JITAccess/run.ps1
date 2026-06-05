# Revoke-JITAccess/run.ps1
#
# HTTP DELETE /api/Revoke-JITAccess/{ruleId}
#
# Removes an active JIT rule before its natural expiry.
# The caller must be the rule's original requester, or hold the JIT.Admin role.
#
# Authorization: Bearer <AAD token with JIT.Requester (or JIT.Admin) role>

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"  -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1" -Force

$tenantId         = $env:AZURE_TENANT_ID
$audience         = $env:JWT_AUDIENCE
$allowedClientIds = ($env:APPROVED_CLIENT_IDS -split ',') |
                        ForEach-Object { $_.Trim() } | Where-Object { $_ }
$tableName        = if ($env:JIT_TABLE_NAME) { $env:JIT_TABLE_NAME } else { 'JITRules' }

function Write-JsonResponse {
    param([HttpStatusCode]$Status, [hashtable]$Body)
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $Status
        Body       = ($Body | ConvertTo-Json -Compress)
        Headers    = @{ 'Content-Type' = 'application/json' }
    })
}

#region ── 1. Validate token ──────────────────────────────────────────────────

$authHeader = $Request.Headers['Authorization']
if (-not $authHeader -or -not $authHeader.ToString().StartsWith('Bearer ')) {
    Write-JsonResponse -Status Unauthorized -Body @{ error = 'Missing or invalid Authorization header.' }
    return
}

$token  = $authHeader.ToString().Substring(7)
$claims = Invoke-JwtValidation -Token $token `
                               -TenantId $tenantId `
                               -Audience $audience `
                               -AllowedClientIds $allowedClientIds

if (-not $claims) {
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token validation failed.' }
    return
}

$callerRoles = @()
if ($claims.roles) { $callerRoles = @($claims.roles) }

if ('JIT.Requester' -notin $callerRoles) {
    Write-JsonResponse -Status Forbidden -Body @{ error = 'JIT.Requester role required.' }
    return
}

$isAdmin     = 'JIT.Admin' -in $callerRoles
$requestedBy = if ($claims.upn)         { $claims.upn }
               elseif ($claims.unique_name) { $claims.unique_name }
               else                         { $claims.sub }

#endregion

#region ── 2. Look up the rule ────────────────────────────────────────────────

$ruleId = $Request.Params.ruleId
if (-not $ruleId -or $ruleId -notmatch '^jit-[0-9a-fA-F]{8}$') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Invalid or missing ruleId in URL path.' }
    return
}

try {
    $cloudTable = Get-JITCloudTable -TableName $tableName
    # RowKey equals the ruleId; partition key is the subscriptionId which we don't know without a scan.
    $row = Get-AzTableRow -Table $cloudTable `
               -CustomFilter "RowKey eq '$ruleId'" |
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

# Ownership check — only the original requester or an admin may revoke.
if ($row.RequestedBy -ne $requestedBy -and -not $isAdmin) {
    Write-JsonResponse -Status Forbidden -Body @{
        error = 'You can only revoke rules you personally requested. ' +
                'The JIT.Admin role is required to revoke rules for other users.'
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
    Remove-AzTableRow -Table $cloudTable `
                      -PartitionKey $row.PartitionKey `
                      -RowKey       $row.RowKey | Out-Null
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
