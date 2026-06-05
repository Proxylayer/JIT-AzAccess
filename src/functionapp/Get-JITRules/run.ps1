# Get-JITRules/run.ps1
#
# HTTP GET — Returns active (non-expired) JIT rules from Table Storage that the
# caller personally requested.
#
# Authorization: Bearer <AAD ARM token>. Caller must hold the "JIT Requester"
# RBAC role on the function app site resource.

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"  -Force

$tenantId             = $env:AZURE_TENANT_ID
$siteResourceId       = $env:JIT_SITE_RESOURCE_ID
$jitRequesterRoleName = if ($env:JIT_REQUESTER_ROLE_NAME) { $env:JIT_REQUESTER_ROLE_NAME } else { 'JIT Requester' }
$tableName            = if ($env:JIT_TABLE_NAME)          { $env:JIT_TABLE_NAME }          else { 'JITRules' }

function Write-JsonResponse {
    param([HttpStatusCode]$Status, [object]$Body, [hashtable]$ExtraHeaders = @{})
    $headers = @{ 'Content-Type' = 'application/json' }
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $Status
        Body       = (ConvertTo-Json -InputObject $Body -Depth 5 -Compress)
        Headers    = $headers
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

#region ── 2. Query active rules ──────────────────────────────────────────────

try {
    Get-JITTableName -TableName $tableName | Out-Null
    $allRows    = Get-JITTableRows -TableName $tableName

    $now    = [DateTime]::UtcNow
    $active = $allRows | Where-Object {
        try { [DateTime]::Parse($_.ExpiryUtc) -gt $now } catch { $false }
    }

    # Callers see only the rules they personally requested.
    $active = @($active | Where-Object { $_.RequestedBy -eq $requestedBy })

    $result = @($active | ForEach-Object {
        @{
            ruleId         = $_.RowKey
            targetType     = $_.TargetType
            subscriptionId = $_.SubscriptionId
            resourceGroup  = $_.ResourceRg
            resourceName   = $_.ResourceName
            ruleIdentifier = $_.RuleIdentifier
            callerIp       = $_.CallerIp
            port           = if ($_.Port -and $_.Port -ne '*') { $_.Port } else { $null }
            requestedBy    = $_.RequestedBy
            expiresUtc     = $_.ExpiryUtc
            justification  = $_.Justification
        }
    })

    # Report the caller's current public IP (the exact IP a grant would use) so
    # the client can detect resources whose firewall already allows it and skip
    # a redundant request. Header-only keeps the JSON body an array.
    $callerIp = Get-CallerIp -Request $Request

    Write-Host "Get-JITRules: returning $($result.Count) active rule(s) for '$requestedBy' (callerIp=$callerIp)."
    Write-JsonResponse -Status OK -Body $result -ExtraHeaders @{ 'X-JIT-Caller-IP' = $callerIp }
}
catch {
    Write-Error "Get-JITRules: failed to query rules table — $_"
    Write-JsonResponse -Status InternalServerError -Body @{ error = 'Failed to query active rules.' }
}

#endregion
