# Get-JITRules/run.ps1
#
# HTTP GET — Returns active (non-expired) JIT rules from Table Storage.
#
# JIT.Requester  → sees only rules they personally requested.
# JIT.Admin      → sees all active rules across all callers.
#
# Authorization: Bearer <AAD token with JIT.Requester (or JIT.Admin) role>

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1" -Force

$tenantId         = $env:AZURE_TENANT_ID
$audience         = $env:JWT_AUDIENCE
$allowedClientIds = ($env:APPROVED_CLIENT_IDS -split ',') |
                        ForEach-Object { $_.Trim() } | Where-Object { $_ }
$tableName        = if ($env:JIT_TABLE_NAME) { $env:JIT_TABLE_NAME } else { 'JITRules' }

function Write-JsonResponse {
    param([HttpStatusCode]$Status, [object]$Body)
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $Status
        Body       = ($Body | ConvertTo-Json -Depth 5 -Compress)
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

#region ── 2. Query active rules ──────────────────────────────────────────────

try {
    $cloudTable = Get-JITCloudTable -TableName $tableName
    $allRows    = Get-AzTableRow -Table $cloudTable

    $now    = [DateTime]::UtcNow
    $active = $allRows | Where-Object {
        try { [DateTime]::Parse($_.ExpiryUtc) -gt $now } catch { $false }
    }

    # Non-admins see only their own rules.
    if (-not $isAdmin) {
        $active = @($active | Where-Object { $_.RequestedBy -eq $requestedBy })
    }

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

    Write-Host "Get-JITRules: returning $($result.Count) active rule(s) for '$requestedBy' (admin=$isAdmin)."
    Write-JsonResponse -Status OK -Body $result
}
catch {
    Write-Error "Get-JITRules: failed to query rules table — $_"
    Write-JsonResponse -Status InternalServerError -Body @{ error = 'Failed to query active rules.' }
}

#endregion
