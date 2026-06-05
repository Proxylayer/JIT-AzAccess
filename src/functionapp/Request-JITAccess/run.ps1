# Request-jitazaccess/run.ps1
#
# HTTP POST — Grants a caller's IP address temporary access on a supported target resource.
#
# Supported targetType values:  nsg | sqlServer | storageAccount | keyVault
#
# Minimum request body:
# {
#   "targetType":    "nsg",
#   "subscriptionId": "<guid>",
#   "resourceGroup":  "<rg-name>",
#   "resourceName":   "<resource-name>",
#   "durationHours":  4,          // must be in ALLOWED_DURATIONS_HOURS
#   "port":           "443"       // NSG only — omit to allow any port
# }
#
# Authorization: Bearer <AAD token>
#   Token must match AZURE_TENANT_ID, JWT_AUDIENCE, and APPROVED_CLIENT_IDS.

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"  -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1" -Force

#region ── Configuration ──────────────────────────────────────────────────────

$tenantId        = $env:AZURE_TENANT_ID
$audience        = $env:JWT_AUDIENCE
$allowedClientIds = ($env:APPROVED_CLIENT_IDS -split ',') |
                        ForEach-Object { $_.Trim() } |
                        Where-Object   { $_ }
$allowedDurations = ($env:ALLOWED_DURATIONS_HOURS -split ',') |
                        ForEach-Object { [int]$_.Trim() }
$tableName           = if ($env:JIT_TABLE_NAME)            { $env:JIT_TABLE_NAME }            else { 'JITRules' }
$priorityMin         = if ($env:JIT_NSG_PRIORITY_MIN)      { [int]$env:JIT_NSG_PRIORITY_MIN }  else { 1000 }
$priorityMax         = if ($env:JIT_NSG_PRIORITY_MAX)      { [int]$env:JIT_NSG_PRIORITY_MAX }  else { 3900 }
$maxRulesPerCaller   = if ($env:JIT_MAX_RULES_PER_CALLER)   { [int]$env:JIT_MAX_RULES_PER_CALLER }   else { 5 }
$maxRulesPerResource = if ($env:JIT_MAX_RULES_PER_RESOURCE) { [int]$env:JIT_MAX_RULES_PER_RESOURCE } else { 20 }

#endregion

#region ── Helpers ────────────────────────────────────────────────────────────

function Write-JsonResponse {
    param([HttpStatusCode]$Status, [hashtable]$Body)
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $Status
        Body       = ($Body | ConvertTo-Json -Compress)
        Headers    = @{ 'Content-Type' = 'application/json' }
    })
}

#endregion

#region ── 1. Validate bearer token ───────────────────────────────────────────

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
    Write-JITAuditEvent -EventType JITDenied -DenyReason 'TokenValidationFailed' -CallerIp 'unknown'
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token validation failed. Check tenant, audience, and client ID.' }
    return
}

# Extract a human-readable identity for audit logging
$requestedBy = if ($claims.upn)         { $claims.upn }
               elseif ($claims.unique_name) { $claims.unique_name }
               else                         { $claims.sub }

Write-Host "JIT request from: $requestedBy (appid: $($claims.appid ?? $claims.azp))"

# ── Require JIT.Requester app role (must be activated via PIM) ───────────────
$callerRoles = @()
if ($claims.roles) { $callerRoles = @($claims.roles) }

if ('JIT.Requester' -notin $callerRoles) {
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp 'unknown' `
        -DenyReason 'MissingRole' -Extra @{ requiredRole = 'JIT.Requester' }
    Write-JsonResponse -Status Forbidden -Body @{
        error        = 'Caller does not have the JIT.Requester role. ' +
                       'Activate it via PIM before requesting access.'
        requiredRole = 'JIT.Requester'
    }
    return
}

#endregion

#region ── 2. Parse and validate request body ─────────────────────────────────

try {
    $body = $Request.Body | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Request body is not valid JSON.' }
    return
}

$targetType     = $body.targetType
$subscriptionId = $body.subscriptionId
$resourceGroup  = $body.resourceGroup
$resourceName   = $body.resourceName
$durationHours  = [int]$body.durationHours
$port           = $body.port          # NSG only — null means any port
$justification  = $body.justification # Optional free-text reason; required when target.requiresJustification = true

$supportedTypes = @('nsg', 'sqlServer', 'storageAccount', 'keyVault')

if ($targetType -notin $supportedTypes) {
    Write-JsonResponse -Status BadRequest -Body @{
        error          = 'Unsupported targetType.'
        supportedTypes = $supportedTypes
    }
    return
}

if (-not $subscriptionId -or -not $resourceGroup -or -not $resourceName -or -not $durationHours) {
    Write-JsonResponse -Status BadRequest -Body @{
        error    = 'Missing required field(s).'
        required = @('targetType', 'subscriptionId', 'resourceGroup', 'resourceName', 'durationHours')
    }
    return
}

if ($durationHours -notin $allowedDurations) {
    Write-JsonResponse -Status BadRequest -Body @{
        error         = 'durationHours must be one of the allowed values.'
        allowedValues = $allowedDurations
    }
    return
}

if ($subscriptionId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'subscriptionId must be a valid GUID.' }
    return
}

# Validate resource names against ARM constraints to prevent path injection.
# Rules: 1-90 chars, alphanumeric + hyphens + underscores + dots + parens (conservative union of all types).
if ($resourceGroup -notmatch '^[a-zA-Z0-9._\-()]{1,90}$') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'resourceGroup contains invalid characters.' }
    return
}
if ($resourceName -notmatch '^[a-zA-Z0-9._\-]{1,90}$') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'resourceName contains invalid characters.' }
    return
}
    Write-JsonResponse -Status BadRequest -Body @{ error = "port must be a number or range (e.g. '443' or '8080-8090')." }
    return
}

#endregion

#region ── 3. Determine caller IP ─────────────────────────────────────────────

# Azure injects the real client IP into X-Forwarded-For.
# The header may contain a comma-separated chain; the leftmost is the originating IP.
$xForwardedFor = $Request.Headers['X-Forwarded-For']
if ($xForwardedFor) {
    $callerIp = ($xForwardedFor.ToString() -split ',')[0].Trim() -replace ':\d+$', ''
}
else {
    $callerIp = $Request.HttpContext.Connection.RemoteIpAddress.ToString()
}

if (-not $callerIp -or $callerIp -eq '::1' -or $callerIp -eq '127.0.0.1') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Could not determine caller IP address.' }
    return
}

Write-Host "Caller IP: $callerIp"

#endregion

#region ── 3b. Abuse prevention ─────────────────────────────────────────────────────────────

try {
    $cloudTableCheck = Get-JITCloudTable -TableName $tableName
    $now             = [DateTime]::UtcNow.ToString('o')

    # Count active (non-expired) rules for this caller across all resources
    $callerActive = (Get-AzTableRow -Table $cloudTableCheck `
        -CustomFilter "RequestedBy eq '$requestedBy'") |
        Where-Object { [DateTime]::Parse($_.ExpiryUtc) -gt [DateTime]::UtcNow }

    if ($callerActive.Count -ge $maxRulesPerCaller) {
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -DenyReason 'MaxRulesPerCallerExceeded' `
            -Extra @{ activeCount = $callerActive.Count; limit = $maxRulesPerCaller }
        Write-JsonResponse -Status TooManyRequests -Body @{
            error       = "You have $($callerActive.Count) active JIT rule(s). Maximum is $maxRulesPerCaller."
            activeRules = $callerActive.Count
        }
        return
    }

    # Count active rules on the target resource
    $resourceActive = (Get-AzTableRow -Table $cloudTableCheck `
        -CustomFilter "ResourceName eq '$resourceName' and ResourceRg eq '$resourceGroup'") |
        Where-Object { [DateTime]::Parse($_.ExpiryUtc) -gt [DateTime]::UtcNow }

    if ($resourceActive.Count -ge $maxRulesPerResource) {
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -DenyReason 'MaxRulesPerResourceExceeded' `
            -Extra @{ activeCount = $resourceActive.Count; limit = $maxRulesPerResource }
        Write-JsonResponse -Status TooManyRequests -Body @{
            error       = "Resource '$resourceName' has $($resourceActive.Count) active JIT rule(s). Maximum is $maxRulesPerResource."
            activeRules = $resourceActive.Count
        }
        return
    }

    # Cooldown: block re-requesting the same resource while a rule is already active for this caller.
    $cooldownRow = ($callerActive | Where-Object {
        $_.ResourceName -eq $resourceName -and $_.SubscriptionId -eq $subscriptionId
    } | Select-Object -First 1)

    if ($cooldownRow) {
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -DenyReason 'CooldownActive' `
            -Extra @{ existingRuleId = $cooldownRow.RowKey; expiresUtc = $cooldownRow.ExpiryUtc }
        Write-JsonResponse -Status Conflict -Body @{
            error          = 'An active JIT rule already exists for this resource. Wait for it to expire or revoke it first.'
            existingRuleId = $cooldownRow.RowKey
            expiresUtc     = $cooldownRow.ExpiryUtc
        }
        return
    }
}
catch {
    Write-Warning "Abuse check failed (non-fatal, proceeding): $_"
}

$ruleId  = "jit-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$portVal = if ($port) { $port } else { '*' }
$expiry  = [DateTime]::UtcNow.AddHours($durationHours)

try {
    $addParams = @{
        SubscriptionId = $subscriptionId
        ResourceGroup  = $resourceGroup
        ResourceName   = $resourceName
        CallerIp       = $callerIp
        RuleId         = $ruleId
    }

    # NSG priority assignment is a read-modify-write; hold a distributed lock
    # to prevent two simultaneous requests selecting the same priority number.
    if ($targetType -eq 'nsg') {
        $lockName = "nsg-$($subscriptionId.Substring(0,8))-$($resourceGroup)-$($resourceName)"
        Invoke-WithBlobLock -LockName $lockName -Action {
            $result = Add-JITNsgRule @addParams -Port $portVal -PriorityMin $priorityMin -PriorityMax $priorityMax
        }
    }
    else {
        $result = switch ($targetType) {
            'sqlServer'      { Add-JITSqlFirewallRule     @addParams }
            'storageAccount' { Add-JITStorageNetworkRule  @addParams }
            'keyVault'       { Add-JITKeyVaultNetworkRule @addParams }
        }
    }

    Write-JITAuditEvent -EventType JITGranted -Caller $requestedBy -CallerIp $callerIp `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -RuleId $ruleId `
        -Extra @{ expiresUtc = $expiry.ToString('o'); port = $portVal; durationHours = $durationHours; justification = $justification }
}
catch {
    Write-Error "JIT target modification failed: $_"
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -RuleId $ruleId -DenyReason 'TargetModificationFailed'
    Write-JsonResponse -Status InternalServerError -Body @{
        error  = "Failed to modify $targetType. Verify the function app has the JIT-AzAccess Manager role on the target subscription."
        detail = $_.ToString()
    }
    return
}

#endregion

#region ── 5. Record expiry in Table Storage ──────────────────────────────────

try {
    $cloudTable = Get-JITCloudTable -TableName $tableName

    Add-AzTableRow `
        -Table        $cloudTable `
        -PartitionKey $subscriptionId `
        -RowKey       $ruleId `
        -Property     @{
            TargetType     = $targetType
            ResourceName   = $resourceName
            ResourceRg     = $resourceGroup
            SubscriptionId = $subscriptionId
            RuleIdentifier = $result.RuleIdentifier
            CallerIp       = $callerIp
            Port           = $portVal
            RequestedBy    = $requestedBy
            ExpiryUtc      = $expiry.ToString('o')
            Justification  = if ($justification) { $justification } else { '' }
        } | Out-Null
}
catch {
    Write-Warning "Table write failed. Rule '$($result.RuleIdentifier)' was added but expiry record was not saved: $_"
}

#endregion

Write-JsonResponse -Status OK -Body @{
    ruleId         = $ruleId
    ruleIdentifier = $result.RuleIdentifier
    targetType     = $targetType
    resource       = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/$resourceName"
    callerIp       = $callerIp
    port           = if ($targetType -eq 'nsg') { $portVal } else { $null }
    expiresUtc     = $expiry.ToString('o')
    requestedBy    = $requestedBy
}
