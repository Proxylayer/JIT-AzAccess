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
# Authorization: Bearer <AAD ARM token>
#   Token must match AZURE_TENANT_ID and carry an ARM audience.
#   Caller's AAD objectId must hold the "JIT Requester" custom RBAC role
#   at or above the function app site resource (controlled by
#   JIT_SITE_RESOURCE_ID / JIT_REQUESTER_ROLE_NAME env vars).

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

#region ── Configuration ──────────────────────────────────────────────────────

$tenantId            = $env:AZURE_TENANT_ID
$siteResourceId      = $env:JIT_SITE_RESOURCE_ID
$jitRequesterRoleName = if ($env:JIT_REQUESTER_ROLE_NAME) { $env:JIT_REQUESTER_ROLE_NAME } else { 'JIT Requester' }
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
        Body       = (ConvertTo-Json -InputObject $Body -Compress)
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
$claims = Invoke-JwtValidation -Token $token -TenantId $tenantId

if (-not $claims) {
    Write-JITAuditEvent -EventType JITDenied -DenyReason 'TokenValidationFailed' -CallerIp 'unknown'
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token validation failed. Check tenant and audience.' }
    return
}

# Extract a human-readable identity for audit logging
$requestedBy = if ($claims.upn)         { $claims.upn }
               elseif ($claims.unique_name) { $claims.unique_name }
               else                         { $claims.sub }

# Sanitize for OData filter injection — UPNs can contain apostrophes (e.g. o'brien@contoso.com)
# Azure Table Storage OData escapes single quotes by doubling them.
$oDataRequestedBy = $requestedBy -replace "'", "''"

Write-Host "JIT request from: $requestedBy (oid: $($claims.oid))"

# ── Require the JIT Requester custom RBAC role on the function app site ─────
if (-not $siteResourceId) {
    Write-JsonResponse -Status InternalServerError -Body @{
        error = 'Function app is misconfigured: JIT_SITE_RESOURCE_ID is not set.'
    }
    return
}

$callerObjectId = $claims.oid
if (-not $callerObjectId) {
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp 'unknown' `
        -DenyReason 'MissingObjectIdClaim'
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token has no oid claim; cannot evaluate authorization.' }
    return
}

if (-not (Test-CallerHasJitRequesterRole -CallerObjectId $callerObjectId `
            -SiteResourceId $siteResourceId -RoleDefinitionName $jitRequesterRoleName)) {
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp 'unknown' `
        -DenyReason 'MissingJitRequesterRole' -Extra @{ requiredRole = $jitRequesterRoleName }
    Write-JsonResponse -Status Forbidden -Body @{
        error        = "Caller does not hold the '$jitRequesterRoleName' RBAC role on this function app."
        requiredRole = $jitRequesterRoleName
    }
    return
}

#endregion

#region ── 2. Parse and validate request body ─────────────────────────────────

# The Functions PowerShell worker auto-deserializes an application/json request
# body into a Hashtable/PSCustomObject, so only re-parse when it's still a raw
# string. Piping an already-parsed object to ConvertFrom-Json stringifies it to
# "@{…}" and the parser dies on "@" — the same object-vs-string trap that broke
# Get-JITTargets (see tests/HttpHelpers.Tests.ps1).
$rawBody = $Request.Body
if ($rawBody -is [string]) {
    try {
        $body = $rawBody | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-JsonResponse -Status BadRequest -Body @{ error = 'Request body is not valid JSON.' }
        return
    }
}
elseif ($null -ne $rawBody) {
    $body = $rawBody
}
else {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Request body is required.' }
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

if ($port -and $port -notmatch '^\d{1,5}(-\d{1,5})?$') {
    Write-JsonResponse -Status BadRequest -Body @{ error = "port must be a number or range (e.g. '443' or '8080-8090')." }
    return
}

if ($justification -and $justification.Length -gt 500) {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Justification must be 500 characters or fewer.' }
    return
}

#endregion

#region ── 3. Determine caller IP ─────────────────────────────────────────────

# Shared helper (also used by Get-JITRules) so the IP this grant whitelists is
# exactly the IP reported back to clients for already-allowed detection.
$callerIp = Get-CallerIp -Request $Request

if (-not $callerIp -or $callerIp -eq '::1' -or $callerIp -eq '127.0.0.1') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Could not determine caller IP address.' }
    return
}

# Validate IP format — guards against log injection and crafted X-Forwarded-For values.
if ($callerIp -notmatch '^(\d{1,3}\.){3}\d{1,3}$' -and $callerIp -notmatch '^[0-9a-fA-F:]{2,45}$') {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Invalid caller IP address format.' }
    return
}

Write-Host "Caller IP: $callerIp"

#endregion

#region ── 3b. Abuse prevention ─────────────────────────────────────────────────────────────

try {
    Get-JITTableName -TableName $tableName | Out-Null
    $now             = [DateTime]::UtcNow.ToString('o')

    # Count active (non-expired) rules for this caller across all resources
    $callerActive = (Get-JITTableRows -TableName $tableName `
        -Filter "RequestedBy eq '$oDataRequestedBy'") |
        Where-Object { try { [DateTime]::Parse($_.ExpiryUtc) -gt [DateTime]::UtcNow } catch { $false } }

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
    $resourceActive = (Get-JITTableRows -TableName $tableName `
        -Filter "ResourceName eq '$resourceName' and ResourceRg eq '$resourceGroup'") |
        Where-Object { try { [DateTime]::Parse($_.ExpiryUtc) -gt [DateTime]::UtcNow } catch { $false } }

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
    # Fail CLOSED: if the rules table can't be read we cannot verify the
    # per-caller / per-resource limits or the cooldown, so deny rather than
    # allow unbounded rule creation during a Storage outage.
    Write-Error "Abuse-prevention check failed: $_"
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -DenyReason 'AbuseCheckError'
    Write-JsonResponse -Status ServiceUnavailable -Body @{
        error = 'Could not verify request limits right now. Please retry shortly.'
    }
    return
}

# Embed the caller's username in the rule id so rules are identifiable at a
# glance and in the portal (e.g. jit-jbland-cc5d7ef8). Take the local part of
# the UPN, strip to alphanumerics (NSG/SQL rule names disallow most symbols),
# lowercase, and cap the length so the full name stays within Azure's limits.
$callerUser = ((($requestedBy -split '@')[0]) -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
if (-not $callerUser)            { $callerUser = 'user' }
if ($callerUser.Length -gt 20)   { $callerUser = $callerUser.Substring(0, 20) }
$ruleId  = "jit-$callerUser-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
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
        # Capture the result from the lock's return value — assigning inside the
        # scriptblock would be lost (it runs in a child scope).
        $result = Invoke-WithBlobLock -LockName $lockName -Action {
            Add-JITNsgRule @addParams -Port $portVal -PriorityMin $priorityMin -PriorityMax $priorityMax
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
    Get-JITTableName -TableName $tableName | Out-Null

    Add-JITTableRow -TableName $tableName -Properties @{
        PartitionKey   = $subscriptionId
        RowKey         = $ruleId
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
    }
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
    subscriptionId = $subscriptionId
    resourceGroup  = $resourceGroup
    resourceName   = $resourceName
    callerIp       = $callerIp
    port           = if ($targetType -eq 'nsg') { $portVal } else { $null }
    expiresUtc     = $expiry.ToString('o')
    requestedBy    = $requestedBy
}
