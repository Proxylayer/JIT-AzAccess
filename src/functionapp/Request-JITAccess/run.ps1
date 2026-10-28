# Request-jitazaccess/run.ps1
#
# HTTP POST — Grants a caller's IP address temporary access on a supported target resource.
#
# Supported targetType values:  nsg | sqlServer | postgresqlFlexibleServer |
#   storageAccount | keyVault | mysqlFlexibleServer | redis | synapse | cosmosDb |
#   containerRegistry | aiSearch | cognitiveServices | kusto | iotHub | signalR |
#   eventHub | serviceBus | appService | aks
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
#   Token must be issued by the app's tenant and carry an ARM audience.
#   Caller's AAD objectId must hold the "JIT-Requester" custom RBAC role
#   (hardcoded role name) WITHIN the target subscription named in the request
#   body — i.e. the subscription the caller is requesting access into.

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

#region ── Configuration ──────────────────────────────────────────────────────

$tenantId            = Get-JitTenantId
$allowedDurationsRaw = if ($env:ALLOWED_DURATIONS_HOURS) { $env:ALLOWED_DURATIONS_HOURS } else { '1,4,8' }
$allowedDurations    = ($allowedDurationsRaw -split ',') |
                        ForEach-Object { [int]$_.Trim() }
$tableName           = if ($env:JIT_TABLE_NAME)            { $env:JIT_TABLE_NAME }            else { 'JITRules' }
$priorityMin         = if ($env:JIT_NSG_PRIORITY_MIN)      { [int]$env:JIT_NSG_PRIORITY_MIN }  else { 1000 }
$priorityMax         = if ($env:JIT_NSG_PRIORITY_MAX)      { [int]$env:JIT_NSG_PRIORITY_MAX }  else { 3900 }
$maxRulesPerCaller   = if ($env:JIT_MAX_RULES_PER_CALLER)   { [int]$env:JIT_MAX_RULES_PER_CALLER }   else { 5 }
$maxRulesPerResource = if ($env:JIT_MAX_RULES_PER_RESOURCE) { [int]$env:JIT_MAX_RULES_PER_RESOURCE } else { 20 }

#endregion

#region ── Helpers ────────────────────────────────────────────────────────────

# Correlation id for this request. Internal failure detail is logged against
# it and only the id goes back to the caller, so ARM URLs, resource ids and RP
# error text stay out of the HTTP response.
$correlationId = [guid]::NewGuid().ToString('N').Substring(0, 12)

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

$callerObjectId = $claims.oid
if (-not $callerObjectId) {
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp 'unknown' `
        -DenyReason 'MissingObjectIdClaim'
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token has no oid claim; cannot evaluate authorization.' }
    return
}

# NB: the JIT-Requester RBAC role check is deferred to region 2b — it is
# evaluated against the TARGET subscription parsed from the request body, not
# the function app's own host subscription.

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

# Single source of truth (Modules/JITTargets). Keeping a second hand-written
# copy here is how a type ends up accepted for grant but unknown at expiry.
$supportedTypes = Get-JITSupportedTargetTypes

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

# Justification is REQUIRED by default. The AzureTray app registration can opt
# out server-side by carrying the tag `JustificationRequired:false`. When the
# policy can't be read, Test-JustificationRequired fails SAFE (required).
$justificationTrimmed = if ($justification) { "$justification".Trim() } else { '' }
if ((Test-JustificationRequired) -and -not $justificationTrimmed) {
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp 'unknown' `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -DenyReason 'JustificationRequired'
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Justification is required for JIT access requests.' }
    return
}

if ($justification -and $justification.Length -gt 500) {
    Write-JsonResponse -Status BadRequest -Body @{ error = 'Justification must be 500 characters or fewer.' }
    return
}

#endregion

#region ── 2b. Authorize caller in the target subscription ─────────────────────

# The caller must hold the 'JIT-Requester' custom RBAC role in the subscription
# they are requesting access INTO — evaluated against the request body's
# subscriptionId, not the function app's own host subscription. The role
# definition must exist and be assigned to the caller within that subscription.
if (-not (Test-CallerHasJitRequesterRole -CallerObjectId $callerObjectId -SubscriptionId $subscriptionId)) {
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp 'unknown' `
        -SubscriptionId $subscriptionId -DenyReason 'MissingJitRequesterRole' `
        -Extra @{ requiredRole = 'JIT-Requester' }
    Write-JsonResponse -Status Forbidden -Body @{
        error        = "Caller does not hold the 'JIT-Requester' RBAC role in subscription '$subscriptionId'."
        requiredRole = 'JIT-Requester'
    }
    return
}

#endregion

#region ── 3. Determine caller IP ─────────────────────────────────────────────

# Shared helper (also used by Get-JITRules) so the IP this grant whitelists is
# exactly the IP reported back to clients for already-allowed detection.
# Resolve-JITCallerIp reads the PLATFORM-written end of X-Forwarded-For, not
# the client-written end, and reports whether the client tried to supply a
# chain of its own. This IP is what gets a firewall hole punched for it, so the
# caller must not be able to choose it.
$callerIpInfo = Resolve-JITCallerIp -Request $Request
$callerIp     = $callerIpInfo.IpAddress

if ($callerIpInfo.Spoofed) {
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -DenyReason 'SpoofedForwardedFor' `
        -Extra @{ claimedIp = $callerIpInfo.ClaimedIp; xffEntryCount = $callerIpInfo.EntryCount }
    Write-Warning ("Rejected request from ${requestedBy}: client supplied its own X-Forwarded-For " +
                   "(claimed '$($callerIpInfo.ClaimedIp)', trusted '$callerIp').")
    Write-JsonResponse -Status BadRequest -Body @{
        error = 'Request carried a client-supplied X-Forwarded-For header; the caller IP could not be trusted.'
    }
    return
}

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

    # Count active (non-expired) rules for this caller across all resources
    $callerActive = (Get-JITTableRows -TableName $tableName `
        -Filter "RequestedBy eq '$oDataRequestedBy'") |
        Where-Object { $e = ConvertTo-JITUtc $_.ExpiryUtc; $e -and $e -gt [DateTime]::UtcNow }

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
        Where-Object { $e = ConvertTo-JITUtc $_.ExpiryUtc; $e -and $e -gt [DateTime]::UtcNow }

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
        # IDEMPOTENCY. The AzureTray host wraps its HTTP clients in a resilience
        # handler that RETRIES, and the plugin can neither see nor disable it
        # (AzureTray Program.cs: 30s per attempt, 100s total). A slow
        # LRO-backed grant therefore gets re-sent — and the second attempt
        # lands here, finds the row the FIRST attempt just wrote, and used to
        # answer 409. A grant that actually succeeded was reported to the user
        # as a conflict. Double-clicking the menu item did the same thing.
        #
        # So: if the active rule is for the SAME caller IP, the caller already
        # has exactly what they asked for. Return it as success rather than an
        # error. Matching on IP rather than a time window also covers the
        # genuine conflict — if their IP has CHANGED, the existing rule does
        # not help them and the cooldown below is the right answer.
        #
        # Deliberately does NOT extend the expiry: a retried request must be
        # indistinguishable from the original, not a way to roll the clock.
        if ($cooldownRow.CallerIp -eq $callerIp) {
            Write-Host "Request for '$resourceName' already satisfied by rule '$($cooldownRow.RowKey)' for $callerIp — returning it (idempotent)."
            Write-JsonResponse -Status OK -Body @{
                status         = 'AlreadyActive'
                message        = 'An active JIT rule already covers this resource for your IP.'
                ruleId         = $cooldownRow.RowKey
                ruleIdentifier = $cooldownRow.RuleIdentifier
                targetType     = $cooldownRow.TargetType
                resourceName   = $resourceName
                resourceGroup  = $resourceGroup
                subscriptionId = $subscriptionId
                callerIp       = $callerIp
                expiresUtc     = $cooldownRow.ExpiryUtc
                requestedBy    = $requestedBy
            }
            return
        }

        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -DenyReason 'CooldownActive' `
            -Extra @{ existingRuleId = $cooldownRow.RowKey; expiresUtc = $cooldownRow.ExpiryUtc; existingCallerIp = $cooldownRow.CallerIp }
        Write-JsonResponse -Status Conflict -Body @{
            error          = 'An active JIT rule already exists for this resource, granted to a different IP address. Wait for it to expire or revoke it first.'
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
            'sqlServer'                { Add-JITSqlFirewallRule           @addParams }
            'postgresqlFlexibleServer' { Add-JITPostgresFirewallRule      @addParams }
            'storageAccount'           { Add-JITStorageNetworkRule        @addParams }
            'keyVault'                 { Add-JITKeyVaultNetworkRule       @addParams }
            'mysqlFlexibleServer'      { Add-JITMysqlFlexibleServerRule   @addParams }
            'redis'                    { Add-JITRedisRule                 @addParams }
            'synapse'                  { Add-JITSynapseRule               @addParams }
            'cosmosDb'                 { Add-JITCosmosDbRule              @addParams }
            'containerRegistry'        { Add-JITContainerRegistryRule     @addParams }
            'aiSearch'                 { Add-JITAiSearchRule              @addParams }
            'cognitiveServices'        { Add-JITCognitiveServicesRule     @addParams }
            'kusto'                    { Add-JITKustoRule                 @addParams }
            'iotHub'                   { Add-JITIotHubRule                @addParams }
            'signalR'                  { Add-JITSignalRRule               @addParams }
            'eventHub'                 { Add-JITEventHubRule              @addParams }
            'serviceBus'               { Add-JITServiceBusRule            @addParams }
            'appService'               { Add-JITAppServiceRule            @addParams }
            'aks'                      { Add-JITAksRule                   @addParams }
        }
    }
}
catch {
    # A PostgreSQL flexible server on private/VNet networking has no firewall to
    # write to. Add-JITPostgresFirewallRule throws a sentinel-prefixed message so
    # we can surface a clean 409 denial (+ JITDenied audit) instead of a generic
    # 500. Keep this literal in sync with $script:PostgresPrivateRejectPrefix in
    # Modules/JITTargets/JITTargets.psm1.
    $errMsg = $_.Exception.Message
    if ($errMsg -like 'PRIVATE_SERVER_REJECTED:*') {
        $clientMsg = ($errMsg -replace '^PRIVATE_SERVER_REJECTED:\s*', '')
        Write-Error "JIT target modification denied (private server): $clientMsg"
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -RuleId $ruleId -DenyReason 'PrivateServerNotSupported'
        Write-JsonResponse -Status Conflict -Body @{ error = $clientMsg }
        return
    }

    # Log the detail; return only the correlation id. The exception text can
    # carry ARM URLs, resource ids and raw resource-provider error bodies.
    Write-Error "JIT target modification failed [correlationId=$correlationId]: $_"
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -RuleId $ruleId -DenyReason 'TargetModificationFailed' `
        -Extra @{ correlationId = $correlationId }
    Write-JsonResponse -Status InternalServerError -Body @{
        error         = "Failed to modify $targetType. Verify the function app has the JIT-AzAccess Manager role on the target subscription."
        correlationId = $correlationId
    }
    return
}

#endregion

#region ── 5. Persist / audit based on the Add outcome ─────────────────────────

# Every Add-JIT*Rule handler returns a Status describing what actually happened
# on the target resource:
#   Created        — a rule was added for the caller IP (normal grant).
#   AlreadyPresent — the caller IP was already whitelisted (idempotent add).
#   SkippedOpen    — the resource is open/unrestricted, so nothing was added.
# A handler that returns no Status (unexpected/legacy) is treated as Created.
$grantStatus    = if ($result -and $result.Status) { $result.Status } else { 'Created' }
$ruleIdentifier = if ($result) { $result.RuleIdentifier } else { $ruleId }
# Per-resource outcome detail the handler chose to report (App Service returns
# the site's status plus one entry per deployment slot, and flags a failed slot
# enumeration). Carried onto every audit row below so a partial grant is
# visible in the audit table, not only in the function logs. Most handlers
# report nothing, in which case no Details column is written at all.
$grantDetails   = if ($result) { $result.Details } else { $null }

switch ($grantStatus) {

    'SkippedOpen' {
        # The target is currently open/unrestricted (App Service open site, AKS
        # open cluster, or an unconfigured resource firewall). Adding a single
        # Allow rule would have *restricted* it, so we intentionally did nothing —
        # the caller already has access. No JITRules row, no scheduled removal.
        try {
            Add-JITAuditRow -Action 'SkippedOpen' `
                -SubscriptionId $subscriptionId -TargetType $targetType `
                -ResourceName $resourceName -ResourceRg $resourceGroup `
                -RuleIdentifier $ruleIdentifier -CallerIp $callerIp `
                -Port $portVal -RequestedBy $requestedBy `
                -ExpiryUtc $expiry.ToString('o') -Justification $justification `
                -Details $grantDetails
        }
        catch { Write-Warning "JITRulesAudit write failed for skipped-open '$ruleId': $_" }

        Write-JsonResponse -Status OK -Body @{
            status         = 'SkippedOpen'
            message        = "The $targetType resource is currently open/unrestricted, so no JIT rule was added — the caller IP already has access."
            targetType     = $targetType
            resourceName   = $resourceName
            resourceGroup  = $resourceGroup
            subscriptionId = $subscriptionId
            callerIp       = $callerIp
        }
        return
    }

    'AlreadyPresent' {
        # The caller IP is already whitelisted on the target. If a JIT-managed row
        # for this resource+IP exists it is OURS — refresh its expiry (extend)
        # rather than create a duplicate. Otherwise the whitelist entry is
        # external/manual, so we neither create a row nor schedule a removal for
        # something JIT did not create.
        $existingRow = $null
        try {
            Get-JITTableName -TableName $tableName | Out-Null
            $filter = "PartitionKey eq '$subscriptionId' and ResourceName eq '$resourceName' " +
                      "and ResourceRg eq '$resourceGroup' and TargetType eq '$targetType' " +
                      "and CallerIp eq '$callerIp'"
            $existingRow = Get-JITTableRows -TableName $tableName -Filter $filter | Select-Object -First 1
        }
        catch {
            Write-Warning "AlreadyPresent lookup failed for '$resourceName'/${callerIp}: $_"
        }

        if ($existingRow) {
            # Ours — refresh the expiry in place (no duplicate row).
            try {
                Update-JITTableRow -TableName $tableName `
                    -PartitionKey $existingRow.PartitionKey -RowKey $existingRow.RowKey `
                    -Properties @{ ExpiryUtc = $expiry.ToString('o') }
            }
            catch { Write-Warning "Failed to extend expiry for existing rule '$($existingRow.RowKey)': $_" }

            try {
                Add-JITAuditRow -Action 'Extend' `
                    -SubscriptionId $subscriptionId -TargetType $targetType `
                    -ResourceName $resourceName -ResourceRg $resourceGroup `
                    -RuleIdentifier $existingRow.RuleIdentifier -CallerIp $callerIp `
                    -Port $portVal -RequestedBy $requestedBy `
                    -ExpiryUtc $expiry.ToString('o') -Justification $justification `
                    -Details $grantDetails
            }
            catch { Write-Warning "JITRulesAudit write failed for extend '$($existingRow.RowKey)': $_" }

            Write-JsonResponse -Status OK -Body @{
                status         = 'Extended'
                message        = 'IP already granted by JIT; expiry extended.'
                ruleId         = $existingRow.RowKey
                ruleIdentifier = $existingRow.RuleIdentifier
                targetType     = $targetType
                resourceName   = $resourceName
                resourceGroup  = $resourceGroup
                subscriptionId = $subscriptionId
                callerIp       = $callerIp
                expiresUtc     = $expiry.ToString('o')
                requestedBy    = $requestedBy
            }
            return
        }

        # External/manual entry — leave it alone and track nothing.
        try {
            Add-JITAuditRow -Action 'AlreadyExternal' `
                -SubscriptionId $subscriptionId -TargetType $targetType `
                -ResourceName $resourceName -ResourceRg $resourceGroup `
                -RuleIdentifier $ruleIdentifier -CallerIp $callerIp `
                -Port $portVal -RequestedBy $requestedBy `
                -ExpiryUtc $expiry.ToString('o') -Justification $justification `
                -Details $grantDetails
        }
        catch { Write-Warning "JITRulesAudit write failed for already-external '$ruleId': $_" }

        Write-JsonResponse -Status OK -Body @{
            status         = 'AlreadyWhitelisted'
            message        = 'IP already whitelisted (existing entry not managed by JIT); no rule created and no removal scheduled.'
            targetType     = $targetType
            resourceName   = $resourceName
            resourceGroup  = $resourceGroup
            subscriptionId = $subscriptionId
            callerIp       = $callerIp
        }
        return
    }

    default {
        # 'Created' (and any unexpected/legacy status) — record the new rule in
        # Table Storage and audit a normal grant.
        Write-JITAuditEvent -EventType JITGranted -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -RuleId $ruleId `
            -Extra @{ expiresUtc = $expiry.ToString('o'); port = $portVal; durationHours = $durationHours; justification = $justification }

        try {
            Get-JITTableName -TableName $tableName | Out-Null

            Add-JITTableRow -TableName $tableName -Properties @{
                PartitionKey   = $subscriptionId
                RowKey         = $ruleId
                TargetType     = $targetType
                ResourceName   = $resourceName
                ResourceRg     = $resourceGroup
                SubscriptionId = $subscriptionId
                RuleIdentifier = $ruleIdentifier
                CallerIp       = $callerIp
                Port           = $portVal
                RequestedBy    = $requestedBy
                ExpiryUtc      = $expiry.ToString('o')
                Justification  = if ($justification) { $justification } else { '' }
            }
        }
        catch {
            # WORST CASE: the rule is LIVE on the resource but nothing is
            # tracking it, so Remove-ExpiredRules will never revoke it — a
            # firewall hole open forever. Previously this was a Write-Warning
            # and the endpoint still answered "200 Created".
            #
            # Undo the grant instead of reporting success for access that can
            # never expire.
            Write-Error "Table write failed for rule '$ruleIdentifier' [correlationId=$correlationId]: $_"

            # Shaped like a JITRules row so the Remove handlers read it the
            # same way the timer and Revoke-JITAccess do.
            $rollbackRow = [pscustomobject]@{
                PartitionKey   = $subscriptionId
                RowKey         = $ruleId
                TargetType     = $targetType
                ResourceName   = $resourceName
                ResourceRg     = $resourceGroup
                SubscriptionId = $subscriptionId
                RuleIdentifier = $ruleIdentifier
                CallerIp       = $callerIp
                Port           = $portVal
                RequestedBy    = $requestedBy
                ExpiryUtc      = $expiry.ToString('o')
                Justification  = if ($justification) { $justification } else { '' }
            }

            $rolledBack = $false
            try {
                $undo       = Invoke-JITTargetRemove -Row $rollbackRow
                # No Status (unknown/legacy handler) is treated as Removed, the
                # same convention the timer and Revoke use.
                $undoStatus = if ($undo -and $undo.Status) { $undo.Status } else { 'Removed' }
                $rolledBack = ($undoStatus -in @('Removed', 'NotFound'))
                if (-not $rolledBack) {
                    # AKS refuses to remove the last authorized range. The rule
                    # stays, untracked — that is an orphan, reported below.
                    Write-Warning "Rollback of '$ruleIdentifier' returned status '$undoStatus'."
                }
            }
            catch {
                Write-Error "Rollback FAILED for rule '$ruleIdentifier' [correlationId=$correlationId]: $_"
            }

            if ($rolledBack) {
                Write-JITAuditEvent -EventType JITGrantRolledBack -Caller $requestedBy -CallerIp $callerIp `
                    -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
                    -SubscriptionId $subscriptionId -RuleId $ruleId `
                    -Extra @{ correlationId = $correlationId; reason = 'RulesTableWriteFailed' }

                # Best-effort history row. The audit table shares the storage
                # account that just failed, so this may fail too — the stdout
                # audit event above is the reliable channel.
                try {
                    Add-JITAuditRow -Action 'GrantRolledBack' `
                        -SubscriptionId $subscriptionId -TargetType $targetType `
                        -ResourceName $resourceName -ResourceRg $resourceGroup `
                        -RuleIdentifier $ruleIdentifier -CallerIp $callerIp `
                        -Port $portVal -RequestedBy $requestedBy `
                        -ExpiryUtc $expiry.ToString('o') -Justification $justification `
                        -Extra @{ correlationId = $correlationId } `
                        -Details $grantDetails
                }
                catch { Write-Warning "JITRulesAudit write failed for rollback of '$ruleId': $_" }

                Write-JsonResponse -Status InternalServerError -Body @{
                    error         = 'The access rule could not be recorded, so it was rolled back. No access was granted. Please retry.'
                    correlationId = $correlationId
                }
            }
            else {
                # Nothing else in the system knows this rule exists. Loudest
                # possible signal: a human has to remove it by hand.
                Write-JITAuditEvent -EventType JITOrphanedGrant -Caller $requestedBy -CallerIp $callerIp `
                    -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
                    -SubscriptionId $subscriptionId -RuleId $ruleId `
                    -Extra @{ correlationId = $correlationId; reason = 'RulesTableWriteFailed'; rollback = 'failed' }
                Write-Error ("ORPHANED JIT GRANT: rule '$ruleIdentifier' ($targetType) is live on " +
                             "'$resourceName' in subscription $subscriptionId for IP $callerIp, is NOT " +
                             "tracked in '$tableName', and could not be rolled back. It will never expire. " +
                             "Remove it manually. [correlationId=$correlationId]")

                try {
                    Add-JITAuditRow -Action 'OrphanedGrant' `
                        -SubscriptionId $subscriptionId -TargetType $targetType `
                        -ResourceName $resourceName -ResourceRg $resourceGroup `
                        -RuleIdentifier $ruleIdentifier -CallerIp $callerIp `
                        -Port $portVal -RequestedBy $requestedBy `
                        -ExpiryUtc $expiry.ToString('o') -Justification $justification `
                        -Extra @{ correlationId = $correlationId } `
                        -Details $grantDetails
                }
                catch { Write-Warning "JITRulesAudit write failed for orphaned grant '$ruleId': $_" }

                Write-JsonResponse -Status InternalServerError -Body @{
                    error         = 'The access rule could not be recorded and could not be rolled back. It has been reported for manual removal.'
                    correlationId = $correlationId
                }
            }

            return
        }

        # Append a lifecycle event to the audit history table. Best-effort — an
        # audit write failure must NEVER fail the grant.
        try {
            Add-JITAuditRow -Action 'Grant' `
                -SubscriptionId $subscriptionId -TargetType $targetType `
                -ResourceName $resourceName -ResourceRg $resourceGroup `
                -RuleIdentifier $ruleIdentifier -CallerIp $callerIp `
                -Port $portVal -RequestedBy $requestedBy `
                -ExpiryUtc $expiry.ToString('o') -Justification $justification `
                -Details $grantDetails
        }
        catch {
            Write-Warning "JITRulesAudit write failed for grant '$ruleId' (grant itself succeeded): $_"
        }

        Write-JsonResponse -Status OK -Body @{
            status         = 'Created'
            ruleId         = $ruleId
            ruleIdentifier = $ruleIdentifier
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
        return
    }
}

#endregion
