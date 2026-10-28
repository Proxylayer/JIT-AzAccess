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

# How long a reservation row stays valid before the expiry timer treats it as
# abandoned and cleans it up. Must comfortably exceed the function timeout
# (host.json functionTimeout, 9 minutes) so a slow-but-live grant is never
# reaped out from under itself.
$reservationTtlMinutes = if ($env:JIT_RESERVATION_TTL_MINUTES) { [int]$env:JIT_RESERVATION_TTL_MINUTES } else { 15 }

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

#region ── 3b. Abuse prevention (serialised per caller) ─────────────────────────────────────

# Identity for this grant. Computed BEFORE the limit check, because the
# reservation row that closes the race below is written under this rule id.
#
# The username is embedded so rules are identifiable at a glance and in the
# portal (e.g. jit-jbland-cc5d7ef8): take the local part of the UPN, strip to
# alphanumerics (NSG/SQL rule names disallow most symbols), lowercase, and cap
# the length so the full name stays within Azure's limits.
$callerUser = ((($requestedBy -split '@')[0]) -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
if (-not $callerUser)            { $callerUser = 'user' }
if ($callerUser.Length -gt 20)   { $callerUser = $callerUser.Substring(0, 20) }
$ruleId  = "jit-$callerUser-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$portVal = if ($port) { $port } else { '*' }
$expiry  = [DateTime]::UtcNow.AddHours($durationHours)

# THE RACE THIS CLOSES
#
# The limits used to be evaluated here and the row written several hundred
# lines later, after an ARM call that can take minutes. Two requests from one
# caller both read "4 active, limit 5", both passed, both granted, and both
# inserted - so the caller ended up with 6. The cooldown had the same hole:
# two simultaneous requests for one resource both saw no existing rule.
#
# The fix is to make "check the limits" and "claim a slot" one atomic step.
# Inside a lock keyed on the caller, re-read the counts and, if they pass,
# immediately insert a RESERVATION row: a normal JITRules row carrying
# State='Pending' and a short ExpiryUtc. A concurrent request for the same
# caller blocks on the lock, then counts the reservation and is refused.
#
# The lock does NOT span the ARM call. That is deliberate: the lease is 60
# seconds with no renewal, so a lock held across an LRO-backed grant would
# expire mid-flight and stop excluding anything. Here the critical section is
# two table reads and one insert.
#
# A reservation that is never finalised (worker killed between the grant and
# the finalise) needs no special handling: it is an ordinary row with a short
# expiry, so Remove-ExpiredRules picks it up, attempts the removal - which is
# idempotent and answers NotFound if the rule was never created - and deletes
# the row. That is strictly better than the pre-reservation behaviour, where
# the same crash left a live rule with nothing tracking it at all.
#
# RESIDUAL, stated plainly: the lock is per caller, so the per-RESOURCE limit
# is still only best-effort when two DIFFERENT callers race on one resource.
# Closing that needs a second lock, ordered caller-then-resource to stay
# deadlock-free, and it is a bigger change than this one. The per-caller limit
# and the cooldown - the two the abuse-prevention design actually leans on -
# are now exact.
$callerLockName = "caller-$($callerObjectId -replace '[^A-Za-z0-9-]', '')"

try {
    Get-JITTableName -TableName $tableName | Out-Null

    # The scriptblock runs in a child scope, so it RETURNS a decision rather
    # than writing the response itself; everything below acts on that outside
    # the lock, keeping the critical section as short as possible.
    $gate = Invoke-WithBlobLock -LockName $callerLockName -Action {

        $nowUtc = [DateTime]::UtcNow

        # Every not-yet-expired row this caller holds, reservations included -
        # counting those is the whole point.
        $callerActive = @(Get-JITTableRows -TableName $tableName `
            -Filter "RequestedBy eq '$oDataRequestedBy'" |
            Where-Object { $e = ConvertTo-JITUtc $_.ExpiryUtc; $e -and $e -gt $nowUtc })

        if ($callerActive.Count -ge $maxRulesPerCaller) {
            return @{ Verdict = 'DenyCallerLimit'; Count = $callerActive.Count }
        }

        $resourceActive = @(Get-JITTableRows -TableName $tableName `
            -Filter "ResourceName eq '$resourceName' and ResourceRg eq '$resourceGroup'" |
            Where-Object { $e = ConvertTo-JITUtc $_.ExpiryUtc; $e -and $e -gt $nowUtc })

        if ($resourceActive.Count -ge $maxRulesPerResource) {
            return @{ Verdict = 'DenyResourceLimit'; Count = $resourceActive.Count }
        }

        # Cooldown / idempotency: does this caller already hold something for
        # this exact resource?
        $existing = $callerActive | Where-Object {
            $_.ResourceName -eq $resourceName -and $_.SubscriptionId -eq $subscriptionId
        } | Select-Object -First 1

        if ($existing) {
            if ($existing.State -eq 'Pending') {
                # Another request for the same resource is mid-grant. Neither
                # "you already have it" nor "409 conflict" is true yet.
                return @{ Verdict = 'InProgress'; Row = $existing }
            }
            if ($existing.CallerIp -eq $callerIp) {
                # IDEMPOTENCY. The AzureTray host wraps its HTTP clients in a
                # resilience handler that RETRIES, and the plugin can neither
                # see nor disable it (AzureTray Program.cs: 30s per attempt,
                # 100s total). A slow LRO-backed grant therefore gets re-sent,
                # and the second attempt lands here and finds the row the
                # first one wrote. Answering 409 reported a grant that
                # actually succeeded as a conflict. Double-clicking the menu
                # item did the same thing.
                #
                # Matching on IP rather than a time window also covers the
                # genuine conflict: if their IP has CHANGED, the existing rule
                # does not help them and the cooldown below is right.
                #
                # Deliberately does NOT extend the expiry: a retried request
                # must be indistinguishable from the original, not a way to
                # roll the clock.
                return @{ Verdict = 'Idempotent'; Row = $existing }
            }
            return @{ Verdict = 'Cooldown'; Row = $existing }
        }

        # Claim the slot. Short expiry so an abandoned reservation clears
        # itself; the real expiry is written when the grant is finalised.
        Add-JITTableRow -TableName $tableName -Properties @{
            PartitionKey   = $subscriptionId
            RowKey         = $ruleId
            TargetType     = $targetType
            ResourceName   = $resourceName
            ResourceRg     = $resourceGroup
            SubscriptionId = $subscriptionId
            # Deliberately EMPTY until the grant reports what it actually
            # used. Every Remove-JIT*Rule handler falls back from
            # RuleIdentifier to the right per-type key when it is blank:
            # RowKey for the seven named-rule types (nsg, sqlServer,
            # postgres/mysql flexible, redis, synapse, appService) and
            # CallerIp for the twelve that identify the entry by IP
            # (storage, keyVault, cosmosDb, acr, aiSearch, cognitive, kusto,
            # iotHub, signalR, eventHub, serviceBus, aks).
            #
            # Writing $ruleId here instead looked harmless and was not: for
            # those twelve the handler would hunt for an ipRule whose VALUE is
            # 'jit-alice-abcd1234', never match, report NotFound, and the
            # timer would then delete the row -- leaving a live rule with
            # nothing tracking it. That is the exact orphan the reservation
            # exists to prevent, reintroduced for 12 of the 19 types.
            RuleIdentifier = ''
            CallerIp       = $callerIp
            Port           = $portVal
            RequestedBy    = $requestedBy
            ExpiryUtc      = $nowUtc.AddMinutes($reservationTtlMinutes).ToString('o')
            Justification  = if ($justification) { $justification } else { '' }
            State          = 'Pending'
            ReservedUtc    = $nowUtc.ToString('o')
        }

        return @{ Verdict = 'Reserved' }
    }
}
catch {
    # Fail CLOSED. If the table cannot be read, or the lock cannot be taken,
    # the limits and the cooldown are unverifiable - so deny rather than allow
    # unbounded rule creation during a Storage outage.
    Write-Error "Abuse-prevention check failed [correlationId=$correlationId]: $_"
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -DenyReason 'AbuseCheckError' `
        -Extra @{ correlationId = $correlationId }
    Write-JsonResponse -Status ServiceUnavailable -Body @{
        error         = 'Could not verify request limits right now. Please retry shortly.'
        correlationId = $correlationId
    }
    return
}

# A scriptblock returns everything it emits, so if any statement inside the
# gate ever stops swallowing its output $gate silently becomes an array and
# $gate.Verdict becomes $null - which would fall straight through the switch
# and grant. Normalise, then refuse anything unrecognised. This gate decides
# whether a firewall opens; it does not get to fail open on a typo.
if ($gate -is [System.Array]) { $gate = $gate[-1] }

if (-not $gate -or -not $gate.Verdict) {
    Write-Error "Abuse-prevention gate returned no verdict [correlationId=$correlationId]."
    Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
        -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
        -SubscriptionId $subscriptionId -DenyReason 'AbuseCheckError' `
        -Extra @{ correlationId = $correlationId; reason = 'no-verdict' }
    Write-JsonResponse -Status ServiceUnavailable -Body @{
        error         = 'Could not verify request limits right now. Please retry shortly.'
        correlationId = $correlationId
    }
    return
}

switch ($gate.Verdict) {

    'DenyCallerLimit' {
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -DenyReason 'MaxRulesPerCallerExceeded' `
            -Extra @{ activeCount = $gate.Count; limit = $maxRulesPerCaller }
        Write-JsonResponse -Status TooManyRequests -Body @{
            error       = "You have $($gate.Count) active JIT rule(s). Maximum is $maxRulesPerCaller."
            activeRules = $gate.Count
        }
        return
    }

    'DenyResourceLimit' {
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -DenyReason 'MaxRulesPerResourceExceeded' `
            -Extra @{ activeCount = $gate.Count; limit = $maxRulesPerResource }
        Write-JsonResponse -Status TooManyRequests -Body @{
            error       = "Resource '$resourceName' has $($gate.Count) active JIT rule(s). Maximum is $maxRulesPerResource."
            activeRules = $gate.Count
        }
        return
    }

    'InProgress' {
        Write-Host "Request for '$resourceName' is already being granted under '$($gate.Row.RowKey)' - refusing the duplicate."
        Write-JsonResponse -Status Conflict -Body @{
            error          = 'A JIT request for this resource is already in progress. Retry in a moment.'
            existingRuleId = $gate.Row.RowKey
        }
        return
    }

    'Idempotent' {
        $row = $gate.Row
        Write-Host "Request for '$resourceName' already satisfied by rule '$($row.RowKey)' for $callerIp - returning it (idempotent)."
        Write-JsonResponse -Status OK -Body @{
            status         = 'AlreadyActive'
            message        = 'An active JIT rule already covers this resource for your IP.'
            ruleId         = $row.RowKey
            ruleIdentifier = $row.RuleIdentifier
            targetType     = $row.TargetType
            resourceName   = $resourceName
            resourceGroup  = $resourceGroup
            subscriptionId = $subscriptionId
            callerIp       = $callerIp
            expiresUtc     = $row.ExpiryUtc
            requestedBy    = $requestedBy
        }
        return
    }

    'Cooldown' {
        $row = $gate.Row
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -DenyReason 'CooldownActive' `
            -Extra @{ existingRuleId = $row.RowKey; expiresUtc = $row.ExpiryUtc; existingCallerIp = $row.CallerIp }
        Write-JsonResponse -Status Conflict -Body @{
            error          = 'An active JIT rule already exists for this resource, granted to a different IP address. Wait for it to expire or revoke it first.'
            existingRuleId = $row.RowKey
            expiresUtc     = $row.ExpiryUtc
        }
        return
    }

    'Reserved' {
        # The only verdict that continues to the grant below.
    }

    default {
        # Unreachable unless a verdict is added above without a branch here.
        # Deny rather than fall through into a grant.
        Write-Error "Abuse-prevention gate returned unknown verdict '$($gate.Verdict)' [correlationId=$correlationId]."
        Write-JsonResponse -Status ServiceUnavailable -Body @{
            error         = 'Could not verify request limits right now. Please retry shortly.'
            correlationId = $correlationId
        }
        return
    }
}

# From here the reservation row exists and this request owns it. Every exit
# path below must either finalise it or remove it - leaving it behind would
# consume one of the caller's slots until it expires.
Write-Host "Reserved slot '$ruleId' for $requestedBy on '$resourceName'."

# Releases the slot claimed above. Called on every path that does NOT end in a
# tracked rule: a failed grant, and the three outcomes that deliberately leave
# nothing to revoke (SkippedOpen, an extend of an existing row, and an
# externally-managed whitelist entry).
function Remove-JITReservation {
    param([Parameter(Mandatory)][string]$Why)
    try {
        Remove-JITTableRow -TableName $tableName -PartitionKey $subscriptionId -RowKey $ruleId
        Write-Host "  Released reservation '$ruleId' ($Why)."
    }
    catch {
        # Not fatal. The reservation carries a short expiry, so the timer
        # clears it; until then it costs the caller one slot. Saying so beats
        # failing a request whose access decision has already been made.
        Write-Warning "Could not release reservation '$ruleId' ($Why); it will expire on its own: $_"
    }
}

#endregion


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
        Remove-JITReservation -Why 'private server rejected'
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -RuleId $ruleId -DenyReason 'PrivateServerNotSupported'
        Write-JsonResponse -Status Conflict -Body @{ error = $clientMsg }
        return
    }

    # Did the write possibly land? An ARM rejection (403, 400, a provider
    # refusal) means nothing was created and the slot should go back. A
    # long-running operation we stopped waiting for is different: the rule may
    # have been created a second after we gave up. Releasing the reservation
    # there would leave a live rule with nothing tracking it -- the orphan this
    # whole design exists to avoid -- so the slot is KEPT and the cleanup timer
    # reconciles it when the short reservation expires (the remove handlers are
    # idempotent and answer NotFound if nothing was ever created).
    #
    # Wait-JITArmAsyncOperation marks exactly that case; keep the literal in
    # sync with the throw in _Shared.ps1.
    $outcomeUnknown = ($_.Exception.Message -like 'ARM_LRO_UNRESOLVED:*')

    # Log the detail; return only the correlation id. The exception text can
    # carry ARM URLs, resource ids and raw resource-provider error bodies.
    Write-Error "JIT target modification failed [correlationId=$correlationId]: $_"

    if ($outcomeUnknown) {
        Write-Warning ("Grant for '$ruleId' timed out waiting on ARM; the rule MAY exist. Keeping the " +
                       "reservation row so the cleanup timer reconciles it at $($reservationTtlMinutes)m.")
        Write-JITAuditEvent -EventType JITDenied -Caller $requestedBy -CallerIp $callerIp `
            -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
            -SubscriptionId $subscriptionId -RuleId $ruleId -DenyReason 'TargetModificationUnresolved' `
            -Extra @{ correlationId = $correlationId; reservationRetained = $true }
        Write-JsonResponse -Status InternalServerError -Body @{
            error         = "The $targetType change did not confirm in time. If access appears shortly it will be revoked automatically; retry in a few minutes."
            correlationId = $correlationId
        }
        return
    }

    Remove-JITReservation -Why 'grant failed'
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
        Remove-JITReservation -Why 'target already open'

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
            # Excluding $ruleId matters: this request's own reservation row
            # matches that filter exactly, and treating it as the pre-existing
            # rule would "extend" the row we are about to finalise and report
            # the grant as an extension of itself.
            $existingRow = Get-JITTableRows -TableName $tableName -Filter $filter |
                Where-Object { $_.RowKey -ne $ruleId } | Select-Object -First 1
        }
        catch {
            Write-Warning "AlreadyPresent lookup failed for '$resourceName'/${callerIp}: $_"
        }

        if ($existingRow) {
            # A pre-existing JIT row covers this already, so the slot this
            # request claimed is not needed.
            Remove-JITReservation -Why 'extending an existing rule'

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
        Remove-JITReservation -Why 'whitelist entry is not JIT-managed'

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
            # FINALISE the reservation rather than insert: the row already
            # exists from the slot claimed in region 3b. This promotes it from
            # Pending to Active, swaps the short reservation TTL for the real
            # expiry, and records the identifier the handler actually used
            # (which can differ from $ruleId - array-type resources identify
            # the entry by IP).
            Update-JITTableRow -TableName $tableName `
                -PartitionKey $subscriptionId -RowKey $ruleId `
                -Properties @{
                    State          = 'Active'
                    RuleIdentifier = $ruleIdentifier
                    ExpiryUtc      = $expiry.ToString('o')
                }
        }
        catch {
            # The rule is LIVE on the resource and could not be promoted out
            # of Pending. Undo the grant rather than report success for access
            # whose expiry was never recorded. (Before the compensating remove
            # existed this was a Write-Warning and the endpoint still answered
            # "200 Created".)
            #
            # Note what the reservation buys here: the row from region 3b is
            # still in the table with its short TTL and RuleIdentifier set to
            # $ruleId, so even if everything below fails the rule is TRACKED
            # and Remove-ExpiredRules will attempt it again at that expiry.
            # The pre-reservation version of this path left nothing at all.
            Write-Error "Could not finalise reservation for rule '$ruleIdentifier' [correlationId=$correlationId]: $_"

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
                # The rule is off the resource, so the slot should not stay
                # claimed. If this delete fails the row expires on its own and
                # the timer finds nothing to remove - safe either way.
                Remove-JITReservation -Why 'grant rolled back'

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
                # The rule is still live. KEEP the reservation row: with the
                # grant un-undoable it is the only record that the rule
                # exists, and leaving it means the expiry timer will retry the
                # removal rather than the rule being lost entirely. Still the
                # loudest possible signal, because a 15-minute retry is not a
                # substitute for someone looking.
                Write-JITAuditEvent -EventType JITOrphanedGrant -Caller $requestedBy -CallerIp $callerIp `
                    -TargetType $targetType -ResourceName $resourceName -ResourceGroup $resourceGroup `
                    -SubscriptionId $subscriptionId -RuleId $ruleId `
                    -Extra @{ correlationId = $correlationId; reason = 'RulesTableWriteFailed'; rollback = 'failed' }
                Write-Error ("ORPHANED JIT GRANT: rule '$ruleIdentifier' ($targetType) is live on " +
                             "'$resourceName' in subscription $subscriptionId for IP $callerIp and could " +
                             "NOT be rolled back. Its reservation row '$ruleId' is still in '$tableName' " +
                             "with a short expiry, so the cleanup timer will retry the removal - but that " +
                             "retry is a backstop, not a fix. Confirm the rule is gone, by hand if " +
                             "necessary. [correlationId=$correlationId]")

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
