# JITHelpers.psm1 — shared helpers for the JIT NSG function app.
#
# This module depends on HttpHelpers.psm1 instead of Az.* modules so the
# function app stays slim. All Azure ops go through Invoke-RestMethod via
# the helpers in that module.
#
# IMPORTANT: HttpHelpers must already be loaded (in global scope) before any
# JITHelpers function is invoked. Each endpoint's run.ps1 is responsible for
# Import-Module'ing HttpHelpers FIRST. We do NOT re-import here, because
# Import-Module from inside another .psm1 with -Force has the side effect of
# clearing the inner module's ExportedCommands (PowerShell nested-module
# behavior), which makes Get-ManagedIdentityToken etc. invisible at runtime.

#region ── Per-worker Caches ────────────────────────────────────────────────────────
# Module-scoped variables persist within a worker process lifetime.
$script:JwksCache    = $null   # { Keys: [...], FetchedAt: [DateTime] }
$script:JwksCacheTtl = [TimeSpan]::FromHours(1)

# The custom RBAC role a caller must hold (in the target subscription) to use
# the JIT API. Hardcoded — deliberately NOT configurable via env var.
$script:JitRequesterRoleName = 'JIT-Requester'

# Cache of the JIT-Requester role definition GUID, keyed by subscription id.
# The GUID differs per subscription, so cache per-subscription for the
# lifetime of the worker process.
$script:JitRoleDefIdCache = @{}   # @{ <subscriptionId> = <guid> }

# Cache of per-caller authz decisions. Keyed by "{oid}|{subscriptionId}".
# Cap is 60 seconds for both positive and negative decisions so role
# assignments and revocations take effect within ~1 minute without needing
# a function-app restart, while still saving an ARM round-trip per request
# under typical bursty usage (a grant flow makes several calls back-to-back).
$script:RoleCheckCache    = @{}
$script:RoleCheckCacheTtl = [TimeSpan]::FromSeconds(60)

# ARM audiences accepted on bearer tokens. Override via EXPECTED_AUDIENCES env var
# (comma-separated) for sovereign clouds.
$script:DefaultArmAudiences = @(
    'https://management.azure.com/'
    'https://management.azure.com'
    'https://management.core.windows.net/'
    'https://management.core.windows.net'
)

function Get-CachedJwks {
    param([string]$TenantId)

    $now = [DateTime]::UtcNow

    if ($script:JwksCache -and ($now - $script:JwksCache.FetchedAt) -lt $script:JwksCacheTtl) {
        return $script:JwksCache.Keys
    }

    Write-Host "JIT: refreshing JWKS from Azure AD..."
    $jwks = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/discovery/v2.0/keys" `
                              -Method Get -ErrorAction Stop
    $script:JwksCache = @{ Keys = $jwks.keys; FetchedAt = $now }
    return $jwks.keys
}

#endregion

#region ── JWT Validation ───────────────────────────────────────────────────────────

function ConvertFrom-Base64Url {
    <#
    .SYNOPSIS
        Decodes a Base64Url-encoded string (RFC 4648 §5) to a UTF-8 string.
    #>
    param([string]$Base64Url)

    # Base64Url → Base64: replace URL-safe chars and add padding
    $base64 = $Base64Url -replace '-', '+' -replace '_', '/'
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '='  }
    }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
}

function ConvertFrom-Base64UrlBytes {
    <#
    .SYNOPSIS
        Decodes a Base64Url-encoded string to a byte array (for crypto operations).
    #>
    param([string]$Base64Url)

    $base64 = $Base64Url -replace '-', '+' -replace '_', '/'
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '='  }
    }
    return [Convert]::FromBase64String($base64)
}

function Invoke-JwtValidation {
    <#
    .SYNOPSIS
        Validates an Azure AD JWT bearer token issued for Azure Resource Manager.

    .DESCRIPTION
        Performs full RS256 signature verification against Azure AD's published JWKS,
        then validates expiry, tenant, issuer, and audience.

        The audience must match one of the accepted ARM audiences (defaults cover
        commercial Azure; override via the EXPECTED_AUDIENCES env var for sovereign
        clouds, comma-separated).

        Authorization (the JIT-Requester role check) is performed by the caller
        via Test-CallerHasJitRequesterRole — keep this function focused on
        authentication only.

    .PARAMETER Token
        The raw bearer token string (without the "Bearer " prefix).

    .PARAMETER TenantId
        The expected Azure AD tenant ID.

    .PARAMETER AllowedAudiences
        Optional override for accepted audiences. When omitted, EXPECTED_AUDIENCES
        env var is consulted; falls back to the ARM defaults.

    .OUTPUTS
        The decoded payload PSObject if valid; $null if any validation step fails.
    #>
    param(
        [Parameter(Mandatory)][string]   $Token,
        [Parameter(Mandatory)][string]   $TenantId,
        [string[]]                        $AllowedAudiences
    )

    if (-not $AllowedAudiences -or $AllowedAudiences.Count -eq 0) {
        if ($env:EXPECTED_AUDIENCES) {
            $AllowedAudiences = ($env:EXPECTED_AUDIENCES -split ',') |
                ForEach-Object { $_.Trim() } |
                Where-Object   { $_ }
        }
        if (-not $AllowedAudiences -or $AllowedAudiences.Count -eq 0) {
            $AllowedAudiences = $script:DefaultArmAudiences
        }
    }

    try {
        $parts = $Token.Split('.')
        if ($parts.Count -ne 3) {
            Write-Warning 'JWT: malformed token (expected 3 parts)'
            return $null
        }

        # ── Decode header and payload ─────────────────────────────────────────
        $header  = ConvertFrom-Base64Url $parts[0] | ConvertFrom-Json
        $payload = ConvertFrom-Base64Url $parts[1] | ConvertFrom-Json

        # ── Header: algorithm ────────────────────────────────────────────────
        if ($header.alg -ne 'RS256') {
            Write-Warning "JWT: unsupported algorithm '$($header.alg)' — only RS256 is accepted"
            return $null
        }

        # ── Claim: expiry ─────────────────────────────────────────────────────
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($payload.exp -lt $now) {
            Write-Warning 'JWT: token has expired'
            return $null
        }

        # ── Claim: not before ─────────────────────────────────────────────────
        if ($payload.nbf -and $payload.nbf -gt $now) {
            Write-Warning 'JWT: token not yet valid (nbf in future)'
            return $null
        }

        # ── Claim: tenant ─────────────────────────────────────────────────────
        if ($payload.tid -ne $TenantId) {
            Write-Warning "JWT: tenant mismatch (got '$($payload.tid)')"
            return $null
        }

        # ── Claim: issuer ─────────────────────────────────────────────────────
        $validIssuers = @(
            "https://sts.windows.net/$TenantId/"
            "https://login.microsoftonline.com/$TenantId/v2.0"
        )
        if ($payload.iss -notin $validIssuers) {
            Write-Warning "JWT: untrusted issuer '$($payload.iss)'"
            return $null
        }

        # ── Claim: audience (must match an ARM audience) ─────────────────────
        $audList = @($payload.aud)
        $audOk   = $false
        foreach ($a in $audList) {
            if ($a -in $AllowedAudiences) { $audOk = $true; break }
        }
        if (-not $audOk) {
            Write-Warning "JWT: audience mismatch (got '$($audList -join ', ')')"
            return $null
        }

        # ── Signature: fetch JWKS and verify RS256 ────────────────────────────
        $allKeys  = Get-CachedJwks -TenantId $TenantId
        $jwkKey   = $allKeys | Where-Object { $_.kid -eq $header.kid } | Select-Object -First 1

        # On cache miss, force a refresh and retry once (handles key rotation)
        if (-not $jwkKey) {
            $script:JwksCache = $null
            $allKeys  = Get-CachedJwks -TenantId $TenantId
            $jwkKey   = $allKeys | Where-Object { $_.kid -eq $header.kid } | Select-Object -First 1
        }

        if (-not $jwkKey) {
            Write-Warning "JWT: signing key '$($header.kid)' not found in JWKS"
            return $null
        }

        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsaParams = New-Object System.Security.Cryptography.RSAParameters
        $rsaParams.Modulus  = ConvertFrom-Base64UrlBytes $jwkKey.n
        $rsaParams.Exponent = ConvertFrom-Base64UrlBytes $jwkKey.e
        $rsa.ImportParameters($rsaParams)

        $signingInput  = [System.Text.Encoding]::ASCII.GetBytes("$($parts[0]).$($parts[1])")
        $signatureBytes = ConvertFrom-Base64UrlBytes $parts[2]

        $valid = $rsa.VerifyData(
            $signingInput,
            $signatureBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        if (-not $valid) {
            Write-Warning 'JWT: RS256 signature verification failed'
            return $null
        }

        return $payload
    }
    catch {
        Write-Warning "JWT: validation threw an exception — $_"
        return $null
    }
}

#endregion

#region ── Authorization (custom RBAC role check) ───────────────────────────────────

function Get-JitRequesterRoleDefinitionGuid {
    <#
    .SYNOPSIS
        Resolves the GUID of the 'JIT-Requester' custom RBAC role definition
        within the given subscription. Cached per subscription for the lifetime
        of the worker process (the GUID can differ between subscriptions).
    #>
    param(
        [Parameter(Mandatory)][string] $SubscriptionId
    )

    if ($script:JitRoleDefIdCache.ContainsKey($SubscriptionId)) {
        return $script:JitRoleDefIdCache[$SubscriptionId]
    }

    try {
        $resp = Invoke-ArmRest `
            -Path  "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions" `
            -Query @{ '$filter' = "roleName eq '$script:JitRequesterRoleName'" }

        if (@($resp.value).Count -gt 0) {
            # response.value[].name is the role definition GUID
            $guid = $resp.value[0].name
            $script:JitRoleDefIdCache[$SubscriptionId] = $guid
            return $guid
        }
    }
    catch {
        Write-Warning "JIT: role definition lookup failed for '$script:JitRequesterRoleName' in sub $SubscriptionId — $_"
    }

    return $null
}

function Test-CallerHasJitRequesterRole {
    <#
    .SYNOPSIS
        Returns $true if the caller (identified by AAD objectId) has an active
        assignment of the custom 'JIT-Requester' role within the given target
        subscription (at the /subscriptions/<id> scope, inherited from a parent
        management group, or on a child resource group / resource in it).

    .DESCRIPTION
        Uses the function app's managed identity to query ARM for role
        assignments via the assignedTo() filter at the TARGET subscription
        scope. The caller must hold 'JIT-Requester' in the subscription they
        are operating on — this is the subscription the request targets, NOT
        the function app's own host subscription.

        Decisions are cached per (callerObjectId, subscriptionId) for
        60 seconds — long enough to absorb a burst of calls in a single
        grant/revoke flow, short enough that role assignments and
        revocations take effect within ~1 minute without a restart.
    #>
    param(
        [Parameter(Mandatory)][string] $CallerObjectId,
        [Parameter(Mandatory)][string] $SubscriptionId
    )

    $cacheKey = "$CallerObjectId|$SubscriptionId"
    $now      = [DateTime]::UtcNow

    if ($script:RoleCheckCache.ContainsKey($cacheKey) -and
        ($now - $script:RoleCheckCache[$cacheKey].At) -lt $script:RoleCheckCacheTtl) {
        return $script:RoleCheckCache[$cacheKey].Allowed
    }

    # Breadcrumb so we can confirm this code is loaded and being invoked.
    # Logged as Information so it definitely flows through to Function logs.
    Write-Host "JIT-AUTH: checking caller $CallerObjectId in subscription $SubscriptionId for role '$script:JitRequesterRoleName'."

    $allowed = $false
    try {
        $roleDefGuid = Get-JitRequesterRoleDefinitionGuid -SubscriptionId $SubscriptionId

        if (-not $roleDefGuid) {
            Write-Host "JIT-AUTH: role '$script:JitRequesterRoleName' not found in sub $SubscriptionId — DENIED."
        }
        else {
            $scope = "/subscriptions/$SubscriptionId"
            # NB: ARM's assignedTo() takes a bare GUID. The Microsoft docs
            # render the placeholder as "{principalId}" — that's
            # documentation punctuation; wrapping in braces returns 0 results.
            Write-Host "JIT-AUTH: querying roleAssignments at $scope with assignedTo('$CallerObjectId')"
            # Follow nextLink so a matching assignment on a later page isn't
            # missed (ARM paginates roleAssignments).
            $assignments = @()
            $nextUrl     = "$scope/providers/Microsoft.Authorization/roleAssignments"
            $firstPage   = $true
            do {
                $resp = if ($firstPage) {
                    Invoke-ArmRest -Path $nextUrl -Query @{ '$filter' = "assignedTo('$CallerObjectId')" }
                } else {
                    Invoke-ArmRest -Path $nextUrl   # nextLink is absolute; carries $filter + api-version
                }
                $firstPage    = $false
                $assignments += @($resp.value)
                $nextUrl      = $resp.nextLink
            } while ($nextUrl)
            $assignmentSummary = if ($assignments.Count -eq 0) {
                '(none found via assignedTo)'
            } else {
                ($assignments | ForEach-Object {
                    "$(($_.properties.roleDefinitionId -split '/')[-1])@$($_.properties.scope)"
                }) -join '; '
            }
            Write-Host "JIT-AUTH: looked for role-def GUID $roleDefGuid; ARM returned $($assignments.Count) assignment(s): $assignmentSummary"

            foreach ($a in $assignments) {
                $assignedGuid = ($a.properties.roleDefinitionId -split '/')[-1]
                if ($assignedGuid -eq $roleDefGuid) { $allowed = $true; break }
            }

            Write-Host "JIT-AUTH: result for $CallerObjectId — $(if ($allowed) { 'ALLOWED' } else { 'DENIED' })"
        }
    }
    catch {
        Write-Warning "JIT: role check failed for $CallerObjectId — $_"
    }

    $script:RoleCheckCache[$cacheKey] = @{ Allowed = $allowed; At = $now }
    return $allowed
}

#endregion

#region ── Runtime Configuration Derivation ─────────────────────────────────────────
# Zero-config: each of these values is derived at runtime from platform-injected
# env vars (or IMDS / the MI token) so the function app deploys with no operational
# configuration. In every case an explicit App Setting (env var) WINS when set,
# so any derived value can still be overridden after deployment.

# Per-worker caches — the derived values don't change during a worker's lifetime.
$script:DerivedSubscriptionId = $null
$script:DerivedTenantId       = $null

function Get-JitInstanceMetadata {
    <#
    .SYNOPSIS
        Queries the Azure Instance Metadata Service (IMDS) compute block.
        Best-effort — returns $null if IMDS is unreachable (it is not always
        available on App Service / Functions plans).
    #>
    try {
        $resp = Invoke-RestMethod -Method Get `
            -Uri 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' `
            -Headers @{ Metadata = 'true' } -TimeoutSec 5 -ErrorAction Stop
        return $resp.compute
    }
    catch {
        Write-Warning "JIT: IMDS query failed — $_"
        return $null
    }
}

function Get-JitSubscriptionId {
    <#
    .SYNOPSIS
        Returns the function app's own (host) subscription id.
        ENV JIT_SUBSCRIPTION_ID wins; else parsed from WEBSITE_OWNER_NAME
        (format "<subId>+<rg>-<region>webspace"); else from IMDS.
    #>
    if ($env:JIT_SUBSCRIPTION_ID)    { return $env:JIT_SUBSCRIPTION_ID }
    if ($script:DerivedSubscriptionId) { return $script:DerivedSubscriptionId }

    if ($env:WEBSITE_OWNER_NAME) {
        $subId = ($env:WEBSITE_OWNER_NAME -split '\+')[0]
        if ($subId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            $script:DerivedSubscriptionId = $subId
            return $subId
        }
    }

    $compute = Get-JitInstanceMetadata
    if ($compute -and $compute.subscriptionId) {
        $script:DerivedSubscriptionId = $compute.subscriptionId
        return $script:DerivedSubscriptionId
    }

    return $null
}

function Get-JitResourceGroup {
    <#
    .SYNOPSIS
        Returns the function app's resource group. ENV JIT_RESOURCE_GROUP wins;
        else the platform-injected WEBSITE_RESOURCE_GROUP.
    #>
    if ($env:JIT_RESOURCE_GROUP) { return $env:JIT_RESOURCE_GROUP }
    return $env:WEBSITE_RESOURCE_GROUP
}

function Get-JitSiteName {
    <#
    .SYNOPSIS
        Returns the function app's site name. ENV JIT_SITE_NAME wins; else the
        platform-injected WEBSITE_SITE_NAME.
    #>
    if ($env:JIT_SITE_NAME) { return $env:JIT_SITE_NAME }
    return $env:WEBSITE_SITE_NAME
}

function Get-JitSiteResourceId {
    <#
    .SYNOPSIS
        Returns the function app's own site resource id. ENV JIT_SITE_RESOURCE_ID
        wins; else built from the derived subscription id, resource group, and
        site name.
    #>
    if ($env:JIT_SITE_RESOURCE_ID) { return $env:JIT_SITE_RESOURCE_ID }

    $subId    = Get-JitSubscriptionId
    $rg       = Get-JitResourceGroup
    $siteName = Get-JitSiteName
    if ($subId -and $rg -and $siteName) {
        return "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Web/sites/$siteName"
    }
    return $null
}

function Get-JitTenantId {
    <#
    .SYNOPSIS
        Returns the function app's home tenant id. ENV AZURE_TENANT_ID wins;
        else decoded from the MI ARM token's 'tid' claim; else from IMDS.
    #>
    if ($env:AZURE_TENANT_ID)   { return $env:AZURE_TENANT_ID }
    if ($script:DerivedTenantId) { return $script:DerivedTenantId }

    # Decode the tid claim from the MI's own ARM token.
    try {
        $token = Get-ManagedIdentityToken -Resource 'https://management.azure.com/'
        $parts = $token.Split('.')
        if ($parts.Count -ge 2) {
            $payload = ConvertFrom-Base64Url $parts[1] | ConvertFrom-Json
            if ($payload.tid) {
                $script:DerivedTenantId = $payload.tid
                return $payload.tid
            }
        }
    }
    catch {
        Write-Warning "JIT: could not derive tenant id from MI token — $_"
    }

    # Best-effort fallback: IMDS (compute.tenantId is not populated on all plans).
    $compute = Get-JitInstanceMetadata
    if ($compute -and $compute.tenantId) {
        $script:DerivedTenantId = $compute.tenantId
        return $script:DerivedTenantId
    }

    return $null
}

#endregion

#region ── Audit Logging ───────────────────────────────────────────────────────────────

function Write-JITAuditEvent {
    <#
    .SYNOPSIS
        Writes a structured JSON audit event to stdout (surfaced in the function app's
        standard logs — Log stream, Kudu, az functionapp log tail).
        All JIT-AzAccess decisions — grants, denials, and expirations — flow through here.
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('JITGranted','JITDenied','JITExpired','JITRemoveFailed','JITRevoked')]
        [string]$EventType,

        [string]$Caller,
        [string]$CallerIp,
        [string]$TargetType,
        [string]$ResourceName,
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$RuleId,
        [string]$DenyReason,
        [hashtable]$Extra = @{}
    )

    $auditEntry = @{
        auditEvent     = $EventType
        timestamp      = [DateTime]::UtcNow.ToString('o')
        caller         = $Caller
        callerIp       = $CallerIp
        targetType     = $TargetType
        resourceName   = $ResourceName
        resourceGroup  = $ResourceGroup
        subscriptionId = $SubscriptionId
        ruleId         = $RuleId
        denyReason     = $DenyReason
    }
    foreach ($k in $Extra.Keys) { $auditEntry[$k] = $Extra[$k] }

    Write-Host ($auditEntry | ConvertTo-Json -Compress)
}

#endregion

#region ── NSG Helpers ───────────────────────────────────────────────────────────────
function Get-AvailableNsgPriority {
    <#
    .SYNOPSIS
        Returns the lowest unused inbound rule priority in the given range.
        Raises an error if no priority is available.
    #>
    param(
        [Parameter(Mandatory)]
        $Nsg,
        [int]$Min = 1000,
        [int]$Max = 3900
    )

    $used = $Nsg.SecurityRules |
        Where-Object { $_.Direction -eq 'Inbound' -and $_.Priority -ge $Min -and $_.Priority -le $Max } |
        Select-Object -ExpandProperty Priority

    for ($p = $Min; $p -le $Max; $p += 10) {
        if ($p -notin $used) { return $p }
    }

    throw "No available NSG rule priority in range [$Min, $Max]. Remove some existing JIT rules first."
}

#endregion

#region ── Distributed Lock (Blob Lease) ──────────────────────────────────────────────────

function Invoke-WithBlobLock {
    <#
    .SYNOPSIS
        Executes a script block while holding an Azure Blob Storage lease as a
        distributed mutex. Up to $RetryCount attempts spaced $RetryDelayMs apart.

        Use this before any read-modify-write operation on a shared resource
        (e.g. NSG priority assignment) to prevent simultaneous callers from
        colliding.
    #>
    param(
        [Parameter(Mandatory)][string]      $LockName,
        [Parameter(Mandatory)][scriptblock] $Action,
        [int]$LeaseDurationSeconds = 60,
        [int]$RetryCount           = 10,
        [int]$RetryDelayMs         = 500
    )

    $containerName = 'jit-locks'

    # Ensure container exists (idempotent).
    New-Container -Container $containerName

    # Ensure lock blob exists. Use If-None-Match: * so PUT only creates when
    # absent — avoids racing against an active lease which forbids overwrites.
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes('lock')
        Invoke-BlobRest -Method PUT -Container $containerName -Blob $LockName `
            -BodyBytes $bytes -ContentType 'application/octet-stream' `
            -ExtraHeaders @{ 'x-ms-blob-type' = 'BlockBlob'; 'If-None-Match' = '*' } | Out-Null
    } catch {
        # 409/412 means the blob already exists — that's fine, we just want to lease it.
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($status -ne 409 -and $status -ne 412) { throw }
    }

    # Acquire lease (POST ?comp=lease with x-ms-lease-action: acquire).
    $leaseId = $null
    for ($i = 0; $i -lt $RetryCount; $i++) {
        try {
            $headers = @{
                'x-ms-lease-action'   = 'acquire'
                'x-ms-lease-duration' = "$LeaseDurationSeconds"
            }
            $resp = Invoke-WebRequest -Method PUT `
                -Uri ((Get-LockBlobUri $containerName $LockName) + '?comp=lease') `
                -Headers (New-LeaseHeaders -ResourcePath "/$containerName/$LockName" `
                                           -Query 'comp=lease' `
                                           -ExtraHeaders $headers) `
                -ErrorAction Stop
            $leaseId = $resp.Headers['x-ms-lease-id']
            if ($leaseId -is [array]) { $leaseId = $leaseId[0] }
            break
        }
        catch {
            if ($i -eq ($RetryCount - 1)) {
                throw "Could not acquire lock '$LockName' after $RetryCount attempts: $_"
            }
            Start-Sleep -Milliseconds $RetryDelayMs
        }
    }

    $actionResult = $null
    try {
        # Capture and return the action's output. The scriptblock runs in a
        # child scope, so a caller relying on `$x = ...` *inside* the block
        # would lose it; callers must use `$x = Invoke-WithBlobLock -Action {...}`.
        $actionResult = & $Action
    }
    finally {
        # Release lease.
        try {
            $headers = @{
                'x-ms-lease-action' = 'release'
                'x-ms-lease-id'     = $leaseId
            }
            Invoke-WebRequest -Method PUT `
                -Uri ((Get-LockBlobUri $containerName $LockName) + '?comp=lease') `
                -Headers (New-LeaseHeaders -ResourcePath "/$containerName/$LockName" `
                                           -Query 'comp=lease' `
                                           -ExtraHeaders $headers) `
                -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Warning "Failed to release blob lease '$LockName': $_"
        }
    }

    return $actionResult
}

# Minimal helpers for the lease ops (which need direct Invoke-WebRequest to
# read response headers for the lease id).
function script:Get-LockBlobUri {
    param([string]$Container, [string]$Blob)
    $sp = & (Get-Module HttpHelpers) { Get-StorageParts }
    return "https://$($sp.Account).blob.$($sp.Suffix)/$Container/$Blob"
}
function script:New-LeaseHeaders {
    param([string]$ResourcePath, [string]$Query, [hashtable]$ExtraHeaders)
    $date = [DateTime]::UtcNow.ToString('R')
    $headers = @{ 'x-ms-version' = '2021-12-02'; 'x-ms-date' = $date }
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }

    $sp = & (Get-Module HttpHelpers) { Get-StorageParts }

    # CanonicalResource must use the Blob recipe: the query param goes on its
    # own "comp:lease" line, NOT the literal "?comp=lease" (that's the Table
    # form). Reuse the same helper Invoke-BlobRest uses so the two can't drift.
    $canResource = & (Get-Module HttpHelpers) {
        param($A, $P, $Q) Get-BlobCanonicalResource -Account $A -Path $P -Query $Q
    } $sp.Account $ResourcePath $Query

    $sig = & (Get-Module HttpHelpers) {
        param($M, $C, $H, $L, $T) New-SharedKeySignature -Method $M -CanonicalResource $C -Headers $H -ContentLength $L -ContentType $T
    } 'PUT' $canResource $headers 0 ''
    $headers.Authorization = $sig
    return $headers
}

#endregion

#region ── Table Storage Helpers ──────────────────────────────────────────────

function Get-JITTableName {
    <#
    .SYNOPSIS
        Returns the name of the JIT rules table, creating it via Table REST
        if it does not yet exist. Replaces the Az.Storage/AzTable cmdlets.
    #>
    param([Parameter(Mandatory)][string]$TableName)

    # Ensure the table exists (POST /Tables, idempotent against 409).
    try {
        Invoke-TableRest -Method POST -Path '/Tables' -Body @{ TableName = $TableName } | Out-Null
    } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($status -ne 409) { throw }  # 409 = already exists
    }
    return $TableName
}

function Get-JITTableRows {
    <#
    .SYNOPSIS
        Reads rows from a Table Storage table. Optional OData $filter.
    #>
    param(
        [Parameter(Mandatory)][string]$TableName,
        [string]$Filter = ''
    )
    $query = if ($Filter) { '$filter=' + [Uri]::EscapeDataString($Filter) } else { '' }
    $resp  = Invoke-TableRest -Method GET -Path "/$TableName()" -Query $query
    return @($resp.value)
}

function Add-JITTableRow {
    <#
    .SYNOPSIS
        Inserts a row into a Table Storage table.
        Properties must include PartitionKey and RowKey.
    #>
    param(
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][hashtable]$Properties
    )
    Invoke-TableRest -Method POST -Path "/$TableName" -Body $Properties | Out-Null
}

function Remove-JITTableRow {
    <#
    .SYNOPSIS
        Deletes a row from a Table Storage table.
    #>
    param(
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$PartitionKey,
        [Parameter(Mandatory)][string]$RowKey
    )
    $pk   = [Uri]::EscapeDataString($PartitionKey)
    $rk   = [Uri]::EscapeDataString($RowKey)
    Invoke-TableRest -Method DELETE -Path "/$TableName(PartitionKey='$pk',RowKey='$rk')" `
        -ExtraHeaders @{ 'If-Match' = '*' } | Out-Null
}

#endregion

#region ── Caller IP ──────────────────────────────────────────────────────────

function Get-CallerIp {
    <#
    .SYNOPSIS
        Extracts the caller's public IP from the request. Azure injects the real
        client IP into X-Forwarded-For (leftmost entry is the originating IP);
        entries may be "ip:port" (IPv4), "[ipv6]:port", or bare. Falls back to
        the socket remote address. Shared by Request-JITAccess (to write the
        firewall rule) and Get-JITRules (to report the IP back to the client),
        so both agree on exactly which IP a grant would use.
    #>
    param([Parameter(Mandatory)]$Request)

    $xff = $Request.Headers['X-Forwarded-For']
    if ($xff) {
        $first = ($xff.ToString() -split ',')[0].Trim()
        if ($first -match '^\[(.+)\]:\d+$')                  { return $matches[1] }  # [ipv6]:port
        if ($first -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$')   { return $matches[1] }  # ipv4:port
        return $first                                                                # bare ip
    }

    return $Request.HttpContext.Connection.RemoteIpAddress.ToString()
}

#endregion

Export-ModuleMember -Function @(
    'Invoke-JwtValidation'
    'Test-CallerHasJitRequesterRole'
    'Get-JitSubscriptionId'
    'Get-JitResourceGroup'
    'Get-JitSiteName'
    'Get-JitSiteResourceId'
    'Get-JitTenantId'
    'Write-JITAuditEvent'
    'Get-AvailableNsgPriority'
    'Invoke-WithBlobLock'
    'Get-JITTableName'
    'Get-JITTableRows'
    'Add-JITTableRow'
    'Remove-JITTableRow'
    'Get-CallerIp'
)
