# JITHelpers.psm1 — shared helpers for the JIT NSG function app.

#region ── JWKS Cache ───────────────────────────────────────────────────────────────
# Module-scoped variables persist within a worker process lifetime,
# giving us an in-memory JWKS cache that survives across invocations.
$script:JwksCache    = $null   # { Keys: [...], FetchedAt: [DateTime] }
$script:JwksCacheTtl = [TimeSpan]::FromHours(1)

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
        Validates an Azure AD JWT bearer token.

    .DESCRIPTION
        Performs full RS256 signature verification against Azure AD's published JWKS,
        then validates the standard claims: expiry, tenant, issuer, audience, and
        whether the calling app's client ID is in the approved list.

    .PARAMETER Token
        The raw bearer token string (without the "Bearer " prefix).

    .PARAMETER TenantId
        The expected Azure AD tenant ID.

    .PARAMETER Audience
        The expected 'aud' claim (typically api://<functionAppClientId>).

    .PARAMETER AllowedClientIds
        Array of Azure AD client IDs (appid claim) that are permitted callers.

    .OUTPUTS
        The decoded payload PSObject if valid; $null if any validation step fails.
    #>
    param(
        [Parameter(Mandatory)][string]   $Token,
        [Parameter(Mandatory)][string]   $TenantId,
        [Parameter(Mandatory)][string]   $Audience,
        [Parameter(Mandatory)][string[]] $AllowedClientIds
    )

    try {
        $parts = $Token.Split('.')
        if ($parts.Count -ne 3) {
            Write-Warning 'JWT: malformed token (expected 3 parts)'
            return $null
        }

        # ── Decode header and payload ─────────────────────────────────────────
        $header  = ConvertFrom-Base64Url $parts[0] | ConvertFrom-Json
        $payload = ConvertFrom-Base64Url $parts[1] | ConvertFrom-Json

        # ── Claim: expiry ─────────────────────────────────────────────────────
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($payload.exp -lt $now) {
            Write-Warning 'JWT: token has expired'
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

        # ── Claim: audience ───────────────────────────────────────────────────
        $audList = @($payload.aud)
        if ($Audience -notin $audList) {
            Write-Warning "JWT: audience mismatch (expected '$Audience', got '$($audList -join ', ')')"
            return $null
        }

        # ── Claim: approved calling app ───────────────────────────────────────
        $callerAppId = if ($payload.appid) { $payload.appid } else { $payload.azp }
        if ($callerAppId -notin $AllowedClientIds) {
            Write-Warning "JWT: appid '$callerAppId' is not in the approved list"
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

#region ── Audit Logging ───────────────────────────────────────────────────────────────

function Write-JITAuditEvent {
    <#
    .SYNOPSIS
        Writes a structured JSON audit event to stdout (picked up by Application Insights).
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

    $event = @{
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
    foreach ($k in $Extra.Keys) { $event[$k] = $Extra[$k] }

    Write-Host ($event | ConvertTo-Json -Compress)
}

#endregion

#region ── NSG Helpers ───────────────────────────────────────────────────────────────
    <#
    .SYNOPSIS
        Returns the lowest unused inbound rule priority in the given range.
        Raises an error if no priority is available.
    #>
    param(
        [Parameter(Mandatory)]
        [Microsoft.Azure.Commands.Network.Models.PSNetworkSecurityGroup]$Nsg,
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
    $ctx           = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage

    # Ensure container exists (idempotent)
    if (-not (Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue)) {
        New-AzStorageContainer -Name $containerName -Context $ctx -Permission Off | Out-Null
    }

    # Ensure lock blob exists (content irrelevant; just needs to be a leasable blob)
    $tmpFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmpFile, 'lock')
        Set-AzStorageBlobContent -Container $containerName -Blob $LockName -File $tmpFile `
            -Context $ctx -Force -ErrorAction SilentlyContinue | Out-Null
    }
    finally { Remove-Item $tmpFile -ErrorAction SilentlyContinue }

    # Try to acquire a lease, retrying on conflict
    $leaseId = $null
    for ($i = 0; $i -lt $RetryCount; $i++) {
        try {
            $blob    = Get-AzStorageBlob -Container $containerName -Blob $LockName -Context $ctx
            $leaseId = $blob.ICloudBlob.AcquireLease(
                [nullable[TimeSpan]]([TimeSpan]::FromSeconds($LeaseDurationSeconds)), $null)
            break
        }
        catch {
            if ($i -eq ($RetryCount - 1)) {
                throw "Could not acquire lock '$LockName' after $RetryCount attempts: $_"
            }
            Start-Sleep -Milliseconds $RetryDelayMs
        }
    }

    try {
        & $Action
    }
    finally {
        try {
            $blob = Get-AzStorageBlob -Container $containerName -Blob $LockName -Context $ctx
            $condition = [Microsoft.Azure.Storage.AccessCondition]::GenerateLeaseCondition($leaseId)
            $blob.ICloudBlob.ReleaseLease($condition)
        }
        catch {
            Write-Warning "Failed to release blob lease '$LockName': $_"
        }
    }
}

#endregion

#region ── Table Storage Helpers ──────────────────────────────────────────────

function Get-JITCloudTable {
    <#
    .SYNOPSIS
        Returns the AzTable CloudTable object for the JIT rules table,
        creating the table if it does not already exist.
    #>
    param([string]$TableName)

    $ctx   = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage
    $table = Get-AzStorageTable -Name $TableName -Context $ctx -ErrorAction SilentlyContinue

    if (-not $table) {
        Write-Host "Creating JIT rules table '$TableName'..."
        $table = New-AzStorageTable -Name $TableName -Context $ctx
    }

    return $table.CloudTable
}

#endregion

#region ── Target Manifest (Blob Storage) ─────────────────────────────────────

function Get-JITTargetManifest {
    <#
    .SYNOPSIS
        Reads the JIT target manifest from jit-config/targets.json in the
        AzureWebJobsStorage account.  Returns an empty array if the blob
        does not yet exist.  This is the server-of-record for which resources
        are available in the plugin's browse list.
    #>
    $containerName = 'jit-config'
    $blobName      = 'targets.json'
    $ctx           = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage

    # Create container if it doesn't exist (idempotent, private access)
    if (-not (Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue)) {
        New-AzStorageContainer -Name $containerName -Context $ctx -Permission Off | Out-Null
    }

    $blob = Get-AzStorageBlob -Container $containerName -Blob $blobName `
                -Context $ctx -ErrorAction SilentlyContinue

    if (-not $blob) {
        Write-Host "JIT: target manifest blob '$containerName/$blobName' not found — returning empty list."
        return @()
    }

    $tmpFile = [System.IO.Path]::GetTempFileName()
    try {
        Get-AzStorageBlobContent -Container $containerName -Blob $blobName `
            -Destination $tmpFile -Context $ctx -Force | Out-Null
        $json = Get-Content -Path $tmpFile -Raw -Encoding UTF8
        return ($json | ConvertFrom-Json)
    }
    finally {
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
    }
}

#endregion

Export-ModuleMember -Function @(
    'Invoke-JwtValidation'
    'Write-JITAuditEvent'
    'Get-AvailableNsgPriority'
    'Invoke-WithBlobLock'
    'Get-JITCloudTable'
    'Get-JITTargetManifest'
)
