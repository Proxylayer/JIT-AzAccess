# HttpHelpers.psm1 — REST helpers used by the JIT function app.
#
# This module exists so the function app needs ZERO Az PowerShell modules at
# runtime. All Azure ops go through Invoke-RestMethod with the function app's
# managed identity (via IDENTITY_ENDPOINT), which issues Bearer tokens for
# three audiences: ARM, Microsoft Graph, and — since the storage migration
# below — the Storage data plane.
#
# Dropping Az.* drops ~400MB of resident memory and ~5s of cold-start time.
#
# ── STORAGE AUTH: Entra ID only, never account keys ───────────────────────────
# Storage data-plane calls (blob, table) authenticate with the function app's
# managed identity — a token for https://storage.azure.com/ passed as a plain
# Bearer header. There is NO account-key code path in this module, deliberately
# and permanently. Do not reintroduce one.
#
# Two reasons, either sufficient on its own:
#
#   1. It cannot work. A subscription-scope Azure Policy ("Storage accounts
#      authenticate with Entra ID, not account keys") applies a Modify effect
#      that forces allowSharedKeyAccess = false and silently reverts any attempt
#      to set it back — including from this repo's own ARM template. Shared Key
#      requests return 403 KeyBasedAuthenticationNotPermitted, always.
#
#   2. It failed silently for eight days. When that policy landed on
#      2026-08-21 the entire app went dark and nobody noticed: Get-JITRules
#      returned 500, Request-JITAccess fail-closed to 503, and the
#      Remove-ExpiredRules timer stopped firing, so expired JIT grants were
#      never revoked. A key path that "works in some environments" is worse
#      than none, because it turns a hard failure into a quiet one.
#
# This requires DATA-plane RBAC on the storage account — Storage Blob Data
# Owner, Storage Table Data Contributor, Storage Queue Data Contributor.
# Control-plane roles (Owner, Contributor) grant none of it. Deploy.ps1 step 1b
# assigns them; the host's own AzureWebJobsStorage__accountName setting relies
# on exactly the same grants.

#region ── Per-worker caches ────────────────────────────────────────────────────

# Cache of MI tokens by resource URI. Tokens are good for ~1 hour; we
# refresh 5 minutes early to be safe.
$script:MiTokenCache = @{}

# Parsed AzureWebJobsStorage connection string parts. Resolved once.
$script:StorageParts = $null

#endregion

#region ── Managed identity token ───────────────────────────────────────────────

function Get-ManagedIdentityToken {
    <#
    .SYNOPSIS
        Returns a Bearer token for the function app's system-assigned managed
        identity, scoped to the given resource (audience).

    .PARAMETER Resource
        The token audience — e.g. 'https://management.azure.com/' for ARM,
        'https://graph.microsoft.com/' for Microsoft Graph.
    #>
    param(
        [Parameter(Mandatory)][string] $Resource
    )

    $now    = [DateTime]::UtcNow
    $cached = $script:MiTokenCache[$Resource]
    if ($cached -and ($cached.ExpiresUtc - $now).TotalMinutes -gt 5) {
        return $cached.Token
    }

    $endpoint = $env:IDENTITY_ENDPOINT
    $header   = $env:IDENTITY_HEADER
    if (-not $endpoint -or -not $header) {
        throw "IDENTITY_ENDPOINT / IDENTITY_HEADER env vars are missing. " +
              "Is the system-assigned managed identity enabled on this function app?"
    }

    $uri = "{0}?resource={1}&api-version=2019-08-01" -f $endpoint, [Uri]::EscapeDataString($Resource)
    $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $header } -ErrorAction Stop

    # MI endpoint returns expires_on as Unix seconds (string).
    $expSec = [int64]$resp.expires_on
    $expUtc = [DateTimeOffset]::FromUnixTimeSeconds($expSec).UtcDateTime

    $script:MiTokenCache[$Resource] = @{ Token = $resp.access_token; ExpiresUtc = $expUtc }
    return $resp.access_token
}

#endregion

#region ── ARM REST ──────────────────────────────────────────────────────────────

function Invoke-ArmRest {
    <#
    .SYNOPSIS
        Calls ARM with the MI's Bearer token. Appends api-version to the URL
        if not already present.

    .PARAMETER Path
        Either an absolute URL (https://management.azure.com/...) or a path
        starting with "/subscriptions/..." which gets prefixed with the ARM host.

    .PARAMETER ApiVersion
        Defaults to "2022-04-01". Pass a per-resource api-version when needed.

    .PARAMETER Body
        Either a hashtable (will be JSON-serialized) or a pre-serialized string.

    .PARAMETER Query
        Optional hashtable of additional query parameters appended to the URL.
    #>
    param(
        [Parameter(Mandatory)][string] $Path,
        [string]    $Method     = 'GET',
        [string]    $ApiVersion = '2022-04-01',
        $Body                   = $null,
        [hashtable] $Query      = @{}
    )

    $token = Get-ManagedIdentityToken -Resource 'https://management.azure.com/'

    $uri = if ($Path -like 'http*') { $Path } else { "https://management.azure.com$Path" }

    # Build query string
    $qs = @()
    if ($uri -notmatch 'api-version=') { $qs += "api-version=$ApiVersion" }
    foreach ($k in $Query.Keys) {
        # `$filter` is the most common one — caller passes literal "`$filter" or "%24filter"
        $qs += ("{0}={1}" -f [Uri]::EscapeDataString($k), [Uri]::EscapeDataString([string]$Query[$k]))
    }
    if ($qs.Count -gt 0) {
        $sep = if ($uri.Contains('?')) { '&' } else { '?' }
        $uri = "$uri$sep$($qs -join '&')"
    }

    $params = @{
        Method  = $Method
        Uri     = $uri
        Headers = @{ Authorization = "Bearer $token" }
    }
    if ($null -ne $Body) {
        $params.ContentType = 'application/json'
        $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
    }

    Invoke-RestMethod @params -ErrorAction Stop
}

function Invoke-ArmRestRaw {
    <#
    .SYNOPSIS
        Same request shape as Invoke-ArmRest, but returns the raw HTTP response
        so callers can inspect the status code and response headers. Needed for
        asynchronous (long-running) ARM operations that reply 202 Accepted with
        `Azure-AsyncOperation` / `Location` / `Retry-After` headers that must be
        polled to completion — information Invoke-RestMethod discards.

        Returns a hashtable:
            @{ StatusCode = <int>; Headers = <hashtable>; Content = <string> }

    .PARAMETER Path
        Either an absolute URL (https://management.azure.com/...) or a path
        starting with "/subscriptions/..." which gets prefixed with the ARM host.
        Async-operation poll URLs from a 202 response are absolute and pass
        through unchanged.

    .PARAMETER ApiVersion
        Defaults to "2022-04-01". Pass a per-resource api-version when needed.
        Ignored when the URL already carries an api-version (e.g. LRO poll URLs).

    .PARAMETER Body
        Either a hashtable (will be JSON-serialized) or a pre-serialized string.

    .PARAMETER Query
        Optional hashtable of additional query parameters appended to the URL.

    .PARAMETER ExtraHeaders
        Optional hashtable of additional request headers merged over the
        Authorization header. Used for conditional writes — the ETag
        read-modify-write helper sends `If-Match` here to get optimistic
        concurrency (a stale write fails 412 instead of clobbering).
    #>
    param(
        [Parameter(Mandatory)][string] $Path,
        [string]    $Method       = 'GET',
        [string]    $ApiVersion   = '2022-04-01',
        $Body                     = $null,
        [hashtable] $Query        = @{},
        [hashtable] $ExtraHeaders = @{}
    )

    $token = Get-ManagedIdentityToken -Resource 'https://management.azure.com/'

    $uri = if ($Path -like 'http*') { $Path } else { "https://management.azure.com$Path" }

    $qs = @()
    if ($uri -notmatch 'api-version=') { $qs += "api-version=$ApiVersion" }
    foreach ($k in $Query.Keys) {
        $qs += ("{0}={1}" -f [Uri]::EscapeDataString($k), [Uri]::EscapeDataString([string]$Query[$k]))
    }
    if ($qs.Count -gt 0) {
        $sep = if ($uri.Contains('?')) { '&' } else { '?' }
        $uri = "$uri$sep$($qs -join '&')"
    }

    $reqHeaders = @{ Authorization = "Bearer $token" }
    foreach ($k in $ExtraHeaders.Keys) { $reqHeaders[$k] = $ExtraHeaders[$k] }

    $params = @{
        Method  = $Method
        Uri     = $uri
        Headers = $reqHeaders
    }
    if ($null -ne $Body) {
        $params.ContentType = 'application/json'
        $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
    }

    # Invoke-WebRequest (unlike Invoke-RestMethod) surfaces StatusCode and the
    # full response Headers. A non-2xx still throws (caught by callers via
    # Get-StatusFromError), preserving the existing 404-swallow behavior.
    $resp = Invoke-WebRequest @params -ErrorAction Stop

    # Normalize headers into a plain hashtable of single string values. PS7's
    # response headers are string[]; collapse arrays to a comma-joined string.
    $headers = @{}
    if ($resp.Headers) {
        foreach ($h in $resp.Headers.GetEnumerator()) {
            $val = $h.Value
            if ($val -is [System.Array]) { $val = ($val -join ',') }
            $headers[[string]$h.Key] = [string]$val
        }
    }

    return @{
        StatusCode = [int]$resp.StatusCode
        Headers    = $headers
        Content    = [string]$resp.Content
    }
}

#endregion

#region ── Storage shared-key signing ───────────────────────────────────────────

function script:Get-StorageParts {
    <#
        Resolves the storage account this app uses for the rules table, the
        audit table, and the NSG lock blobs.

        Only the account NAME is resolved. Any AccountKey present in a legacy
        AzureWebJobsStorage connection string is deliberately ignored and never
        read — see the module header. Authentication is Entra ID only.

        Name resolution, first match wins:
          1. JIT_STORAGE_ACCOUNT          — explicit override
          2. AzureWebJobsStorage__accountName — identity-based host connection
          3. AccountName=… inside AzureWebJobsStorage — legacy connection string
    #>
    if ($script:StorageParts) { return $script:StorageParts }

    $cs    = $env:AzureWebJobsStorage
    $parts = @{}
    if ($cs) {
        foreach ($pair in $cs -split ';') {
            if ($pair -match '^([^=]+)=(.*)$') { $parts[$matches[1]] = $matches[2] }
        }
    }

    $account =
        if     ($env:JIT_STORAGE_ACCOUNT)              { $env:JIT_STORAGE_ACCOUNT }
        elseif ($env:AzureWebJobsStorage__accountName) { $env:AzureWebJobsStorage__accountName }
        else                                           { $parts.AccountName }

    if (-not $account) {
        throw "Could not determine the storage account name. Set JIT_STORAGE_ACCOUNT, " +
              "AzureWebJobsStorage__accountName, or an AzureWebJobsStorage connection string " +
              "containing AccountName."
    }

    $script:StorageParts = @{
        Account = $account
        Suffix  = if ($parts.EndpointSuffix) { $parts.EndpointSuffix } else { 'core.windows.net' }
    }
    return $script:StorageParts
}

function script:Get-StorageAuthHeader {
    <#
    .SYNOPSIS
        Returns the Authorization header for one Storage data-plane request:
        always a managed-identity Bearer token, never an account-key signature.

    .DESCRIPTION
        Every storage caller routes through here — Invoke-BlobRest,
        Invoke-TableRest, and the blob-lease path in JITHelpers that builds its
        own headers to read the lease id off the response — so no caller can
        drift onto a different auth scheme.

        Tokens are cached per audience by Get-ManagedIdentityToken and refreshed
        five minutes before expiry, so calling this per request is cheap.
    #>
    return "Bearer $(Get-ManagedIdentityToken -Resource 'https://storage.azure.com/')"
}

#endregion

#region ── Blob REST ────────────────────────────────────────────────────────────

function Invoke-BlobRest {
    <#
    .SYNOPSIS
        Calls Azure Blob Storage, authenticated per Get-StorageAuthHeader
        (managed identity by default). Used for the distributed lock blob lease.
    #>
    param(
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $Container,
        [string]    $Blob       = '',
        [string]    $Query      = '',       # e.g. "comp=lease" — appended after path
        [byte[]]    $BodyBytes  = $null,
        [string]    $ContentType = '',
        [hashtable] $ExtraHeaders = @{}
    )

    $sp   = Get-StorageParts
    $date = [DateTime]::UtcNow.ToString('R')   # RFC 1123

    $path = if ($Blob) { "/$Container/$Blob" } else { "/$Container" }
    $url  = "https://$($sp.Account).blob.$($sp.Suffix)$path"
    if ($Query) { $url = "$url`?$Query" }

    # x-ms-* headers — canonical signature input.
    $headers = @{
        'x-ms-version' = '2021-12-02'
        'x-ms-date'    = $date
    }
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }

    $headers.Authorization = Get-StorageAuthHeader

    $params = @{
        Method  = $Method
        Uri     = $url
        Headers = $headers
    }
    if ($BodyBytes) {
        $params.Body        = $BodyBytes
        $params.ContentType = $ContentType
    }

    Invoke-RestMethod @params -ErrorAction Stop
}

# Cross-version helper: extract HTTP status code from a thrown
# Invoke-RestMethod / Invoke-WebRequest exception. PS 5 puts it on
# .Exception.Response.StatusCode; PS 7+ on .Exception.StatusCode.
function Get-StatusFromError {
    param($ErrorRecord)
    try {
        if ($null -ne $ErrorRecord.Exception.StatusCode) { return [int]$ErrorRecord.Exception.StatusCode }
    } catch { }
    try {
        if ($ErrorRecord.Exception.Response -and $null -ne $ErrorRecord.Exception.Response.StatusCode) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    } catch { }
    return 0
}

function Test-BlobExists {
    param([Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob)
    Write-Host "STORAGE: HEAD /$Container/$Blob ..."
    try {
        Invoke-BlobRest -Method HEAD -Container $Container -Blob $Blob | Out-Null
        Write-Host "STORAGE: HEAD /$Container/$Blob -> 200"
        return $true
    } catch {
        $status = Get-StatusFromError $_
        Write-Host "STORAGE: HEAD /$Container/$Blob -> $status ($($_.Exception.Message))"
        if ($status -eq 404) { return $false }
        throw
    }
}

function Test-ContainerExists {
    param([Parameter(Mandatory)][string]$Container)
    Write-Host "STORAGE: HEAD /$Container?restype=container ..."
    try {
        Invoke-BlobRest -Method HEAD -Container $Container -Query 'restype=container' | Out-Null
        Write-Host "STORAGE: HEAD /$Container?restype=container -> 200"
        return $true
    } catch {
        $status = Get-StatusFromError $_
        Write-Host "STORAGE: HEAD /$Container?restype=container -> $status ($($_.Exception.Message))"
        if ($status -eq 404) { return $false }
        throw
    }
}

function New-Container {
    param([Parameter(Mandatory)][string]$Container)
    if (Test-ContainerExists -Container $Container) { return }
    Write-Host "STORAGE: PUT /$Container?restype=container ..."
    try {
        Invoke-BlobRest -Method PUT -Container $Container -Query 'restype=container' | Out-Null
        Write-Host "STORAGE: PUT /$Container?restype=container -> 201"
    } catch {
        $status = Get-StatusFromError $_
        Write-Host "STORAGE: PUT /$Container?restype=container -> $status ($($_.Exception.Message))"
        # 409 (already exists) is benign — another worker beat us to it.
        if ($status -eq 409) { return }
        throw
    }
}

#endregion

#region ── Table REST ───────────────────────────────────────────────────────────

function Invoke-TableRest {
    <#
    .SYNOPSIS
        Calls Azure Table Storage, authenticated per Get-StorageAuthHeader
        (managed identity by default). Used for the JIT rules table (active
        rule store) and the audit history table.

    .PARAMETER Path
        e.g. "/Tables" or "/JITRules(PartitionKey='subA',RowKey='jit-123')"
        Always relative to the table service root.

    .PARAMETER Method
        GET / POST / PUT / MERGE / DELETE
    #>
    param(
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $Path,
        [string]    $Query    = '',
        $Body                 = $null,
        [hashtable] $ExtraHeaders = @{}
    )

    $sp   = Get-StorageParts
    $date = [DateTime]::UtcNow.ToString('R')
    $url  = "https://$($sp.Account).table.$($sp.Suffix)$Path"
    if ($Query) { $url = "$url`?$Query" }

    $bodyBytes = $null
    $bodyJson  = $null
    if ($null -ne $Body) {
        $bodyJson  = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
        $bodyBytes = [Text.Encoding]::UTF8.GetBytes($bodyJson)
    }

    $contentType = if ($null -ne $Body) { 'application/json' } else { '' }

    # 2020-12-06 is the minimum version Microsoft documents for AAD (Bearer)
    # auth against the Table service. The old 2019-02-02 does still answer a
    # plain entity query with a Bearer token, so this is not the thing that was
    # broken — but staying on a version that predates documented AAD support is
    # a trap for whichever operation stops being lenient first, so pin forward.
    $headers = @{
        'x-ms-version'         = '2020-12-06'
        'x-ms-date'            = $date
        'Accept'               = 'application/json;odata=nometadata'
        'DataServiceVersion'   = '3.0;NetFx'
        'MaxDataServiceVersion' = '3.0;NetFx'
    }
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }

    $headers.Authorization = Get-StorageAuthHeader

    $params = @{
        Method      = $Method
        Uri         = $url
        Headers     = $headers
    }
    if ($bodyBytes) {
        $params.Body        = $bodyBytes
        $params.ContentType = $contentType
    }

    return Invoke-RestMethod @params -ErrorAction Stop
}

#endregion

Export-ModuleMember -Function @(
    'Get-ManagedIdentityToken'
    'Invoke-ArmRest'
    'Invoke-ArmRestRaw'
    'Invoke-BlobRest'
    'Test-BlobExists'
    'Test-ContainerExists'
    'New-Container'
    'Invoke-TableRest'
    'Get-StatusFromError'
)
