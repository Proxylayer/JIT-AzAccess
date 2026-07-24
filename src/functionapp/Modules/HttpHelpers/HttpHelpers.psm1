# HttpHelpers.psm1 — REST helpers used by the JIT function app.
#
# This module exists so the function app needs ZERO Az PowerShell modules at
# runtime. All Azure ops go through Invoke-RestMethod with either:
#   • The function app's managed identity (via IDENTITY_ENDPOINT) for ARM
#     and Graph calls (Bearer tokens).
#   • Shared-Key signing against AzureWebJobsStorage for Storage data-plane
#     (blob, table) ops.
#
# Dropping Az.* drops ~400MB of resident memory and ~5s of cold-start time.

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
    if ($script:StorageParts) { return $script:StorageParts }
    $cs = $env:AzureWebJobsStorage
    if (-not $cs) { throw "AzureWebJobsStorage env var is missing." }

    $parts = @{}
    foreach ($pair in $cs -split ';') {
        if ($pair -match '^([^=]+)=(.*)$') { $parts[$matches[1]] = $matches[2] }
    }
    if (-not $parts.AccountName -or -not $parts.AccountKey) {
        throw "AzureWebJobsStorage must contain AccountName and AccountKey."
    }
    $script:StorageParts = @{
        Account = $parts.AccountName
        Key     = $parts.AccountKey
        Suffix  = if ($parts.EndpointSuffix) { $parts.EndpointSuffix } else { 'core.windows.net' }
    }
    return $script:StorageParts
}

function Get-BlobStringToSign {
    <#
    .SYNOPSIS
        Builds the canonical 14-line StringToSign for Blob / Queue / File
        SharedKey auth.
    #>
    param(
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $CanonicalResource,
        [hashtable] $Headers = @{},
        [int]       $ContentLength = 0,
        [string]    $ContentType   = '',
        [string]    $ContentMd5    = ''
    )

    $xms = $Headers.GetEnumerator() |
        Where-Object { $_.Key -like 'x-ms-*' } |
        ForEach-Object { @{ K = $_.Key.ToLowerInvariant(); V = $_.Value } }
    $canHeaders = ($xms | Sort-Object { $_.K } | ForEach-Object { "$($_.K):$($_.V)" }) -join "`n"

    $clLine = if ($ContentLength -eq 0) { '' } else { "$ContentLength" }

    # The standard (non x-ms-) conditional headers each occupy a fixed line in
    # the StringToSign, and Azure DOES include them in its computed signature
    # when the request carries them — e.g. the create-only lock PUT sends
    # `If-None-Match: *` and the release sends `If-Match: *`. We must sign the
    # exact same values or the MAC won't match (AuthenticationFailed). Look them
    # up case-insensitively from the request headers.
    $lc = @{}
    foreach ($e in $Headers.GetEnumerator()) { $lc[[string]$e.Key.ToLowerInvariant()] = [string]$e.Value }
    $ifModifiedSince   = if ($lc.ContainsKey('if-modified-since'))   { $lc['if-modified-since'] }   else { '' }
    $ifMatch           = if ($lc.ContainsKey('if-match'))            { $lc['if-match'] }            else { '' }
    $ifNoneMatch       = if ($lc.ContainsKey('if-none-match'))       { $lc['if-none-match'] }       else { '' }
    $ifUnmodifiedSince = if ($lc.ContainsKey('if-unmodified-since')) { $lc['if-unmodified-since'] } else { '' }
    $range             = if ($lc.ContainsKey('range'))               { $lc['range'] }               else { '' }

    return @(
        $Method
        ''                  # Content-Encoding
        ''                  # Content-Language
        $clLine
        $ContentMd5
        $ContentType
        ''                  # Date — using x-ms-date instead
        $ifModifiedSince
        $ifMatch
        $ifNoneMatch
        $ifUnmodifiedSince
        $range
        $canHeaders
        $CanonicalResource
    ) -join "`n"
}

function Get-TableStringToSign {
    <#
    .SYNOPSIS
        Builds the 5-line StringToSign for Table service SharedKey auth.
        Tables do NOT use the same recipe as Blob/Queue/File — only these
        5 lines, no x-ms-* canonicalized headers, no extra blanks.

        https://learn.microsoft.com/rest/api/storageservices/authentication-for-the-azure-storage-services#table-service-shared-key-authorization
    #>
    param(
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $Date,
        [Parameter(Mandatory)][string] $CanonicalResource,
        [string] $ContentType = '',
        [string] $ContentMd5  = ''
    )
    return @(
        $Method
        $ContentMd5
        $ContentType
        $Date
        $CanonicalResource
    ) -join "`n"
}

function Get-BlobCanonicalResource {
    <#
    .SYNOPSIS
        Builds the CanonicalizedResource for Blob/Queue/File SharedKey auth:
        "/<account><path>" followed by each query parameter on its own line as
        "name:value" (name lower-cased, params sorted by name).

        NOTE: this is the Blob/Queue/File recipe. The Table service uses a
        different "?comp=value" form — see Build-TableCanonicalResource. Mixing
        them up yields an AuthenticationFailed MAC mismatch.
    #>
    param(
        [Parameter(Mandatory)][string] $Account,
        [Parameter(Mandatory)][string] $Path,
        [string] $Query = ''
    )
    $can = "/$Account$Path"
    if ($Query) {
        $params = @{}
        foreach ($pair in $Query -split '&') {
            if ($pair -match '^([^=]+)=(.*)$') {
                $name = [Uri]::UnescapeDataString($matches[1]).ToLowerInvariant()
                $val  = [Uri]::UnescapeDataString($matches[2])
                if ($params.ContainsKey($name)) { $params[$name] += ",$val" } else { $params[$name] = $val }
            }
        }
        $sorted = ($params.GetEnumerator() | Sort-Object { $_.Key } | ForEach-Object { "$($_.Key):$($_.Value)" }) -join "`n"
        $can = "$can`n$sorted"
    }
    return $can
}

function script:Get-HmacSignature {
    param([Parameter(Mandatory)][string]$StringToSign, [Parameter(Mandatory)][string]$Base64Key)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($Base64Key))
    try {
        return [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($StringToSign)))
    }
    finally { $hmac.Dispose() }
}

function script:New-SharedKeySignature {
    <#
    .SYNOPSIS
        Returns the "SharedKey <account>:<sig>" Authorization header value
        for Blob / Queue / File.
    #>
    param(
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $CanonicalResource,
        [hashtable] $Headers = @{},
        [int]       $ContentLength = 0,
        [string]    $ContentType   = '',
        [string]    $ContentMd5    = ''
    )
    $sp = Get-StorageParts
    $stringToSign = Get-BlobStringToSign `
        -Method            $Method `
        -CanonicalResource $CanonicalResource `
        -Headers           $Headers `
        -ContentLength     $ContentLength `
        -ContentType       $ContentType `
        -ContentMd5        $ContentMd5
    $sig = Get-HmacSignature -StringToSign $stringToSign -Base64Key $sp.Key
    return "SharedKey $($sp.Account):$sig"
}

#endregion

#region ── Blob REST (Shared Key) ───────────────────────────────────────────────

function Invoke-BlobRest {
    <#
    .SYNOPSIS
        Calls Azure Blob Storage with Shared Key auth derived from
        AzureWebJobsStorage. Used for the distributed lock blob lease.
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

    $len = if ($BodyBytes) { $BodyBytes.Length } else { 0 }

    # CanonicalResource for Shared Key: "/account/container[/blob]" then each
    # query param on its own "name:value" line (NOT "?key=value").
    $canResource = Get-BlobCanonicalResource -Account $sp.Account -Path $path -Query $Query

    $headers.Authorization = New-SharedKeySignature `
        -Method            $Method `
        -CanonicalResource $canResource `
        -Headers           $headers `
        -ContentLength     $len `
        -ContentType       $ContentType

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

#region ── Table REST (Shared Key) ──────────────────────────────────────────────

function Build-TableCanonicalResource {
    <#
    .SYNOPSIS
        Builds CanonicalResource for Table SharedKey signing:
            /<account>/<resource-path>[?comp=<value>]
        Note: ONLY the comp parameter goes in. Other query string params
        ($filter, $top, etc.) are NOT included in the signature.
    #>
    param(
        [Parameter(Mandatory)][string] $AccountName,
        [Parameter(Mandatory)][string] $Path,
        [string] $Query = ''
    )
    $can = "/$AccountName$Path"
    if ($Query) {
        $compMatch = [regex]::Match($Query, '(?:^|&)comp=([^&]+)')
        if ($compMatch.Success) { $can = "$can`?comp=$($compMatch.Groups[1].Value)" }
    }
    return $can
}

function Invoke-TableRest {
    <#
    .SYNOPSIS
        Calls Azure Table Storage with SharedKey auth derived from
        AzureWebJobsStorage. Used for the JIT rules table (active rule store).

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

    $headers = @{
        'x-ms-version'         = '2019-02-02'
        'x-ms-date'            = $date
        'Accept'               = 'application/json;odata=nometadata'
        'DataServiceVersion'   = '3.0;NetFx'
        'MaxDataServiceVersion' = '3.0;NetFx'
    }
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }

    $canResource  = Build-TableCanonicalResource -AccountName $sp.Account -Path $Path -Query $Query
    $stringToSign = Get-TableStringToSign `
        -Method            $Method `
        -Date              $date `
        -CanonicalResource $canResource `
        -ContentType       $contentType
    $sig = Get-HmacSignature -StringToSign $stringToSign -Base64Key $sp.Key
    $headers.Authorization = "SharedKey $($sp.Account):$sig"

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
    # Exposed for unit tests + reuse by JITHelpers' lease signing:
    'Get-BlobStringToSign'
    'Get-BlobCanonicalResource'
    'Get-TableStringToSign'
    'Build-TableCanonicalResource'
)
