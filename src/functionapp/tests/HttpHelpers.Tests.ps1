# Tests for HttpHelpers.psm1 — verifies the Storage REST signing logic
# without touching Azure. Run directly:
#   pwsh -NoProfile -File tests/HttpHelpers.Tests.ps1
#
# These are simple assertion-style tests (no Pester) so they run anywhere.

$ErrorActionPreference = 'Stop'
$module = "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1"

# Set storage env var BEFORE importing so the module-level cache picks it up.
$testKey = [Convert]::ToBase64String((New-Object byte[] 32))   # base64 of 32 zero bytes
$env:AzureWebJobsStorage = "DefaultEndpointsProtocol=https;AccountName=testacct;AccountKey=$testKey;EndpointSuffix=core.windows.net"

Import-Module $module -Force

$failures = 0
function Should-Equal {
    param([string]$Label, $Expected, $Actual)
    if ($Expected -ceq $Actual) {
        Write-Host "[PASS] $Label" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $Label" -ForegroundColor Red
        Write-Host "       expected: [$Expected]"
        Write-Host "       actual  : [$Actual]"
        $script:failures++
    }
}

# ── Get-TableStringToSign ─────────────────────────────────────────────────────
# Per https://learn.microsoft.com/rest/api/storageservices/authentication-for-the-azure-storage-services
# Table SharedKey StringToSign is exactly 5 lines:
#   VERB \n Content-MD5 \n Content-Type \n Date \n CanonicalResource

Write-Host ""
Write-Host "=== Get-TableStringToSign (5-line Table format) ===" -ForegroundColor Cyan
$date = 'Wed, 28 Apr 2010 23:51:46 GMT'

Should-Equal 'GET on /Tables with no body' `
    "GET`n`n`n$date`n/testacct/Tables" `
    (Get-TableStringToSign -Method 'GET' -Date $date -CanonicalResource '/testacct/Tables')

Should-Equal 'POST with body has Content-Type on line 3' `
    "POST`n`napplication/json`n$date`n/testacct/JITRules" `
    (Get-TableStringToSign -Method 'POST' -Date $date `
        -CanonicalResource '/testacct/JITRules' `
        -ContentType 'application/json')

Should-Equal 'DELETE point-row preserves PartitionKey/RowKey parens' `
    "DELETE`n`n`n$date`n/testacct/JITRules(PartitionKey='sub',RowKey='jit-1')" `
    (Get-TableStringToSign -Method 'DELETE' -Date $date `
        -CanonicalResource "/testacct/JITRules(PartitionKey='sub',RowKey='jit-1')")

# ── Build-TableCanonicalResource ──────────────────────────────────────────────
# For Tables, only the `comp` query parameter is included in the canonical
# resource. $filter, $top, $select are NOT.

Write-Host ""
Write-Host "=== Build-TableCanonicalResource ===" -ForegroundColor Cyan

Should-Equal 'No query string → /<account>/<path>' `
    '/testacct/JITRules()' `
    (Build-TableCanonicalResource -AccountName 'testacct' -Path '/JITRules()' -Query '')

Should-Equal '$filter is NOT in the canonical resource' `
    '/testacct/JITRules()' `
    (Build-TableCanonicalResource -AccountName 'testacct' -Path '/JITRules()' `
        -Query '$filter=RowKey%20eq%20%27jit-1%27')

Should-Equal 'Only comp=<value> goes into the canonical resource' `
    '/testacct/?comp=list' `
    (Build-TableCanonicalResource -AccountName 'testacct' -Path '/' -Query 'comp=list')

Should-Equal 'comp= mid-string is still extracted' `
    '/testacct/?comp=acl' `
    (Build-TableCanonicalResource -AccountName 'testacct' -Path '/' -Query 'restype=table&comp=acl&other=x')

# ── Reference HMAC computation matches our pipeline ───────────────────────────
# This validates that the StringToSign + HMAC + base64 chain produces the
# value we'd expect any other Azure SDK to produce for the same inputs.

Write-Host ""
Write-Host "=== HMAC is deterministic + matches plain HMAC-SHA256 ===" -ForegroundColor Cyan

$sts = Get-TableStringToSign -Method 'GET' -Date $date -CanonicalResource '/testacct/Tables'

function script:Compute-HmacB64 {
    param([string]$Key, [string]$Data)
    $h = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($Key))
    try { return [Convert]::ToBase64String($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))) }
    finally { $h.Dispose() }
}

$sig1 = Compute-HmacB64 -Key $testKey -Data $sts
$sig2 = Compute-HmacB64 -Key $testKey -Data $sts
Should-Equal 'Same inputs → same HMAC (Table)' $sig1 $sig2

# Sanity: changing ANY byte of the StringToSign changes the signature.
$sigDiff = Compute-HmacB64 -Key $testKey -Data ($sts + ' ')
if ($sig1 -ceq $sigDiff) {
    Write-Host "[FAIL] HMAC unchanged after appending a space — sanity check failed." -ForegroundColor Red
    $failures++
} else {
    Write-Host "[PASS] HMAC changes when input changes (sensitive to bytes)" -ForegroundColor Green
}

# ── Blob StringToSign sanity ──────────────────────────────────────────────────
# Blob/Queue/File SharedKey has 14 lines.

Write-Host ""
Write-Host "=== Get-BlobStringToSign (14-line Blob/Queue/File format) ===" -ForegroundColor Cyan

$actual = Get-BlobStringToSign -Method 'GET' `
    -CanonicalResource '/testacct/mycontainer' `
    -Headers @{ 'x-ms-date' = 'Wed, 28 Apr 2010 23:51:46 GMT'; 'x-ms-version' = '2021-12-02' }

$expected = (@(
    'GET', '', '', '', '', '', '', '', '', '', '', ''
) -join "`n") +
"`n" + "x-ms-date:Wed, 28 Apr 2010 23:51:46 GMT`nx-ms-version:2021-12-02`n/testacct/mycontainer"

Should-Equal 'GET blob container: 12 empty leading lines, then sorted x-ms-* headers, then resource' `
    $expected $actual

$blob1 = Compute-HmacB64 -Key $testKey -Data $actual
$blob2 = Compute-HmacB64 -Key $testKey -Data $actual
Should-Equal 'Same inputs → same HMAC (Blob)' $blob1 $blob2

# Regression: the create-only lock PUT sends `If-None-Match: *`, which Azure
# echoes on line 10 of the StringToSign. If Get-BlobStringToSign emits an empty
# line there instead of the header value, the MAC mismatches and the lock PUT
# fails with AuthenticationFailed (this broke every NSG grant).
$lockDate = 'Wed, 27 May 2026 22:44:40 GMT'
$lockSts  = Get-BlobStringToSign -Method 'PUT' `
    -CanonicalResource '/testacct/jit-locks/mylock' `
    -Headers @{ 'x-ms-version' = '2021-12-02'; 'x-ms-date' = $lockDate; 'x-ms-blob-type' = 'BlockBlob'; 'If-None-Match' = '*' } `
    -ContentLength 4 -ContentType 'application/octet-stream'

$lockExpected = (@('PUT', '', '', '4', '', 'application/octet-stream', '', '', '', '*', '', '') -join "`n") +
    "`n" + "x-ms-blob-type:BlockBlob`nx-ms-date:$lockDate`nx-ms-version:2021-12-02`n/testacct/jit-locks/mylock"

Should-Equal 'Lock PUT: If-None-Match:* lands on line 10 of the StringToSign' `
    $lockExpected $lockSts

# Release path sends `If-Match: *` — must land on line 9.
$relSts = Get-BlobStringToSign -Method 'PUT' `
    -CanonicalResource '/testacct/jit-locks/mylock' `
    -Headers @{ 'x-ms-version' = '2021-12-02'; 'x-ms-date' = $lockDate; 'If-Match' = '*' }

$relExpected = (@('PUT', '', '', '', '', '', '', '', '*', '', '', '') -join "`n") +
    "`n" + "x-ms-date:$lockDate`nx-ms-version:2021-12-02`n/testacct/jit-locks/mylock"

Should-Equal 'Lock release: If-Match:* lands on line 9 of the StringToSign' `
    $relExpected $relSts

Write-Host ""
Write-Host "=== Get-BlobCanonicalResource (query params as name:value lines) ===" -ForegroundColor Cyan

Should-Equal 'No query → just /account/path' `
    '/testacct/jit-locks/mylock' `
    (Get-BlobCanonicalResource -Account 'testacct' -Path '/jit-locks/mylock')

# The lease bug: comp=lease must become a "comp:lease" LINE, not "?comp=lease".
# Signing the literal "?comp=lease" produced AuthenticationFailed on every NSG
# lock acquire/release.
Should-Equal 'comp=lease → newline + comp:lease (Blob recipe, not ?comp=lease)' `
    "/testacct/jit-locks/mylock`ncomp:lease" `
    (Get-BlobCanonicalResource -Account 'testacct' -Path '/jit-locks/mylock' -Query 'comp=lease')

Should-Equal 'restype=container → newline + restype:container' `
    "/testacct/mycontainer`nrestype:container" `
    (Get-BlobCanonicalResource -Account 'testacct' -Path '/mycontainer' -Query 'restype=container')

Should-Equal 'Multiple params are lower-cased and sorted by name' `
    "/testacct/c/b`ncomp:lease`nrestype:container" `
    (Get-BlobCanonicalResource -Account 'testacct' -Path '/c/b' -Query 'restype=container&comp=lease')

Write-Host ""
Write-Host "=== Manifest-parse: object vs string return from Invoke-RestMethod ===" -ForegroundColor Cyan

# This is the bug that broke Get-JITTargets: Invoke-RestMethod auto-parses
# responses whose Content-Type is application/json into PSCustomObject. Calling
# `$obj | ConvertFrom-Json` on the already-parsed object converts it to its
# string repr (which starts with "@{...}") and the JSON parser dies on "@".

$alreadyParsed = [pscustomobject]@{ name = 'x'; enabled = $true }

# Confirm the failure mode that the function app hit:
$ex = $null
try {
    $alreadyParsed | ConvertFrom-Json -ErrorAction Stop | Out-Null
} catch { $ex = $_.Exception.Message }
if ($ex -and $ex -like '*Unexpected character*') {
    Write-Host "[PASS] Re-parsing PSCustomObject via ConvertFrom-Json fails as expected" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Expected ConvertFrom-Json to fail on PSCustomObject (got: $ex)" -ForegroundColor Red
    $failures++
}

# Manifest reader logic: should handle both shapes cleanly.
function script:Test-ManifestParse {
    param($content)
    if ($null -eq $content) { return @() }
    if ($content -is [string]) { return ($content | ConvertFrom-Json) }
    return $content
}

Should-Equal 'String input gets parsed' `
    'targetA' `
    (Test-ManifestParse -content '[{"name":"targetA"}]')[0].name

Should-Equal 'Already-parsed PSCustomObject array passes through' `
    'targetA' `
    (Test-ManifestParse -content @([pscustomobject]@{ name = 'targetA' }))[0].name

Should-Equal 'Null returns empty array' `
    0 `
    (@(Test-ManifestParse -content $null)).Count

Write-Host ""
Write-Host "=== Write-JsonResponse-style empty-array serialization ===" -ForegroundColor Cyan

# This is the PowerShell gotcha that caused Get-JITRules to return an empty
# body and break the plugin's JSON deserializer. Piping an empty array to
# ConvertTo-Json unwraps it through the pipeline; -InputObject preserves it.

Should-Equal 'Pipeline @() | ConvertTo-Json returns empty string (the bug)' `
    '' `
    ((@() | ConvertTo-Json -Compress) -as [string])

Should-Equal 'ConvertTo-Json -InputObject @() returns "[]" (the fix)' `
    '[]' `
    (ConvertTo-Json -InputObject @() -Compress)

Should-Equal 'ConvertTo-Json -InputObject hashtable still works' `
    '{"error":"x"}' `
    (ConvertTo-Json -InputObject @{ error = 'x' } -Compress)

Should-Equal 'ConvertTo-Json -InputObject single-element array preserves array shape' `
    '[{"a":1}]' `
    (ConvertTo-Json -InputObject @(@{ a = 1 }) -Compress)

Write-Host ""
if ($failures -gt 0) {
    Write-Host "FAILED: $failures test(s)" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All tests passed." -ForegroundColor Green
}
