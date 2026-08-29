# Tests for HttpHelpers.psm1 — verifies storage auth and JSON handling without
# touching Azure. Run directly:
#   pwsh -NoProfile -File tests/HttpHelpers.Tests.ps1
#
# These are simple assertion-style tests (no Pester) so they run anywhere.
#
# The Shared Key StringToSign / canonical-resource / HMAC tests that used to
# live here were deleted along with the code they covered. Storage auth is
# Entra ID only — see the HttpHelpers.psm1 header for why an account-key path
# must never come back. The guard below fails the suite if one does.

$ErrorActionPreference = 'Stop'
$module = "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1"

# Deliberately supply a connection string that DOES carry an AccountKey: the
# module must resolve the account name from it and ignore the key entirely.
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


Write-Host ""
Write-Host "=== Storage auth is Entra ID only (no account-key path) ===" -ForegroundColor Cyan

# 1. The account key present in AzureWebJobsStorage must be ignored outright:
#    Get-StorageParts resolves the NAME and must not carry a Key at all.
$parts = & (Get-Module HttpHelpers) { Get-StorageParts }

Should-Equal 'Account name resolves from the connection string' 'testacct' $parts.Account
Should-Equal 'Resolved storage parts expose NO account key'     $false     ($parts.ContainsKey('Key'))

# 2. The single auth helper always returns a managed-identity Bearer token.
#    Get-ManagedIdentityToken is shadowed so nothing reaches IMDS.
$auth = & (Get-Module HttpHelpers) {
    function Get-ManagedIdentityToken { param($Resource) "TOK($Resource)" }
    Get-StorageAuthHeader
}
Should-Equal 'Storage auth header is a Bearer token for the storage audience' `
    'Bearer TOK(https://storage.azure.com/)' $auth

# 3. Regression guard. A subscription Azure Policy forces
#    allowSharedKeyAccess=false, so any reintroduced Shared Key path is dead
#    code that can only fail in production — and it failed silently for eight
#    days once already. Fail the suite rather than let one back in quietly.
$src = Get-Content "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Raw
foreach ($banned in @('HMACSHA256', 'SharedKey $(', 'StringToSign', 'JIT_STORAGE_AUTH')) {
    if ($src -like "*$banned*") {
        Write-Host "[FAIL] HttpHelpers.psm1 reintroduces an account-key code path: '$banned'" -ForegroundColor Red
        $failures++
    } else {
        Write-Host "[PASS] No account-key code path: '$banned' absent" -ForegroundColor Green
    }
}

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
