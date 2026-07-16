<#
.SYNOPSIS
    Test runner for JIT-AzAccess.

.DESCRIPTION
    Discovers and runs the function app's test suite under
    src/functionapp/tests headlessly. Three modes:

      ./test.ps1                     Simple (default): quiet run of the whole
                                     suite; prints total / passed / failed /
                                     skipped and the names of any failed tests.

      ./test.ps1 -Detailed          Verbose diagnostic output for the whole run.
                                     Use only after a simple run flags a problem.

      ./test.ps1 -Target <name>     Run one test file (matched by file name) or,
                                     if no file name matches, all tests whose
                                     Describe/It name matches "*<name>*".
                                     Combine with -Detailed to diagnose one thing.

    Two kinds of tests live under tests/:
      * Pester (v3.4.0) files   — contain Describe blocks; run via Invoke-Pester.
      * Standalone script tests — HttpHelpers.Tests.ps1 is a plain assertion
                                  script that exits non-zero on failure; run in a
                                  child process and judged by its exit code.
#>
[CmdletBinding()]
param(
    [switch] $Detailed,
    [string] $Target
)

$ErrorActionPreference = 'Stop'

$testsDir = Join-Path $PSScriptRoot 'src/functionapp/tests'
if (-not (Test-Path $testsDir)) {
    Write-Error "Tests directory not found: $testsDir"
    exit 2
}

Import-Module Pester -RequiredVersion 3.4.0 -Force

# ── Discover and classify test files ─────────────────────────────────────────
$allFiles = Get-ChildItem -Path $testsDir -Filter '*.Tests.ps1' -File

$pesterFiles     = @()
$standaloneFiles = @()
foreach ($f in $allFiles) {
    if (Select-String -Path $f.FullName -Pattern '^\s*Describe\b' -Quiet) {
        $pesterFiles += $f
    } else {
        $standaloneFiles += $f
    }
}

# ── Apply -Target filter ─────────────────────────────────────────────────────
$testNameFilter = $null
if ($Target) {
    $matchedPester     = @($pesterFiles     | Where-Object { $_.BaseName -like "*$Target*" })
    $matchedStandalone = @($standaloneFiles | Where-Object { $_.BaseName -like "*$Target*" })

    if ($matchedPester.Count -gt 0 -or $matchedStandalone.Count -gt 0) {
        # Target matched one or more file names: run just those files.
        $pesterFiles     = $matchedPester
        $standaloneFiles = $matchedStandalone
    } else {
        # No file-name match: treat Target as a Describe/It name filter across
        # all Pester files; standalone scripts can't be name-filtered, so skip.
        $testNameFilter  = "*$Target*"
        $standaloneFiles = @()
    }
}

$total   = 0
$passed  = 0
$failed  = 0
$skipped = 0
$failedNames = @()

# ── Run Pester files ─────────────────────────────────────────────────────────
if ($pesterFiles.Count -gt 0) {
    $invokeArgs = @{
        Script   = @($pesterFiles.FullName)
        PassThru = $true
    }
    # Simple mode: suppress per-test chatter. Detailed: full output.
    if (-not $Detailed) { $invokeArgs['Quiet'] = $true }
    if ($testNameFilter) { $invokeArgs['TestName'] = $testNameFilter }

    $result = Invoke-Pester @invokeArgs

    $total   += $result.TotalCount
    $passed  += $result.PassedCount
    $failed  += $result.FailedCount
    $skipped += ($result.SkippedCount + $result.PendingCount + $result.InconclusiveCount)

    $failedNames += $result.TestResult |
        Where-Object { -not $_.Passed -and $_.Result -eq 'Failed' } |
        ForEach-Object { "$($_.Describe) > $($_.Name)" }
}

# ── Run standalone assertion scripts (own process; exit code = pass/fail) ─────
foreach ($s in $standaloneFiles) {
    $total++
    $output = & pwsh -NoProfile -File $s.FullName 2>&1
    $code = $LASTEXITCODE
    if ($Detailed) { $output | ForEach-Object { Write-Host $_ } }

    if ($code -eq 0) {
        $passed++
    } else {
        $failed++
        $failedNames += "$($s.Name) (standalone script)"
        if (-not $Detailed) {
            # Surface the failing lines even in simple mode.
            $output | Where-Object { $_ -match '\[FAIL\]|FAILED' } | ForEach-Object { Write-Host $_ }
        }
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '================ Test Summary ================'
Write-Host ("Total:   {0}" -f $total)
Write-Host ("Passed:  {0}" -f $passed)
Write-Host ("Failed:  {0}" -f $failed)
Write-Host ("Skipped: {0}" -f $skipped)
if ($failedNames.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failed tests:'
    $failedNames | ForEach-Object { Write-Host ("  - {0}" -f $_) }
}
Write-Host '============================================='

if ($failed -gt 0) { exit 1 } else { exit 0 }
