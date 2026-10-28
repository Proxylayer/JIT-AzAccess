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
      * Pester files            — contain Describe blocks; run via Invoke-Pester.
      * Standalone script tests — HttpHelpers.Tests.ps1 is a plain assertion
                                  script that exits non-zero on failure; run in a
                                  child process and judged by its exit code.

    Pester version: the suite is written against Pester 5+ syntax
    (`Should -Be`, `Should -Invoke`, setup in BeforeAll). Windows ships Pester
    3.4.0 in C:\Program Files\WindowsPowerShell\Modules, and a bare
    `Import-Module Pester` can bind commands from it even when a newer version
    is also installed — which fails in confusing ways, because 3.4.0's Mock and
    Describe then shadow the new ones. So this script resolves the newest
    installed version at or above the floor and imports it by exact version.
#>
[CmdletBinding()]
param(
    [switch] $Detailed,
    [string] $Target,

    # Skip the C# (xUnit) project. Useful on a machine without the .NET SDK,
    # or when iterating on the PowerShell suite alone.
    [switch] $SkipDotNet
)

$ErrorActionPreference = 'Stop'

# Floor, not a pin: 5.5.0 is the oldest release with the configuration object
# and `Should -Invoke` in the form this suite uses. CI pins an exact version.
$MinimumPesterVersion = [version]'5.5.0'

$testsDir = Join-Path $PSScriptRoot 'src/functionapp/tests'
if (-not (Test-Path $testsDir)) {
    Write-Error "Tests directory not found: $testsDir"
    exit 2
}

$pester = Get-Module -ListAvailable Pester |
    Where-Object { $_.Version -ge $MinimumPesterVersion } |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $pester) {
    Write-Host "Pester $MinimumPesterVersion or newer is required but not installed." -ForegroundColor Red
    Write-Host "Install it with:" -ForegroundColor Yellow
    Write-Host "  Install-Module Pester -MinimumVersion $MinimumPesterVersion -Scope CurrentUser -Force -SkipPublisherCheck" -ForegroundColor Yellow
    exit 2
}

Remove-Module Pester -Force -ErrorAction SilentlyContinue
Import-Module Pester -RequiredVersion $pester.Version -Force
Write-Host "Using Pester $($pester.Version)" -ForegroundColor DarkGray

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
    $config = New-PesterConfiguration
    $config.Run.Path     = @($pesterFiles.FullName)
    $config.Run.PassThru = $true
    $config.Output.Verbosity = if ($Detailed) { 'Detailed' } else { 'None' }
    if ($testNameFilter) { $config.Filter.FullName = $testNameFilter }

    $result = Invoke-Pester -Configuration $config

    $total   += $result.TotalCount
    $passed  += $result.PassedCount
    $failed  += $result.FailedCount
    $skipped += ($result.SkippedCount + $result.NotRunCount)

    # ExpandedPath is "Describe.Context.It" — enough to find the test without
    # re-running in -Detailed.
    $failedNames += $result.Failed | ForEach-Object { $_.ExpandedPath }
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

# ── Run the C# test project ──────────────────────────────────────────────────
# Reported separately: xUnit owns its own counts, and folding them into the
# Pester totals would make a failure ambiguous about which suite broke.
$dotnetFailed = $false
if (-not $SkipDotNet -and -not $Target) {
    $testProj = Join-Path $PSScriptRoot 'src/plugin/AzureTray.Plugin.JITAzAccess.Tests/AzureTray.Plugin.JITAzAccess.Tests.csproj'
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Write-Host ''
        Write-Host 'dotnet SDK not found - skipping the C# test project.' -ForegroundColor Yellow
    }
    elseif (Test-Path $testProj) {
        Write-Host ''
        Write-Host 'Running C# tests...' -ForegroundColor Cyan
        $verbosity = if ($Detailed) { 'normal' } else { 'quiet' }
        & dotnet test $testProj --nologo -v $verbosity
        if ($LASTEXITCODE -ne 0) { $dotnetFailed = $true }
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '================ Test Summary ================'
Write-Host ("Total:   {0}" -f $total)
Write-Host ("Passed:  {0}" -f $passed)
Write-Host ("Failed:  {0}" -f $failed)
Write-Host ("Skipped: {0}" -f $skipped)
if ($dotnetFailed) {
    Write-Host 'C#:      FAILED (see dotnet test output above)' -ForegroundColor Red
}
if ($failedNames.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failed tests:'
    $failedNames | ForEach-Object { Write-Host ("  - {0}" -f $_) }
}
Write-Host '============================================='

if ($failed -gt 0 -or $dotnetFailed) { exit 1 } else { exit 0 }
