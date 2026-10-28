<#
.SYNOPSIS
    Build script for the JIT-AzAccess repository.

.DESCRIPTION
    Modes:
      simple  (default) : quiet build; prints only a pass/fail summary and errors.
      -Detailed         : full diagnostic MSBuild output (use only to diagnose a failure).
      -Target <name>    : build just one project by name. Known targets:
                          JITAzAccess, JITAzAccessTests, FunctionApp.
                          FunctionApp is not a .NET project: it parses every
                          function-app .ps1/.psm1 and runs PSScriptAnalyzer
                          over them, which is otherwise the one part of this
                          repo with no build-time validation at all.
      -Pack             : produce a NuGet package (dotnet pack) instead of a plain build.
                          Implies Release unless -Configuration is given; the .nupkg
                          lands in each project's bin/<Configuration> folder.

.EXAMPLE
    ./build.ps1
    ./build.ps1 -Detailed
    ./build.ps1 -Target JITAzAccess
    ./build.ps1 -Pack
    ./build.ps1 -Pack -Target JITAzAccess
#>
[CmdletBinding()]
param(
    [switch] $Detailed,
    [string] $Target,
    [switch] $Pack,
    [string] $Configuration
)

# Pack defaults to Release; a plain build defaults to Debug. An explicit
# -Configuration always wins.
if (-not $Configuration) {
    $Configuration = if ($Pack) { 'Release' } else { 'Debug' }
}

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot

# Known buildable projects in this repo. Add entries here as projects appear.
$projects = [ordered]@{
    JITAzAccess      = Join-Path $repoRoot 'src/plugin/AzureTray.Plugin.JITAzAccess/AzureTray.Plugin.JITAzAccess.csproj'
    JITAzAccessTests = Join-Path $repoRoot 'src/plugin/AzureTray.Plugin.JITAzAccess.Tests/AzureTray.Plugin.JITAzAccess.Tests.csproj'
}

# ── FunctionApp: parse + analyze the PowerShell ──────────────────────────────
#
# The function app is the whole server side and `dotnet build` never sees it,
# so a syntax error there used to reach a deployment unchallenged. This target
# parses every file and runs PSScriptAnalyzer with the repo settings.
function Invoke-FunctionAppCheck {
    $appDir  = Join-Path $repoRoot 'src/functionapp'
    $testDir = Join-Path $appDir 'tests'

    # Everything gets PARSED, tests included — a syntax error in a test file is
    # still a broken build. Only shipped code gets LINTED: test files
    # legitimately use bare $Timer fixtures, New-* helpers that change no
    # system state, and other shapes the analyzer rules are not written for.
    $allFiles = @(Get-ChildItem -Path $appDir -Include '*.ps1', '*.psm1' -Recurse -File)
    $lintFiles = @($allFiles | Where-Object {
        -not $_.FullName.StartsWith($testDir, [System.StringComparison]::OrdinalIgnoreCase)
    })

    Write-Host "Parsing $($allFiles.Count) script(s); linting $($lintFiles.Count)..." -ForegroundColor Cyan

    $problems = 0

    foreach ($f in $allFiles) {
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $f.FullName, [ref]$null, [ref]$parseErrors) | Out-Null
        if ($parseErrors -and $parseErrors.Count -gt 0) {
            foreach ($e in $parseErrors) {
                Write-Host ("  PARSE  {0}:{1} {2}" -f `
                    $f.Name, $e.Extent.StartLineNumber, $e.Message) -ForegroundColor Red
                $problems++
            }
        }
    }

    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        Write-Host "  PSScriptAnalyzer is not installed - skipping lint." -ForegroundColor Yellow
        Write-Host "  Install-Module PSScriptAnalyzer -Scope CurrentUser -Force" -ForegroundColor Yellow
    } else {
        Import-Module PSScriptAnalyzer -Force
        $settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
        foreach ($f in $lintFiles) {
            # -Path takes a single string, not an array. Passing an array
            # silently analyzes nothing, which reads as a clean result.
            $found = Invoke-ScriptAnalyzer -Path $f.FullName -Settings $settings
            foreach ($d in $found) {
                Write-Host ("  {0,-8} {1}:{2} {3}" -f `
                    $d.Severity, $f.Name, $d.Line, $d.RuleName) -ForegroundColor Red
                Write-Host ("           {0}" -f $d.Message) -ForegroundColor DarkGray
                $problems++
            }
        }
    }

    return $problems
}

if ($Target) {
    if ($Target -eq 'FunctionApp') {
        $problems = Invoke-FunctionAppCheck
        if ($problems -gt 0) {
            Write-Host "CHECK FAILED: FunctionApp ($problems finding(s))" -ForegroundColor Red
            exit 1
        }
        Write-Host "CHECK OK: FunctionApp" -ForegroundColor Green
        exit 0
    }
    if (-not $projects.Contains($Target)) {
        Write-Host "Unknown target '$Target'. Known targets: $(($projects.Keys + 'FunctionApp') -join ', ')" -ForegroundColor Red
        exit 2
    }
    $toBuild = [ordered]@{ $Target = $projects[$Target] }
} else {
    $toBuild = $projects
}

$verbosity = if ($Detailed) { 'detailed' } else { 'minimal' }
$failed = $false

$verb = if ($Pack) { 'pack' } else { 'build' }

foreach ($name in @($toBuild.Keys)) {
    $proj = $toBuild[$name]

    # The test project is IsPackable=false; packing it is a no-op that only
    # produces noise.
    if ($Pack -and $name -like '*Tests') {
        Write-Host "Skipping $name (not packable)." -ForegroundColor DarkGray
        continue
    }

    $action = if ($Pack) { 'Packing' } else { 'Building' }
    Write-Host "$action $name ($Configuration)..." -ForegroundColor Cyan

    $args = @($verb, $proj, '-c', $Configuration, '--nologo', '-v', $verbosity)
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$($verb.ToUpper()) FAILED: $name" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "$($verb.ToUpper()) OK: $name" -ForegroundColor Green
    }
}

if ($failed) { exit 1 }

if ($Pack) {
    Write-Host "All packs succeeded." -ForegroundColor Green
    foreach ($name in @($toBuild.Keys)) {
        if ($name -like '*Tests') { continue }
        $binDir = Join-Path (Split-Path $toBuild[$name]) "bin/$Configuration"
        Get-ChildItem -Path $binDir -Filter '*.nupkg' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime |
            ForEach-Object { Write-Host "  package: $($_.FullName)" -ForegroundColor Green }
    }
} else {
    Write-Host "All builds succeeded." -ForegroundColor Green
}
