<#
.SYNOPSIS
    Build script for the JIT-AzAccess repository.

.DESCRIPTION
    Three modes:
      simple  (default) : quiet build; prints only a pass/fail summary and errors.
      -Detailed         : full diagnostic MSBuild output (use only to diagnose a failure).
      -Target <name>    : build just one project by name (currently: JITAzAccess).

.EXAMPLE
    ./build.ps1
    ./build.ps1 -Detailed
    ./build.ps1 -Target JITAzAccess
#>
[CmdletBinding()]
param(
    [switch] $Detailed,
    [string] $Target,
    [string] $Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot

# Known buildable projects in this repo. Add entries here as projects appear.
$projects = @{
    JITAzAccess = Join-Path $repoRoot 'src/plugin/AzureTray.Plugin.JITAzAccess/AzureTray.Plugin.JITAzAccess.csproj'
}

if ($Target) {
    if (-not $projects.ContainsKey($Target)) {
        Write-Host "Unknown target '$Target'. Known targets: $($projects.Keys -join ', ')" -ForegroundColor Red
        exit 2
    }
    $toBuild = @{ $Target = $projects[$Target] }
} else {
    $toBuild = $projects
}

$verbosity = if ($Detailed) { 'detailed' } else { 'minimal' }
$failed = $false

foreach ($name in $toBuild.Keys) {
    $proj = $toBuild[$name]
    Write-Host "Building $name ($Configuration)..." -ForegroundColor Cyan

    $args = @('build', $proj, '-c', $Configuration, '--nologo', '-v', $verbosity)
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BUILD FAILED: $name" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "BUILD OK: $name" -ForegroundColor Green
    }
}

if ($failed) { exit 1 }
Write-Host "All builds succeeded." -ForegroundColor Green
