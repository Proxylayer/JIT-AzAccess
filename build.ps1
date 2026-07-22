<#
.SYNOPSIS
    Build script for the JIT-AzAccess repository.

.DESCRIPTION
    Modes:
      simple  (default) : quiet build; prints only a pass/fail summary and errors.
      -Detailed         : full diagnostic MSBuild output (use only to diagnose a failure).
      -Target <name>    : build just one project by name (currently: JITAzAccess).
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

$verb = if ($Pack) { 'pack' } else { 'build' }

foreach ($name in $toBuild.Keys) {
    $proj = $toBuild[$name]
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
    foreach ($name in $toBuild.Keys) {
        $binDir = Join-Path (Split-Path $toBuild[$name]) "bin/$Configuration"
        Get-ChildItem -Path $binDir -Filter '*.nupkg' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime |
            ForEach-Object { Write-Host "  package: $($_.FullName)" -ForegroundColor Green }
    }
} else {
    Write-Host "All builds succeeded." -ForegroundColor Green
}
