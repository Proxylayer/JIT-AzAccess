<#
.SYNOPSIS
    End-to-end deployment of the JIT-AzAccess function app.

.DESCRIPTION
    Runs all deployment steps in order:
      1. Deploy ARM template (creates resource group + all Azure resources)
      2. Zip-deploy the function app code
      3. Configure the AAD app registration (Graph permission + owner)
      4. Prompt to run Grant-JITPermissions.ps1 on target subscriptions

    Prerequisites:
      - Azure CLI installed and logged in: az login
      - Zip utility available (uses Compress-Archive)

.PARAMETER SubscriptionId
    Subscription where the JIT infrastructure will be deployed.

.PARAMETER Location
    Azure region (e.g. eastus, westeurope).

.PARAMETER AppRegistrationObjectId
    Object ID of the AAD app registration created for the JIT service.
    Create one in the Azure portal (App registrations) or with:
      az ad app create --display-name "JIT-AzAccess" --query id -o tsv

.PARAMETER ApprovedClientIds
    Comma-separated AAD client IDs whose tokens will be accepted by the API.

.PARAMETER JwtAudience
    Expected 'aud' claim in the bearer token (the app registration's Application ID URI).

.PARAMETER AppName
    Short lowercase alphanumeric name used to derive resource names (default: jitazaccess).

.PARAMETER ResourceGroupName
    Resource group to create (default: rg-jit-azaccess).

.PARAMETER ParametersFile
    Path to an azuredeploy.parameters.json file. When supplied, individual
    parameter switches are ignored (except -SubscriptionId).

.PARAMETER SkipAppRegistration
    Skip the Set-JITAppRegistration.ps1 step (e.g. you already ran it).

.EXAMPLE
    # Minimal — answer prompts for IDs
    ./scripts/Deploy.ps1 -SubscriptionId "xxxx" -Location "eastus"

.EXAMPLE
    # Fully scripted
    ./scripts/Deploy.ps1 `
        -SubscriptionId          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -Location                "eastus" `
        -AppRegistrationObjectId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ApprovedClientIds       "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" `
        -JwtAudience             "api://jit-azaccess"

.EXAMPLE
    # Using a parameters file
    ./scripts/Deploy.ps1 `
        -SubscriptionId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ParametersFile  "./azuredeploy.parameters.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [string]$Location,
    [string]$AppRegistrationObjectId,
    [string]$ApprovedClientIds,
    [string]$JwtAudience,
    [string]$AppName            = 'jitazaccess',
    [string]$ResourceGroupName  = 'rg-jit-azaccess',
    [string]$ParametersFile,
    [switch]$SkipAppRegistration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir   = $PSScriptRoot
$repoRoot    = Split-Path $scriptDir -Parent
$templatePath = Join-Path $repoRoot 'azuredeploy.json'
$funcAppDir   = Join-Path $repoRoot 'functionapp'

# ── Pre-flight checks ─────────────────────────────────────────────────────────

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI not found. Install from https://aka.ms/installazurecliwindows"
    exit 1
}

$accountInfo = az account show --output json 2>$null | ConvertFrom-Json
if (-not $accountInfo) {
    Write-Error "Not logged in to Azure CLI. Run: az login"
    exit 1
}

Write-Host "Logged in as: $($accountInfo.user.name)"
Write-Host "Setting subscription to: $SubscriptionId"
az account set --subscription $SubscriptionId

# ── Prompt for missing required values ───────────────────────────────────────

if (-not $ParametersFile) {
    if (-not $Location) {
        $Location = Read-Host "Azure region (e.g. eastus, westeurope)"
    }
    if (-not $ApprovedClientIds) {
        $ApprovedClientIds = Read-Host "Comma-separated approved AAD client IDs"
    }
    if (-not $JwtAudience) {
        $JwtAudience = Read-Host "JWT audience / Application ID URI (e.g. api://jit-azaccess)"
    }
    if (-not $AppRegistrationObjectId -and -not $SkipAppRegistration) {
        $AppRegistrationObjectId = Read-Host "App registration Object ID (Enter to skip)"
    }
}

# ── Step 1: Deploy ARM template ───────────────────────────────────────────────

Write-Host ""
Write-Host "=== Step 1: Deploying ARM template ===" -ForegroundColor Cyan

$deploymentName = "jit-azaccess-$(Get-Date -Format 'yyyyMMddHHmm')"

$deployArgs = @(
    'deployment', 'sub', 'create'
    '--name',           $deploymentName
    '--location',       if ($Location) { $Location } else { 'eastus' }
    '--template-file',  $templatePath
    '--subscription',   $SubscriptionId
)

if ($ParametersFile) {
    $deployArgs += '--parameters', "@$ParametersFile"
}
else {
    $deployArgs += '--parameters'
    $deployArgs += "location=$Location"
    $deployArgs += "appName=$AppName"
    $deployArgs += "resourceGroupName=$ResourceGroupName"
    $deployArgs += "approvedClientIds=$ApprovedClientIds"
    $deployArgs += "jwtAudience=$JwtAudience"
    if ($AppRegistrationObjectId) {
        $deployArgs += "jitAppRegistrationObjectId=$AppRegistrationObjectId"
    }
}

Write-Host "Running: az $($deployArgs -join ' ')"
$deployOutput = az @deployArgs --output json | ConvertFrom-Json

if ($LASTEXITCODE -ne 0) {
    Write-Error "ARM deployment failed."
    exit 1
}

$principalId      = $deployOutput.properties.outputs.functionAppPrincipalId.value
$functionAppName  = $deployOutput.properties.outputs.functionAppName.value
$functionHostname = $deployOutput.properties.outputs.functionAppHostname.value
$rgName           = $deployOutput.properties.outputs.resourceGroupName.value

Write-Host "ARM deployment succeeded." -ForegroundColor Green
Write-Host "  Function app: $functionAppName"
Write-Host "  Hostname:     $functionHostname"
Write-Host "  Principal ID: $principalId"
Write-Host "  Resource group: $rgName"

# ── Step 2: Zip-deploy function app code ─────────────────────────────────────

Write-Host ""
Write-Host "=== Step 2: Deploying function app code ===" -ForegroundColor Cyan

$zipPath = Join-Path $env:TEMP "jit-azaccess-functionapp.zip"

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Write-Host "Packaging $funcAppDir ..."
Compress-Archive -Path "$funcAppDir\*" -DestinationPath $zipPath -Force
Write-Host "  Package: $zipPath ($([Math]::Round((Get-Item $zipPath).Length / 1KB)) KB)"

Write-Host "Deploying to $functionAppName ..."
az functionapp deployment source config-zip `
    --name              $functionAppName `
    --resource-group    $rgName `
    --subscription      $SubscriptionId `
    --src               $zipPath `
    --output            none

if ($LASTEXITCODE -ne 0) {
    Write-Error "Function app code deployment failed."
    exit 1
}

Write-Host "Code deployment succeeded." -ForegroundColor Green

# ── Step 3: Configure AAD app registration ───────────────────────────────────

if (-not $SkipAppRegistration -and $AppRegistrationObjectId) {
    Write-Host ""
    Write-Host "=== Step 3: Configuring AAD app registration ===" -ForegroundColor Cyan

    $homePageUrl = "https://$functionHostname/api/Request-jitazaccess"

    & "$scriptDir\Set-JITAppRegistration.ps1" `
        -FunctionAppPrincipalId  $principalId `
        -AppRegistrationObjectId $AppRegistrationObjectId `
        -HomePageUrl             $homePageUrl
}
else {
    Write-Host ""
    Write-Host "=== Step 3: Skipped (no AppRegistrationObjectId supplied) ===" -ForegroundColor Yellow
    Write-Host "  Run Set-JITAppRegistration.ps1 manually when ready:"
    Write-Host "    ./scripts/Set-JITAppRegistration.ps1 -FunctionAppPrincipalId '$principalId' -AppRegistrationObjectId '<objectId>'"
}

# ── Step 4: Reminder — grant permissions on target subscriptions ─────────────

Write-Host ""
Write-Host "=== Step 4: Grant permissions on target subscriptions ===" -ForegroundColor Cyan
Write-Host "  Run the following for each subscription that the JIT app should manage:"
Write-Host ""
Write-Host "  ./scripts/Grant-JITPermissions.ps1 \"" -ForegroundColor White
Write-Host "      -TargetSubscriptionIds @('<target-sub-id>') \"" -ForegroundColor White
Write-Host "      -FunctionAppPrincipalId '$principalId'" -ForegroundColor White
Write-Host ""
Write-Host "=== Deployment complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "JIT API endpoint: https://$functionHostname/api/Request-jitazaccess"
Write-Host ""
Write-Host "Summary of created resources (resource group: $rgName):"
Write-Host "  Storage account:     st$AppName"
Write-Host "  Consumption plan:    asp-$AppName"
Write-Host "  Function app:        func-$AppName"
Write-Host "  Key Vault:           key-$AppName"
Write-Host "  Log Analytics:       log-$AppName"
Write-Host "  Application Insights: appin-$AppName"
