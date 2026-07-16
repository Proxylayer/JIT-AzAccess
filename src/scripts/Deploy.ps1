<#
.SYNOPSIS
    End-to-end deployment of the JIT-AzAccess function app.

.DESCRIPTION
    Runs all deployment steps in order:
      1. Deploy ARM template (resource group + function app + dependencies)
      2. Zip-deploy the function app code
      3. Grant the function app's managed identity, and create the requester role,
         on each target subscription (via Grant-JITPermissions.ps1):
           a. The custom "JIT-AzAccess Manager" RBAC role assigned to the MI on
              each target subscription (so it can write NSG/SQL/Storage/Key Vault
              firewall rules)
           a2. The custom "JIT Requester" role definition made assignable on each
               target subscription. Admins assign this role to end users in the
               subscription they should be able to request JIT access INTO — the
               function app checks the caller holds it in the target subscription.
           b. Graph Application.ReadWrite.OwnedBy + ownership of the AzureTray
              app registration (so it can self-register the JIT base URL on
              cold start for plugin discovery)
      4. Restart the function app so profile.ps1 self-registers its URL on
         the AzureTray host's app registration.

    The "JIT Requester" role is created/assigned ONLY in the target
    subscriptions (via Grant-JITPermissions.ps1). It is NOT needed in the host
    subscription: the Get-JITRules listing endpoint requires only authentication,
    and callers only ever see their own rules.

    Prerequisites:
      - Azure CLI installed and logged in: az login
      - The caller must be Global Administrator OR Application Administrator
        in Entra ID (to grant Graph app role assignments to the MI).

.PARAMETER SubscriptionId
    Subscription where the JIT infrastructure will be deployed.

.PARAMETER Location
    Azure region (e.g. eastus, westeurope).

.PARAMETER AppName
    Short lowercase alphanumeric name used to derive resource names (default: jitazaccess).

.PARAMETER ResourceGroupName
    Resource group to create (default: rg-jit-azaccess).

.PARAMETER AzureTrayAppRegistrationName
    Display name of the AzureTray host's app registration. The function app
    writes its URL as a `jit-baseurl:<sub>=<url>` tag on this app reg on cold
    start so the AzureTray plugin can discover it. (Default: AzureTray)

.PARAMETER ParametersFile
    Path to an azuredeploy.parameters.json file. When supplied, individual
    parameter switches are ignored (except -SubscriptionId).

.PARAMETER TargetSubscriptionIds
    Subscriptions on which the function app should manage NSG/SQL/etc. rules.
    Defaults to the deployment subscription.

    To ADD a new target subscription later, re-run Deploy.ps1 (or just
    Grant-JITPermissions.ps1) including the new subscription in this list.
    The role definition is updated to MERGE the new scope with existing ones,
    so previously-assigned scopes are not dropped.

.PARAMETER SkipGraphPermission
    Skip granting the function app's MI Graph Application.ReadWrite.OwnedBy
    + ownership of the AzureTray app reg. Use when these are pre-granted.

.EXAMPLE
    ./scripts/Deploy.ps1 -SubscriptionId "xxxx" -Location "eastus"

.EXAMPLE
    ./scripts/Deploy.ps1 `
        -SubscriptionId          "xxxx" `
        -Location                "eastus" `
        -AzureTrayAppRegistrationName "AzureTray" `
        -TargetSubscriptionIds   @("subA-guid","subB-guid")
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [string]$Location,
    [string]$AppName                       = 'jitazaccess',
    [string]$ResourceGroupName             = 'rg-jit-azaccess',
    [string]$AzureTrayAppRegistrationName  = 'AzureTray',
    [string]$ParametersFile,
    [string[]]$TargetSubscriptionIds,
    [switch]$SkipGraphPermission
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The function app hardcodes the requester role name 'JIT Requester'; it is no
# longer configurable, so the deployment must use exactly this name.
$JitRequesterRoleName = 'JIT Requester'

$scriptDir    = $PSScriptRoot
$repoRoot     = Split-Path $scriptDir -Parent
$templatePath = Join-Path $repoRoot 'azuredeploy.json'
$funcAppDir   = Join-Path $repoRoot 'functionapp'

# ── Pre-flight ───────────────────────────────────────────────────────────────

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

if (-not $ParametersFile -and -not $Location) {
    $Location = Read-Host "Azure region (e.g. eastus, westeurope)"
}

# ── Step 0: Resolve AzureTray app registration object ID ─────────────────────
# The function app's profile.ps1 PATCHes the AzureTray app reg tags via Graph
# at cold start. The MI holds Application.ReadWrite.OwnedBy which lets it
# read/write OWNED apps but NOT list /applications, so we resolve the object
# ID here (via the operator's delegated Graph perms) and pass it through to
# the ARM template as an app setting.

Write-Host ""
Write-Host "=== Step 0: Resolve AzureTray app registration ===" -ForegroundColor Cyan

$lookupJson = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$AzureTrayAppRegistrationName'&`$select=id,appId" `
    --output json 2>$null
$lookup = if ($lookupJson) { ($lookupJson | ConvertFrom-Json).value } else { @() }

$azureTrayAppObjId = ''
if (@($lookup).Count -eq 0) {
    Write-Warning "App registration '$AzureTrayAppRegistrationName' not found. " +
                  "URL self-register will be disabled until you re-run Deploy.ps1 once it exists."
}
else {
    $azureTrayAppObjId = $lookup[0].id
    Write-Host "  Found app reg '$AzureTrayAppRegistrationName': objectId=$azureTrayAppObjId, appId=$($lookup[0].appId)"
}

# ── Step 1: ARM template ─────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Step 1: Deploying ARM template ===" -ForegroundColor Cyan

$deploymentName = "jit-azaccess-$(Get-Date -Format 'yyyyMMddHHmm')"
$deployLocation = if ($Location) { $Location } else { 'eastus' }

$deployArgs = @(
    'deployment', 'sub', 'create'
    '--name',           $deploymentName
    '--location',       $deployLocation
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
    $deployArgs += "azureTrayAppRegistrationName=$AzureTrayAppRegistrationName"
    $deployArgs += "azureTrayAppRegistrationObjectId=$azureTrayAppObjId"
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
Write-Host "  Function app:   $functionAppName"
Write-Host "  Hostname:       $functionHostname"
Write-Host "  Principal ID:   $principalId"
Write-Host "  Resource group: $rgName"

$siteResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$functionAppName"

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

# ── Step 3a: Grant target-subscription permissions ───────────────────────────

Write-Host ""
Write-Host "=== Step 3a: Grant target-subscription permissions ===" -ForegroundColor Cyan

$grantSubs = if ($TargetSubscriptionIds) { $TargetSubscriptionIds } else { @($SubscriptionId) }

Write-Host "  Granting JIT-AzAccess Manager role on: $($grantSubs -join ', ') ..."
& "$scriptDir\Grant-JITPermissions.ps1" `
    -TargetSubscriptionIds  $grantSubs `
    -FunctionAppPrincipalId $principalId
Write-Host "  Permissions granted." -ForegroundColor Green

# ── Step 3b: Grant Graph permission + AzureTray app reg ownership ─────────────

if ($SkipGraphPermission) {
    Write-Host ""
    Write-Host "=== Step 3b: Skipped (-SkipGraphPermission) ===" -ForegroundColor Yellow
    Write-Host "  Function app cold-start URL self-register will fail until you grant:"
    Write-Host "    1. Graph Application.ReadWrite.OwnedBy app role to MI '$principalId'"
    Write-Host "    2. Ownership of '$AzureTrayAppRegistrationName' app reg to the MI"
}
else {
    Write-Host ""
    Write-Host "=== Step 3b: Grant Graph permission + AzureTray app reg ownership ===" -ForegroundColor Cyan

    $graphSpId = az ad sp list --display-name 'Microsoft Graph' --query '[0].id' --output tsv
    if (-not $graphSpId) {
        Write-Warning "  Could not locate the Microsoft Graph service principal; skipping Graph grant."
    }
    else {
        # Resolve the Application.ReadWrite.OwnedBy app role ID from the Graph SP manifest.
        $graphAppRolesJson = az ad sp show --id $graphSpId --query 'appRoles' --output json
        $graphAppRoles = $graphAppRolesJson | ConvertFrom-Json
        $appRole = $graphAppRoles | Where-Object { $_.value -eq 'Application.ReadWrite.OwnedBy' } | Select-Object -First 1

        if (-not $appRole) {
            Write-Warning "  Could not find 'Application.ReadWrite.OwnedBy' in the Graph SP manifest; skipping."
        }
        else {
            $existingJson = az rest --method GET `
                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" `
                --output json
            $existing = ($existingJson | ConvertFrom-Json).value |
                Where-Object { $_.appRoleId -eq $appRole.id -and $_.resourceId -eq $graphSpId }

            if ($existing) {
                Write-Host "  Graph 'Application.ReadWrite.OwnedBy' already granted to MI."
            }
            else {
                $body = @{ principalId = $principalId; resourceId = $graphSpId; appRoleId = $appRole.id } |
                    ConvertTo-Json -Compress
                az rest --method POST `
                    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" `
                    --body $body --output none
                Write-Host "  Granted Graph 'Application.ReadWrite.OwnedBy' to MI."
            }
        }
    }

    # Make the function app MI an owner of the AzureTray app registration.
    # We resolved $azureTrayAppObjId in Step 0 — reuse it.
    if (-not $azureTrayAppObjId) {
        Write-Warning "  AzureTray app registration '$AzureTrayAppRegistrationName' not found. " +
                      "Cold-start URL self-register will fail until it exists and the MI is an owner."
    }
    else {
        $ownersJson = az rest --method GET `
            --uri "https://graph.microsoft.com/v1.0/applications/$azureTrayAppObjId/owners" `
            --output json
        $owners = ($ownersJson | ConvertFrom-Json).value
        $alreadyOwner = $owners | Where-Object { $_.id -eq $principalId }

        if ($alreadyOwner) {
            Write-Host "  MI is already an owner of '$AzureTrayAppRegistrationName'."
        }
        else {
            # Write the body to a temp file and use az rest's @filepath shorthand —
            # passing it inline mangles the leading '@' in '@odata.id' through
            # PowerShell -> cmd -> az.cmd quoting and Graph returns BadRequest.
            $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$principalId" } |
                ConvertTo-Json -Compress
            $bodyPath = Join-Path $env:TEMP 'jit-owner-ref.json'
            $body | Set-Content -Path $bodyPath -Encoding utf8 -NoNewline
            try {
                az rest --method POST `
                    --uri "https://graph.microsoft.com/v1.0/applications/$azureTrayAppObjId/owners/`$ref" `
                    --body "@$bodyPath" --output none
            }
            finally {
                Remove-Item $bodyPath -ErrorAction SilentlyContinue
            }
            Write-Host "  Added MI as owner of '$AzureTrayAppRegistrationName' app reg."
        }
    }
}

# ── Step 3c: Register this deployment's URL as a tag on the AzureTray app reg ─
# profile.ps1 also writes this tag on every cold start, but doing it here with
# the operator's delegated Graph perms means the tag is present the moment
# Deploy.ps1 finishes — no waiting for a cold start, no race with Graph
# propagation of the MI's permissions.

Write-Host ""
Write-Host "=== Step 3c: Register URL tag on '$AzureTrayAppRegistrationName' app reg ===" -ForegroundColor Cyan

if (-not $azureTrayAppObjId) {
    Write-Host "  Skipped: AzureTray app reg object ID unknown."
}
else {
    $tagPrefix = "jit-baseurl:${SubscriptionId}="
    $newTag    = "${tagPrefix}https://$functionHostname"

    $tagsRespJson = az rest --method GET `
        --uri "https://graph.microsoft.com/v1.0/applications/$azureTrayAppObjId`?`$select=tags" `
        --output json
    $existingTags = @()
    if ($tagsRespJson) {
        $resp = $tagsRespJson | ConvertFrom-Json
        if ($resp.tags) { $existingTags = @($resp.tags) }
    }

    $otherTags  = @($existingTags | Where-Object { $_ -notlike "${tagPrefix}*" })
    $mergedTags = @($otherTags + $newTag) | Sort-Object -Unique

    if ((($existingTags | Sort-Object) -join "`n") -eq (($mergedTags | Sort-Object) -join "`n")) {
        Write-Host "  Tag already up to date: $newTag"
    }
    else {
        # ConvertTo-Json unwraps single-element arrays into scalars
        # (Graph then rejects with "expected StartArray"). Use a typed
        # List<string> to keep it as an array even when count == 1.
        $tagList = [System.Collections.Generic.List[string]]::new()
        foreach ($t in $mergedTags) { $tagList.Add([string]$t) }
        $body = @{ tags = $tagList } | ConvertTo-Json -Depth 3

        $bodyPath = Join-Path $env:TEMP 'jit-app-tags.json'
        $body | Set-Content -Path $bodyPath -Encoding utf8 -NoNewline
        try {
            az rest --method PATCH `
                --uri "https://graph.microsoft.com/v1.0/applications/$azureTrayAppObjId" `
                --body "@$bodyPath" --output none
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Tag written: $newTag" -ForegroundColor Green
            }
            else {
                Write-Warning "  Tag PATCH failed (exit $LASTEXITCODE). profile.ps1 will retry on the next cold start."
            }
        }
        finally {
            Remove-Item $bodyPath -ErrorAction SilentlyContinue
        }
    }
}

# ── Step 4: Restart function app so profile.ps1 self-registers the URL ──────

Write-Host ""
Write-Host "=== Step 4: Restart function app (triggers cold-start URL self-register) ===" -ForegroundColor Cyan

if (-not $azureTrayAppObjId) {
    Write-Host "  Skipped: AzureTray app reg object ID unknown — profile.ps1 would no-op."
}
else {
    az functionapp restart `
        --name           $functionAppName `
        --resource-group $rgName `
        --subscription   $SubscriptionId `
        --output         none
    Write-Host "  Restart triggered."

    # Send an unauthenticated probe so the runtime actually warms up and
    # profile.ps1 runs. A 401/403 response is fine — it just means the
    # worker booted, which is exactly what we need.
    $probeUrl = "https://$functionHostname/api/Get-JITRules"
    Write-Host "  Warmup probe: GET $probeUrl (expect 401/403)..."
    try {
        $resp = Invoke-WebRequest -Uri $probeUrl -Method GET -SkipHttpErrorCheck -TimeoutSec 60
        Write-Host "  Warmup probe returned HTTP $($resp.StatusCode) — profile.ps1 has run."
    }
    catch {
        Write-Host "  Warmup probe failed (non-fatal): $_" -ForegroundColor Yellow
    }
}

# ── Done ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Deployment complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "JIT function app base URL: https://$functionHostname"
Write-Host "Site resource ID:          $siteResourceId"
Write-Host ""
Write-Host "Plugin auto-discovery: no plugin settings required. Users sign in to"
Write-Host "the tenant in AzureTray; the plugin reads the jit-baseurl:<sub>=<url> tag from the"
Write-Host "'$AzureTrayAppRegistrationName' app reg tags (written by profile.ps1 on cold start)."
if (-not $azureTrayAppObjId) {
    Write-Host ""
    Write-Host "  WARNING: AzureTray app reg '$AzureTrayAppRegistrationName' was not found." -ForegroundColor Yellow
    Write-Host "  Sign in to that tenant from AzureTray once (so the host provisions the app reg)," -ForegroundColor Yellow
    Write-Host "  then re-run Deploy.ps1 to wire up URL self-register." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "To grant users access, assign the '$JitRequesterRoleName' role to them in the"
Write-Host "subscription(s) they should be able to request JIT access into, e.g.:"
Write-Host "  /subscriptions/<targetSubscriptionId>"
Write-Host "The function app checks the caller holds the role in the target subscription"
Write-Host "named in each request. Listing your own rules (Get-JITRules) needs only"
Write-Host "authentication — no role assignment is required."
Write-Host ""
Write-Host "Summary of created resources (resource group: $rgName):"
Write-Host "  Storage account:  st$AppName"
Write-Host "  Consumption plan: asp-$AppName"
Write-Host "  Function app:     func-$AppName"
