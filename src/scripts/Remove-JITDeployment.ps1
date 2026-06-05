<#
.SYNOPSIS
    Reverses everything Deploy.ps1 (and the historical app-registration scripts)
    created for JIT-AzAccess. Idempotent — safe to re-run after a partial
    cleanup.

.DESCRIPTION
    Steps, in dependency order so each removal succeeds even if the next ones
    have already been done by hand:

      1. Resolve the function app's managed identity (if the function app
         still exists) so we can clean up Entra-side artefacts that reference it.
      2. Remove the JIT base URL note from the AzureTray app registration
         (preserving any other keys in the notes JSON).
      3. Remove the function app MI from the AzureTray app reg's owners list.
      4. Revoke the Graph 'Application.ReadWrite.OwnedBy' app role assignment
         from the function app MI.
      5. Remove all role assignments of the 'JIT Requester' role at the
         function app site scope.
      6. Remove all role assignments of the 'JIT-AzAccess Manager' role from
         the function app MI on each target subscription.
      7. Delete the 'JIT Requester' and 'JIT-AzAccess Manager' custom role
         definitions (only when no assignments remain).
      8. Delete the resource group (cascades storage, plan, function app, MI).
      9. Optionally delete the legacy 'JIT-AzAccess' API app registration that
         the now-deleted New-JITAppRegistration.ps1 used to create.

    Use -WhatIf to preview without making changes; use -Force to skip the
    final confirmation prompt.

.PARAMETER SubscriptionId
    Subscription that hosts the function app / where the role definitions live.

.PARAMETER AppName
    Short lowercase alphanumeric name used to derive resource names. Default: jitazaccess

.PARAMETER ResourceGroupName
    Resource group to delete. Default: rg-jit-azaccess

.PARAMETER AzureTrayAppRegistrationName
    Display name of the AzureTray host app registration (whose notes + owners
    we clean up). Default: AzureTray

.PARAMETER JitRequesterRoleName
    Name of the custom RBAC role that gates user access. Default: "JIT Requester"

.PARAMETER JitManagerRoleName
    Name of the function app MI's custom RBAC role. Default: "JIT-AzAccess Manager"

.PARAMETER TargetSubscriptionIds
    Subscriptions where the function app MI holds the manager role.
    Defaults to the deployment subscription.

.PARAMETER LegacyJitAppRegistrationName
    Display name of the legacy JIT-specific API app registration created by
    the deleted New-JITAppRegistration.ps1. Set to empty string to skip this
    cleanup. Default: "JIT-AzAccess"

.PARAMETER RemoveLegacyAppRegistration
    Switch to actually delete the legacy app registration when found.
    When omitted, the script reports it but does not delete it.

.PARAMETER KeepFunctionApp
    Soft cleanup. Preserves the resource group, function app, managed identity,
    MI's ownership of the AzureTray app reg, and the MI's Graph 'OwnedBy' app
    role assignment (so you don't have to re-run admin consent). Still removes
    the custom RBAC role definitions and ALL their role assignments, so you can
    redeploy from a clean role/assignment state with Deploy.ps1.

    Note: after this, the function app's MI loses its 'JIT-AzAccess Manager'
    assignment and the function app cannot grant JIT until Deploy.ps1 is re-run.

.PARAMETER Force
    Skip the final confirmation prompt.

.EXAMPLE
    # Dry-run to see what would happen
    ./scripts/Remove-JITDeployment.ps1 -SubscriptionId <subId> -WhatIf

.EXAMPLE
    # Real cleanup, including legacy app reg, no prompt
    ./scripts/Remove-JITDeployment.ps1 -SubscriptionId <subId> -RemoveLegacyAppRegistration -Force

.EXAMPLE
    # Soft cleanup — reset roles/assignments but keep function app + MI + consent
    ./scripts/Remove-JITDeployment.ps1 -SubscriptionId <subId> -KeepFunctionApp -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [string]   $AppName                       = 'jitazaccess',
    [string]   $ResourceGroupName             = 'rg-jit-azaccess',
    [string]   $AzureTrayAppRegistrationName  = 'AzureTray',
    [string]   $JitRequesterRoleName          = 'JIT Requester',
    [string]   $JitManagerRoleName            = 'JIT-AzAccess Manager',
    [string[]] $TargetSubscriptionIds,
    [string]   $LegacyJitAppRegistrationName  = 'JIT-AzAccess',
    [switch]   $RemoveLegacyAppRegistration,
    [switch]   $KeepFunctionApp,
    [switch]   $Force
)

# Cleanup is idempotent — we expect many az calls to return "not found", which
# is a non-zero exit. Don't let that abort the script.
$ErrorActionPreference = 'Continue'
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Step { param($msg) Write-Host "" ; Write-Host "=== $msg ===" -ForegroundColor Cyan }
function Info { param($msg) Write-Host "  $msg" }
function Ok   { param($msg) Write-Host "  $msg" -ForegroundColor Green }
function Warn { param($msg) Write-Host "  $msg" -ForegroundColor Yellow }

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI not found. Install from https://aka.ms/installazurecliwindows"
    exit 1
}

$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Error "Not logged in. Run: az login"
    exit 1
}

Info "Signed in as: $($account.user.name)"
az account set --subscription $SubscriptionId | Out-Null

if (-not $TargetSubscriptionIds) { $TargetSubscriptionIds = @($SubscriptionId) }

$functionAppName = "func-$AppName"

# ── Confirmation gate ────────────────────────────────────────────────────────

if (-not $Force -and -not $WhatIfPreference) {
    Write-Host ""
    if ($KeepFunctionApp) {
        Write-Host "Soft cleanup (-KeepFunctionApp) — about to remove:" -ForegroundColor Yellow
        Write-Host "  '$JitRequesterRoleName' role + all its assignments (any scope)"
        Write-Host "  '$JitManagerRoleName' role + all its assignments (any scope)"
        Write-Host ""
        Write-Host "Will PRESERVE:"
        Write-Host "  Resource group $ResourceGroupName + function app + MI"
        Write-Host "  MI's ownership of app reg '$AzureTrayAppRegistrationName'"
        Write-Host "  MI's Graph 'Application.ReadWrite.OwnedBy' app role assignment"
        Write-Host "  jitBaseUrl note on '$AzureTrayAppRegistrationName' (refreshed on next cold start)"
    } else {
        Write-Host "About to remove the following:" -ForegroundColor Yellow
        Write-Host "  Resource group           : $ResourceGroupName  (subscription $SubscriptionId)"
        Write-Host "  Function app             : $functionAppName"
        Write-Host "  '$JitRequesterRoleName' role + all its assignments"
        Write-Host "  '$JitManagerRoleName' role + all its assignments"
        Write-Host "  'jitBaseUrl' note + MI ownership on app reg '$AzureTrayAppRegistrationName'"
        Write-Host "  Graph 'Application.ReadWrite.OwnedBy' app role assignment on the function app MI"
    }
    if ($RemoveLegacyAppRegistration -and $LegacyJitAppRegistrationName) {
        Write-Host "  Legacy app registration  : $LegacyJitAppRegistrationName" -ForegroundColor Red
    }
    Write-Host ""
    $resp = Read-Host "Type 'remove' to proceed"
    if ($resp -ne 'remove') {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# ── Step 1: Resolve function app MI principal ID ─────────────────────────────

Step 'Step 1: Resolving function app managed identity'

$principalId = (az functionapp identity show `
    --name           $functionAppName `
    --resource-group $ResourceGroupName `
    --subscription   $SubscriptionId `
    --query          principalId `
    --output         tsv 2>$null)
if ($principalId) { $principalId = $principalId.Trim() }

if (-not $principalId -or $principalId -eq 'null') {
    Warn "Function app '$functionAppName' not found (or has no MI) — skipping MI-scoped cleanup."
    $principalId = $null
}
else {
    Ok "Managed identity principal ID: $principalId"
}

# ── Step 2: Drop this deployment's jit-baseurl:<subId>=… tag ─────────────────
# Always look up the app reg (Step 3 needs it too), but only PATCH the tags
# when doing a full teardown — soft cleanup leaves the tag alone since the
# function app refreshes it on the next cold start.

Step "Step 2: Remove 'jit-baseurl:$SubscriptionId=…' tag from '$AzureTrayAppRegistrationName'"

$appRegLookupJson = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$AzureTrayAppRegistrationName'&`$select=id,tags" `
    --output json 2>$null
$appReg = $null
if ($appRegLookupJson) {
    $appReg = ($appRegLookupJson | ConvertFrom-Json).value | Select-Object -First 1
}

if ($KeepFunctionApp) {
    Info "Soft cleanup — leaving tags unchanged (function app refreshes its tag on next cold start)."
}
elseif (-not $appReg) {
    Warn "App registration '$AzureTrayAppRegistrationName' not found — skipping."
}
else {
    $existingTags = if ($appReg.tags) { @($appReg.tags) } else { @() }
    $tagPrefix    = "jit-baseurl:${SubscriptionId}="

    $ourTags  = @($existingTags | Where-Object { $_ -like "${tagPrefix}*" })
    $keptTags = @($existingTags | Where-Object { $_ -notlike "${tagPrefix}*" })

    if ($ourTags.Count -eq 0) {
        Info "No 'jit-baseurl:$SubscriptionId=…' tag found on the app reg — nothing to remove."
    }
    elseif ($PSCmdlet.ShouldProcess("'$AzureTrayAppRegistrationName' tags",
                                    "Remove $($ourTags.Count) JIT tag(s) for sub $SubscriptionId")) {
        # ConvertTo-Json unwraps single-element arrays — force the array
        # shape via List<string> so Graph doesn't 400 on count == 1.
        $tagList = [System.Collections.Generic.List[string]]::new()
        foreach ($t in $keptTags) { $tagList.Add([string]$t) }
        $body = @{ tags = $tagList } | ConvertTo-Json -Depth 3

        # Inline body has the same '@' quirk as Step 3c — write to temp file.
        $bodyPath = Join-Path $env:TEMP 'jit-remove-tags.json'
        $body | Set-Content -Path $bodyPath -Encoding utf8 -NoNewline
        try {
            az rest --method PATCH `
                --uri "https://graph.microsoft.com/v1.0/applications/$($appReg.id)" `
                --body "@$bodyPath" --output none
            if ($LASTEXITCODE -eq 0) {
                foreach ($t in $ourTags) { Ok "Removed tag: $t" }
            } else {
                Warn "PATCH on app registration tags returned exit $LASTEXITCODE."
            }
        }
        finally {
            Remove-Item $bodyPath -ErrorAction SilentlyContinue
        }
    }
}

# ── Step 3: Remove MI from AzureTray app reg owners ──────────────────────────

if ($KeepFunctionApp) {
    Step "Step 3: (skipped under -KeepFunctionApp; MI keeps app reg ownership)"
}
elseif ($appReg -and $principalId) {
    Step "Step 3: Remove function app MI from '$AzureTrayAppRegistrationName' owners"

    $ownersJson = az rest --method GET `
        --uri "https://graph.microsoft.com/v1.0/applications/$($appReg.id)/owners" `
        --output json 2>$null
    $isOwner = $false
    if ($ownersJson) {
        $owners = ($ownersJson | ConvertFrom-Json).value
        $isOwner = ($owners | Where-Object { $_.id -eq $principalId } | Measure-Object).Count -gt 0
    }

    if (-not $isOwner) {
        Info "MI is not an owner — skipping."
    }
    elseif ($PSCmdlet.ShouldProcess("'$AzureTrayAppRegistrationName' app reg owners", "Remove MI $principalId")) {
        az rest --method DELETE `
            --uri "https://graph.microsoft.com/v1.0/applications/$($appReg.id)/owners/$principalId/`$ref" `
            --output none
        Ok "Removed MI from owners."
    }
}

# ── Step 4: Revoke Graph app role assignment from MI ─────────────────────────

if ($KeepFunctionApp) {
    Step "Step 4: (skipped under -KeepFunctionApp; MI keeps Graph 'OwnedBy' app role)"
}
elseif ($principalId) {
    Step "Step 4: Revoke Graph 'Application.ReadWrite.OwnedBy' app role assignment"

    $assignmentsJson = az rest --method GET `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" `
        --output json 2>$null
    $assignments = if ($assignmentsJson) { @(($assignmentsJson | ConvertFrom-Json).value) } else { @() }

    $graphSpId = az ad sp list --display-name 'Microsoft Graph' --query '[0].id' --output tsv 2>$null
    if ($graphSpId) { $graphSpId = $graphSpId.Trim() }

    if (-not $graphSpId) {
        Warn "Could not locate the Microsoft Graph service principal."
    }
    else {
        $graphAssignments = @($assignments | Where-Object { $_.resourceId -eq $graphSpId })
        if ($graphAssignments.Count -eq 0) {
            Info "MI has no Graph app role assignments — skipping."
        }
        else {
            foreach ($a in $graphAssignments) {
                if ($PSCmdlet.ShouldProcess("MI appRoleAssignment $($a.id)", "Delete")) {
                    az rest --method DELETE `
                        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments/$($a.id)" `
                        --output none
                    Ok "Revoked app role assignment $($a.id)."
                }
            }
        }
    }
}

# ── Step 5: Remove all role assignments for JIT Requester (any scope) ────────

Step "Step 5: Remove all '$JitRequesterRoleName' role assignments"

$siteAssignmentsJson = az role assignment list `
    --role     $JitRequesterRoleName `
    --all `
    --output   json 2>$null
$siteAssignments = if ($siteAssignmentsJson) { @($siteAssignmentsJson | ConvertFrom-Json) } else { @() }

if ($siteAssignments.Count -eq 0) {
    Info "No '$JitRequesterRoleName' assignments found."
}
else {
    foreach ($a in $siteAssignments) {
        $principalLabel = if ($a.principalName) { $a.principalName } else { $a.principalId }
        if ($PSCmdlet.ShouldProcess("role assignment $($a.id)", "Delete")) {
            az role assignment delete --ids $a.id --output none
            if ($LASTEXITCODE -eq 0) {
                Ok "Removed assignment for principal $principalLabel at $($a.scope)."
            } else {
                Warn "Failed to remove assignment for principal $principalLabel at $($a.scope)."
            }
        }
    }
}

# ── Step 6: Remove all role assignments for JIT Manager (any scope) ─────────

Step "Step 6: Remove all '$JitManagerRoleName' role assignments"

$mgrAssignmentsJson = az role assignment list `
    --role   $JitManagerRoleName `
    --all `
    --output json 2>$null
$mgrAssignments = if ($mgrAssignmentsJson) { @($mgrAssignmentsJson | ConvertFrom-Json) } else { @() }

if ($mgrAssignments.Count -eq 0) {
    Info "No '$JitManagerRoleName' assignments found."
}
else {
    foreach ($a in $mgrAssignments) {
        $principalLabel = if ($a.principalName) { $a.principalName } else { $a.principalId }
        if ($PSCmdlet.ShouldProcess("role assignment $($a.id)", "Delete")) {
            az role assignment delete --ids $a.id --output none
            if ($LASTEXITCODE -eq 0) {
                Ok "Removed assignment for principal $principalLabel at $($a.scope)."
            } else {
                Warn "Failed to remove assignment for principal $principalLabel at $($a.scope)."
            }
        }
    }
}

# ── Step 7: Delete custom role definitions ───────────────────────────────────

Step 'Step 7: Delete custom role definitions'

foreach ($roleName in @($JitRequesterRoleName, $JitManagerRoleName)) {
    $roleJson = az role definition list --name $roleName --output json 2>$null
    $role = if ($roleJson) { ($roleJson | ConvertFrom-Json | Select-Object -First 1) } else { $null }
    if (-not $role) {
        Info "Role definition '$roleName' not found — skipping."
        continue
    }

    # Verify no stale assignments remain (role definitions can't be deleted while in use).
    $stillAssignedJson = az role assignment list --role $roleName --all --output json 2>$null
    $stillAssigned = if ($stillAssignedJson) { @($stillAssignedJson | ConvertFrom-Json) } else { @() }
    if ($stillAssigned.Count -gt 0) {
        Warn "Role '$roleName' still has $($stillAssigned.Count) assignment(s) — cannot delete the definition."
        Warn "  Remove assignments manually (e.g. via the portal) and re-run."
        continue
    }

    if ($PSCmdlet.ShouldProcess("role definition '$roleName'", "Delete")) {
        az role definition delete --name $roleName --output none
        Ok "Deleted role definition '$roleName'."
    }
}

# ── Step 8: Delete resource group ────────────────────────────────────────────

if ($KeepFunctionApp) {
    Step "Step 8: (skipped under -KeepFunctionApp; resource group + function app preserved)"
}
else {
    Step "Step 8: Delete resource group '$ResourceGroupName'"

    $rgExists = az group exists --name $ResourceGroupName --subscription $SubscriptionId --output tsv 2>$null
    if ($rgExists -ne 'true') {
        Info "Resource group does not exist — skipping."
    }
    elseif ($PSCmdlet.ShouldProcess("resource group $ResourceGroupName", "Delete")) {
        az group delete --name $ResourceGroupName --subscription $SubscriptionId --yes --no-wait --output none
        Ok "Resource group delete initiated (running async — check 'az group show -n $ResourceGroupName' for progress)."
    }
}

# ── Step 9: (Optional) Legacy JIT-AzAccess app registration ──────────────────

if ($LegacyJitAppRegistrationName) {
    Step "Step 9: Legacy '$LegacyJitAppRegistrationName' app registration"

    $legacyJson = az ad app list --display-name $LegacyJitAppRegistrationName --output json 2>$null
    $legacy = if ($legacyJson) { @($legacyJson | ConvertFrom-Json) } else { @() }

    if ($legacy.Count -eq 0) {
        Info "No app registration named '$LegacyJitAppRegistrationName' found."
    }
    elseif (-not $RemoveLegacyAppRegistration) {
        Warn "Found app registration '$LegacyJitAppRegistrationName' (appId: $($legacy[0].appId))."
        Warn "  Pass -RemoveLegacyAppRegistration to delete it."
    }
    else {
        foreach ($app in $legacy) {
            if ($PSCmdlet.ShouldProcess("app registration $($app.displayName) ($($app.appId))", "Delete")) {
                az ad app delete --id $app.appId --output none
                Ok "Deleted app registration $($app.displayName) ($($app.appId))."
            }
        }
    }
}

Write-Host ""
Write-Host "Cleanup complete." -ForegroundColor Green
Write-Host ""
Write-Host "Notes:"
if ($KeepFunctionApp) {
    Write-Host "  - Soft cleanup: the function app and its MI are intact, but the function app"
    Write-Host "    cannot grant JIT access until you re-run Deploy.ps1 to recreate the"
    Write-Host "    '$JitManagerRoleName' / '$JitRequesterRoleName' roles + role assignments."
    Write-Host "  - Deploy.ps1 is idempotent and will reuse the existing function app + MI."
} else {
    Write-Host "  - Resource group deletion is async; the function app MI service principal"
    Write-Host "    will be tombstoned by Entra ID a few minutes after the RG finishes deleting."
    Write-Host "  - If 'Graph Application.ReadWrite.OwnedBy' was granted manually (outside this"
    Write-Host "    deployment) it has NOT been removed by this script — review the function"
    Write-Host "    app MI's app role assignments in Entra ID if you want to be sure."
}
