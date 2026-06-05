<#
.SYNOPSIS
    One-time setup: grants the JIT function app's managed identity the
    Application.ReadWrite.OwnedBy Graph permission and makes it an owner
    of the JIT app registration so it can self-update its homePageUrl.

.PARAMETER FunctionAppPrincipalId
    Object ID of the function app's system-assigned managed identity.
    Retrieve after deployment:
      az functionapp identity show --name <funcName> --resource-group <rgName> --query principalId -o tsv

.PARAMETER AppRegistrationObjectId
    Object ID (not appId/clientId) of the JIT app registration.
    Retrieve: az ad app show --id <appId> --query id -o tsv

.PARAMETER HomePageUrl
    If specified, also sets the homePageUrl immediately. Otherwise the
    function app self-updates it on its first cold start.

.EXAMPLE
    ./Set-JITAppRegistration.ps1 `
        -FunctionAppPrincipalId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -AppRegistrationObjectId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
#>
param(
    [Parameter(Mandatory)][string]$FunctionAppPrincipalId,
    [Parameter(Mandatory)][string]$AppRegistrationObjectId,
    [string]$HomePageUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Microsoft Graph app ID (constant across all tenants)
$graphAppId = '00000003-0000-0000-c000-000000000000'

# Application.ReadWrite.OwnedBy role ID on Microsoft Graph
$appReadWriteOwnedById = '18a4783c-866b-4cc7-a460-3d5e5662c884'

Write-Host "Looking up Microsoft Graph service principal..."
$graphSpId = az ad sp show --id $graphAppId --query id --output tsv

if (-not $graphSpId) {
    Write-Error "Could not find Microsoft Graph service principal. Ensure you are logged in: az login"
    exit 1
}

# ── 1. Grant Application.ReadWrite.OwnedBy ────────────────────────────────────

Write-Host "Checking existing Graph app role assignments for the managed identity..."
$existing = az rest `
    --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionAppPrincipalId/appRoleAssignments" `
    --query "value[?appRoleId=='$appReadWriteOwnedById'].id" `
    --output tsv 2>$null

if ($existing) {
    Write-Host "Application.ReadWrite.OwnedBy already assigned — skipping."
}
else {
    Write-Host "Granting Application.ReadWrite.OwnedBy to managed identity '$FunctionAppPrincipalId'..."
    az rest `
        --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionAppPrincipalId/appRoleAssignments" `
        --body "{`"principalId`":`"$FunctionAppPrincipalId`",`"resourceId`":`"$graphSpId`",`"appRoleId`":`"$appReadWriteOwnedById`"}" `
        --output none
    Write-Host "  Granted."
}

# ── 2. Add managed identity as owner of the app registration ─────────────────

Write-Host "Checking existing owners of app registration '$AppRegistrationObjectId'..."
$owners = az rest `
    --method GET `
    --uri "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId/owners" `
    --query "value[?id=='$FunctionAppPrincipalId'].id" `
    --output tsv 2>$null

if ($owners) {
    Write-Host "Managed identity is already an owner — skipping."
}
else {
    Write-Host "Adding managed identity as owner of the app registration..."
    az rest `
        --method POST `
        --uri "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId/owners/`$ref" `
        --body "{`"@odata.id`":`"https://graph.microsoft.com/v1.0/directoryObjects/$FunctionAppPrincipalId`"}" `
        --output none
    Write-Host "  Added."
}

# ── 3. Optionally set homePageUrl now ─────────────────────────────────────────

if ($HomePageUrl) {
    Write-Host "Setting homePageUrl to '$HomePageUrl'..."
    az rest `
        --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId" `
        --body "{`"web`":{`"homePageUrl`":`"$HomePageUrl`"}}" `
        --output none
    Write-Host "  Updated."
}

# ── 4. Add JIT.Requester and JIT.Admin app roles ──────────────────────────────
#
#   JIT.Requester  — must be activated (via PIM eligibility) before a user can
#                    call any JIT endpoint.  Assign as ELIGIBLE in PIM.
#   JIT.Admin      — grants visibility into all active rules and allows revoking
#                    rules on behalf of other users.  Assign sparingly.
#
#   After adding these roles, assign them to users/groups via:
#     az ad app update --id <appId> --app-roles @app-roles.json
#   or via the Entra ID portal → App registrations → App roles.

Write-Host ""
Write-Host "Checking app roles on registration '$AppRegistrationObjectId'..."

$existingRoles = az rest `
    --method GET `
    --uri "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId" `
    --query "appRoles[].value" `
    --output tsv 2>$null

$rolesToAdd = @()

if ('JIT.Requester' -notin @($existingRoles -split "`n" | ForEach-Object { $_.Trim() })) {
    $rolesToAdd += @{
        id                  = [guid]::NewGuid().ToString()
        displayName         = 'JIT Requester'
        description         = 'Can request and revoke JIT access. Must be activated via PIM.'
        value               = 'JIT.Requester'
        allowedMemberTypes  = @('User', 'Application')
        isEnabled           = $true
    }
    Write-Host "  Will add role: JIT.Requester"
}
else {
    Write-Host "  JIT.Requester already exists — skipping."
}

if ('JIT.Admin' -notin @($existingRoles -split "`n" | ForEach-Object { $_.Trim() })) {
    $rolesToAdd += @{
        id                  = [guid]::NewGuid().ToString()
        displayName         = 'JIT Admin'
        description         = 'Can view all active JIT rules and revoke rules for any user.'
        value               = 'JIT.Admin'
        allowedMemberTypes  = @('User', 'Application')
        isEnabled           = $true
    }
    Write-Host "  Will add role: JIT.Admin"
}
else {
    Write-Host "  JIT.Admin already exists — skipping."
}

if ($rolesToAdd.Count -gt 0) {
    # Merge with existing roles (Graph requires the full array on PATCH).
    $currentRolesJson = az rest `
        --method GET `
        --uri "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId" `
        --query "appRoles" `
        --output json

    $currentRoles = $currentRolesJson | ConvertFrom-Json
    $mergedRoles  = @($currentRoles) + $rolesToAdd
    $body         = @{ appRoles = $mergedRoles } | ConvertTo-Json -Depth 5 -Compress

    az rest `
        --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId" `
        --body $body `
        --output none

    Write-Host "  App roles added successfully."
    Write-Host ""
    Write-Host "NEXT STEPS:"
    Write-Host "  1. Open Entra ID → App registrations → JIT-AzAccess → App roles"
    Write-Host "     to verify both roles appear."
    Write-Host "  2. Go to Entra ID PIM → Azure AD roles → Add eligible assignment"
    Write-Host "     and assign JIT.Requester as ELIGIBLE to your users/groups."
    Write-Host "  3. Users must activate JIT.Requester via PIM before calling any"
    Write-Host "     JIT endpoint — including the AzureTray plugin."
}

Write-Host ""
Write-Host "Done. The function app will self-update homePageUrl on its next cold start."
