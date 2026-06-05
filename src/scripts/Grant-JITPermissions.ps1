<#
.SYNOPSIS
    Creates or updates a custom "JIT-AzAccess Manager" RBAC role and assigns it
    to the JIT function app's managed identity on one or more target subscriptions.

.PARAMETER TargetSubscriptionIds
    One or more subscription IDs where the function app should manage resources.

.PARAMETER FunctionAppPrincipalId
    Object ID of the function app's system-assigned managed identity.

.PARAMETER FunctionAppName
    Name of the function app.

.PARAMETER ResourceGroupName
    Resource group containing the function app.

.PARAMETER FunctionAppSubscriptionId
    Subscription hosting the function app.
#>

param(
    [Parameter(Mandatory)]
    [string[]]$TargetSubscriptionIds,

    [string]$FunctionAppPrincipalId,

    [string]$FunctionAppName,
    [string]$ResourceGroupName,
    [string]$FunctionAppSubscriptionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (
    -not $FunctionAppPrincipalId -and
    (
        -not $FunctionAppName -or
        -not $ResourceGroupName -or
        -not $FunctionAppSubscriptionId
    )
) {
    Write-Error "Provide either -FunctionAppPrincipalId, or all three of -FunctionAppName, -ResourceGroupName, and -FunctionAppSubscriptionId."
    exit 1
}

$roleName = 'JIT-AzAccess Manager'

$roleDescription = 'Manages temporary IP allowlist entries on NSGs, SQL servers, storage accounts, and key vaults for JIT-AzAccess.'

$roleActions = @(
    'Microsoft.Network/networkSecurityGroups/read'
    'Microsoft.Network/networkSecurityGroups/write'
    'Microsoft.Network/networkSecurityGroups/securityRules/read'
    'Microsoft.Network/networkSecurityGroups/securityRules/write'
    'Microsoft.Network/networkSecurityGroups/securityRules/delete'

    'Microsoft.Sql/servers/read'
    'Microsoft.Sql/servers/firewallRules/read'
    'Microsoft.Sql/servers/firewallRules/write'
    'Microsoft.Sql/servers/firewallRules/delete'

    'Microsoft.Storage/storageAccounts/read'
    'Microsoft.Storage/storageAccounts/write'

    'Microsoft.KeyVault/vaults/read'
    'Microsoft.KeyVault/vaults/write'

    # Required by the function app to evaluate the JIT Requester RBAC role
    # assignment of each caller before granting access.
    'Microsoft.Authorization/roleAssignments/read'
    'Microsoft.Authorization/roleDefinitions/read'
)

# Retrieve managed identity principal ID if not supplied

if (-not $FunctionAppPrincipalId) {

    Write-Host "Retrieving principal ID for '$FunctionAppName'..."

    $FunctionAppPrincipalId = az functionapp identity show `
        --name $FunctionAppName `
        --resource-group $ResourceGroupName `
        --subscription $FunctionAppSubscriptionId `
        --query principalId `
        --output tsv

    if (
        -not $FunctionAppPrincipalId -or
        $FunctionAppPrincipalId -eq 'null'
    ) {
        Write-Error "Could not retrieve principal ID. Ensure the function app exists and has a system-assigned identity enabled."
        exit 1
    }
}

Write-Host "Principal ID: $FunctionAppPrincipalId"

# Build assignable scopes

$assignableScopes = @()

foreach ($subId in $TargetSubscriptionIds) {
    $assignableScopes += "/subscriptions/$subId"
}

$tempRolePath = Join-Path $env:TEMP "jitrole.json"

Write-Host ""
Write-Host "Creating or updating role definition '$roleName'..."

$existingRoleJson = az role definition list `
    --name $roleName `
    --output json

$existingRole = $null

if ($existingRoleJson -and $existingRoleJson -ne '[]') {
    $existingRole = $existingRoleJson | ConvertFrom-Json | Select-Object -First 1
}

if ($existingRole) {

    Write-Host "  Existing role found (id $($existingRole.name)). Updating..."

    # Merge the new scopes with the existing ones so re-running this with a
    # different subset of target subs doesn't silently drop subscriptions
    # we've already assigned the role on. (Multi-subscription safe.)
    $existingScopes  = @($existingRole.assignableScopes)
    $assignableScopes = @(($existingScopes + $assignableScopes) | Sort-Object -Unique)

    if ($existingScopes.Count -ne $assignableScopes.Count) {
        $added = $assignableScopes | Where-Object { $_ -notin $existingScopes }
        Write-Host "  Adding $($added.Count) new assignable scope(s): $($added -join ', ')"
    }
}

# Use the ARM-native camelCase shape with nested permissions[]. The legacy
# PascalCase/flat form works on CREATE but trips a KeyError bug inside
# az role definition update when an Id is provided. This shape is exactly
# what `az role definition list` emits, so it round-trips cleanly through
# create or update.
$roleDefinition = [ordered]@{
    roleName         = $roleName
    description      = $roleDescription
    assignableScopes = $assignableScopes
    permissions      = @(
        [ordered]@{
            actions        = $roleActions
            notActions     = @()
            dataActions    = @()
            notDataActions = @()
        }
    )
}

# For update, include the existing role's full ARM path under 'id'.
# az role definition update pops 'Id' or 'id' from the body to identify the
# role; without it, az logs "Role 'id' is missing" and falls back to a
# lookup-by-name. The .name on the existing object is the GUID alone, but
# az wants the full /subscriptions/.../roleDefinitions/<guid> path, which
# is what .id holds.
if ($existingRole) { $roleDefinition['id'] = $existingRole.id }

$roleDefinition |
    ConvertTo-Json -Depth 20 |
    Set-Content -Path $tempRolePath -Encoding UTF8

if ($existingRole) {
    az role definition update `
        --role-definition "@$tempRolePath" `
        --output none `
        --only-show-errors

    Write-Host "  Role updated."
}
else {
    Write-Host "  Role does not exist. Creating..."

    az role definition create `
        --role-definition "@$tempRolePath" `
        --output none `
        --only-show-errors

    Write-Host "  Role created."
}

# Assign role on each subscription

foreach ($subId in $TargetSubscriptionIds) {

    $scope = "/subscriptions/$subId"

    Write-Host ""
    Write-Host "Processing role assignment for subscription: $subId"

    $alreadyAssigned = az role assignment list `
        --assignee $FunctionAppPrincipalId `
        --role $roleName `
        --scope $scope `
        --query "[0].id" `
        --output tsv 2>$null

    if ($alreadyAssigned) {

        Write-Host "  Role already assigned on $scope - no change."
    }
    else {

        Write-Host "  Assigning '$roleName' on $scope..."

        az role assignment create `
            --assignee-object-id $FunctionAppPrincipalId `
            --assignee-principal-type ServicePrincipal `
            --role $roleName `
            --scope $scope `
            --output none

        Write-Host "  Assigned."
    }
}

Write-Host ""
Write-Host (
    "Done. The function app can now manage JIT IP rules on: {0}" -f
    ($TargetSubscriptionIds -join ', ')
)