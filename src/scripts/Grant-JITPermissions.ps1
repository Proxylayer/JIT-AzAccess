<#
.SYNOPSIS
    Creates or updates a custom "JIT-AzAccess Manager" RBAC role and assigns it
    to the JIT function app's managed identity on one or more target subscriptions,
    and creates the "JIT-Requester" custom role definition (assignable in each of
    those subscriptions) that end users must hold to call the JIT API.

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

$roleDescription = 'Manages temporary IP allowlist entries on NSGs, SQL servers, PostgreSQL flexible servers, storage accounts, and key vaults for JIT-AzAccess.'

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

    'Microsoft.DBforPostgreSQL/flexibleServers/read'
    'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read'
    'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write'
    'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/delete'

    'Microsoft.Storage/storageAccounts/read'
    'Microsoft.Storage/storageAccounts/write'

    'Microsoft.KeyVault/vaults/read'
    'Microsoft.KeyVault/vaults/write'

    # Required by the function app to evaluate the JIT-Requester RBAC role
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

# Build the role definition as a flat, PascalCase object and pipe it to az via
# STDIN ("@-"). This is the shape `az role definition create/update` actually
# accepts (it matches the official az docs example); the previous camelCase form
# with a nested permissions[] array, written to a temp file, did not create the
# role reliably in practice.
$roleDefinition = @{
    Name             = $roleName
    Description      = $roleDescription
    IsCustom         = $true
    Actions          = $roleActions
    NotActions       = @()
    DataActions      = @()
    NotDataActions   = @()
    AssignableScopes = $assignableScopes
}

if ($existingRole) {

    # For update, include the existing role's full ARM path under 'Id' so az can
    # identify the role. The .name on the existing object is the bare GUID; az
    # needs the full /subscriptions/.../roleDefinitions/<guid> path, which .id
    # holds.
    $roleDefinition['Id'] = $existingRole.id

    $roleDefinition |
        ConvertTo-Json -Depth 10 -Compress |
        az role definition update `
            --role-definition "@-" `
            --output none `
            --only-show-errors

    Write-Host "  Role updated."
}
else {
    Write-Host "  Role does not exist. Creating..."

    $roleDefinition |
        ConvertTo-Json -Depth 10 -Compress |
        az role definition create `
            --role-definition "@-" `
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

# Create the "JIT-Requester" custom role definition on each target subscription

# This is the role end users must hold — in the subscription they are requesting
# access INTO — to call the JIT API. The function app hardcodes the role name
# 'JIT-Requester', so it must not be renamed here. We create/update the
# DEFINITION only (so it is assignable in each target subscription); assigning
# specific users to it is an operator action (see README), not something this
# script performs. The role grants no Azure control-plane actions by itself —
# it is a pure access marker the function app checks for.

$requesterRoleName        = 'JIT-Requester'
$requesterRoleDescription = 'Permits the holder to request JIT access in this subscription via the JIT-AzAccess function app. Assigned to end users; grants no Azure control-plane actions by itself.'

Write-Host ""
Write-Host "Creating or updating role definition '$requesterRoleName'..."

$existingRequesterJson = az role definition list `
    --name $requesterRoleName `
    --output json

$existingRequester = $null

if ($existingRequesterJson -and $existingRequesterJson -ne '[]') {
    $existingRequester = $existingRequesterJson | ConvertFrom-Json | Select-Object -First 1
}

$requesterScopes = @()

foreach ($subId in $TargetSubscriptionIds) {
    $requesterScopes += "/subscriptions/$subId"
}

if ($existingRequester) {

    Write-Host "  Existing role found (id $($existingRequester.name)). Updating..."

    # Merge new scopes with existing ones so re-running with a different subset
    # of target subs doesn't drop subscriptions the role is already assignable on.
    $existingReqScopes = @($existingRequester.assignableScopes)
    $requesterScopes   = @(($existingReqScopes + $requesterScopes) | Sort-Object -Unique)

    if ($existingReqScopes.Count -ne $requesterScopes.Count) {
        $addedReq = $requesterScopes | Where-Object { $_ -notin $existingReqScopes }
        Write-Host "  Adding $($addedReq.Count) new assignable scope(s): $($addedReq -join ', ')"
    }
}

# Same flat, PascalCase + STDIN ("@-") shape as the manager role above. The
# requester role grants no Azure actions, so Actions is empty.
$requesterRoleDefinition = @{
    Name             = $requesterRoleName
    Description      = $requesterRoleDescription
    IsCustom         = $true
    Actions          = @()
    NotActions       = @()
    DataActions      = @()
    NotDataActions   = @()
    AssignableScopes = $requesterScopes
}

if ($existingRequester) {

    # Full ARM path under 'Id' so az can identify the role on update (see note
    # on the manager role above).
    $requesterRoleDefinition['Id'] = $existingRequester.id

    $requesterRoleDefinition |
        ConvertTo-Json -Depth 10 -Compress |
        az role definition update `
            --role-definition "@-" `
            --output none `
            --only-show-errors

    Write-Host "  Role updated."
}
else {
    Write-Host "  Role does not exist. Creating..."

    $requesterRoleDefinition |
        ConvertTo-Json -Depth 10 -Compress |
        az role definition create `
            --role-definition "@-" `
            --output none `
            --only-show-errors

    Write-Host "  Role created."
}

Write-Host ""
Write-Host (
    "Done. The function app can now manage JIT IP rules on: {0}" -f
    ($TargetSubscriptionIds -join ', ')
)
Write-Host (
    "The '{0}' role is now assignable to end users on: {1}" -f
    $requesterRoleName, ($TargetSubscriptionIds -join ', ')
)