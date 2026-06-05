<#
.SYNOPSIS
    Creates a custom "JIT-AzAccess Manager" RBAC role and assigns it to the
    JIT function app's managed identity on one or more target subscriptions.

    The custom role grants only the specific control-plane actions needed to
    manage IP allowlists on NSGs, SQL servers, storage accounts, and key vaults.
    It grants no data-plane access and cannot create or delete resources.

.PARAMETER TargetSubscriptionIds
    One or more subscription IDs where the function app should manage resources.

.PARAMETER FunctionAppPrincipalId
    Object ID of the function app's system-assigned managed identity.
    Retrieve after ARM deployment:
      az functionapp identity show --name <funcName> --resource-group <rgName> --query principalId -o tsv

.PARAMETER FunctionAppName
    Name of the function app (used to look up principalId if -FunctionAppPrincipalId is not supplied).

.PARAMETER ResourceGroupName
    Resource group containing the function app (used with -FunctionAppName lookup).

.PARAMETER FunctionAppSubscriptionId
    Subscription hosting the function app (used with -FunctionAppName lookup).

.EXAMPLE
    # Using the managed identity principal ID directly (preferred after deployment):
    ./Grant-JITPermissions.ps1 `
        -TargetSubscriptionIds @("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx") `
        -FunctionAppPrincipalId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"

.EXAMPLE
    # Looking up by function app name:
    ./Grant-JITPermissions.ps1 `
        -TargetSubscriptionIds @("sub-id-1", "sub-id-2") `
        -FunctionAppName "func-jitazaccess" `
        -ResourceGroupName "rg-jit-azaccess" `
        -FunctionAppSubscriptionId "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
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

if (-not $FunctionAppPrincipalId -and (-not $FunctionAppName -or -not $ResourceGroupName -or -not $FunctionAppSubscriptionId)) {
    Write-Error "Provide either -FunctionAppPrincipalId, or all three of -FunctionAppName, -ResourceGroupName, and -FunctionAppSubscriptionId."
    exit 1
}

$roleName        = 'JIT-AzAccess Manager'
$roleDescription = 'Manages temporary IP allowlist entries on NSGs, SQL servers, storage accounts, and key vaults for JIT-AzAccess.'

# Minimal action set — no create/delete of resources, only firewall/network rule mutations
$roleActions = @(
    # NSG — read + write security rules only (not the NSG itself)
    'Microsoft.Network/networkSecurityGroups/read'
    'Microsoft.Network/networkSecurityGroups/write'
    'Microsoft.Network/networkSecurityGroups/securityRules/read'
    'Microsoft.Network/networkSecurityGroups/securityRules/write'
    'Microsoft.Network/networkSecurityGroups/securityRules/delete'
    # SQL — firewall rules only (no database or schema access)
    'Microsoft.Sql/servers/read'
    'Microsoft.Sql/servers/firewallRules/read'
    'Microsoft.Sql/servers/firewallRules/write'
    'Microsoft.Sql/servers/firewallRules/delete'
    # Storage — account write required to update networkAcls (no data-plane access)
    'Microsoft.Storage/storageAccounts/read'
    'Microsoft.Storage/storageAccounts/write'
    # Key Vault — vault write required to update networkAcls (no secrets/keys access)
    'Microsoft.KeyVault/vaults/read'
    'Microsoft.KeyVault/vaults/write'
)

# ── Retrieve the managed identity principal ID ────────────────────────────────

if (-not $FunctionAppPrincipalId) {
    Write-Host "Retrieving principal ID for '$FunctionAppName'..."
    $FunctionAppPrincipalId = az functionapp identity show `
        --name              $FunctionAppName `
        --resource-group    $ResourceGroupName `
        --subscription      $FunctionAppSubscriptionId `
        --query             principalId `
        --output            tsv

    if (-not $FunctionAppPrincipalId -or $FunctionAppPrincipalId -eq 'null') {
        Write-Error "Could not retrieve principal ID. Ensure the function app exists and has a system-assigned identity enabled."
        exit 1
    }
}

Write-Host "Principal ID: $FunctionAppPrincipalId"

# ── Create or update the custom role on each target subscription ──────────────

foreach ($subId in $TargetSubscriptionIds) {
    $scope = "/subscriptions/$subId"
    Write-Host ""
    Write-Host "Processing subscription: $subId"

    $existingRole = az role definition list `
        --name  $roleName `
        --scope $scope `
        --query "[0].id" `
        --output tsv 2>$null

    if ($existingRole) {
        Write-Host "  Role '$roleName' already exists — updating actions..."
        $roleJson = az role definition show --name $roleName --scope $scope | ConvertFrom-Json
        $roleJson.permissions[0].actions = $roleActions
        $roleJson | ConvertTo-Json -Depth 10 | Set-Content -Path "$env:TEMP\jitrole.json" -Encoding UTF8
        az role definition update --role-definition "@$env:TEMP\jitrole.json" --output none
        Write-Host "  Updated."
    }
    else {
        Write-Host "  Creating role '$roleName'..."
        $roleDefinition = @{
            Name             = $roleName
            Description      = $roleDescription
            Actions          = $roleActions
            NotActions       = @()
            AssignableScopes = @($scope)
        }
        $roleDefinition | ConvertTo-Json -Depth 5 | Set-Content -Path "$env:TEMP\jitrole.json" -Encoding UTF8
        az role definition create --role-definition "@$env:TEMP\jitrole.json" --output none
        Write-Host "  Created."
    }

    # ── Assign the role to the managed identity ───────────────────────────────

    $alreadyAssigned = az role assignment list `
        --assignee  $FunctionAppPrincipalId `
        --role      $roleName `
        --scope     $scope `
        --query     "[0].id" `
        --output    tsv 2>$null

    if ($alreadyAssigned) {
        Write-Host "  Role already assigned to managed identity on $scope — no change."
    }
    else {
        Write-Host "  Assigning '$roleName' to managed identity on $scope..."
        az role assignment create `
            --assignee-object-id    $FunctionAppPrincipalId `
            --assignee-principal-type ServicePrincipal `
            --role                  $roleName `
            --scope                 $scope `
            --output                none
        Write-Host "  Assigned."
    }
}

Write-Host ""
Write-Host "Done. The function app can now manage JIT IP rules on: $($TargetSubscriptionIds -join ', ')"
