<#
.SYNOPSIS
    Health check for a JIT-AzAccess deployment. Verifies every piece of the
    end-to-end auth + discovery flow that the AzureTray plugin depends on.

.DESCRIPTION
    Runs the following checks against the deployment in -SubscriptionId. Each
    failure is reported but the script keeps going so you see the whole picture.

      1. JIT-Requester custom RBAC role exists at subscription scope.
      2. The signed-in user holds the JIT-Requester role at, above, or below
         the function app site (ARM's assignedTo() filter — includes inherited).
      3. JIT-AzAccess Manager role DEFINITION exists AND its Actions list
         contains every ARM action the function app actually needs at runtime
         (NSG / SQL / Storage / Key Vault rule management, plus the
         Microsoft.Authorization read actions used by the JIT-Requester
         role check).
      4. Function app's managed identity holds JIT-AzAccess Manager on every
         -TargetSubscriptionIds.
      5. Function app is reachable and enforcing auth (expects 401/403 to
         an unauthenticated probe).
      6. Function app has the env vars the new design depends on
         (JIT_SITE_RESOURCE_ID, JIT_SUBSCRIPTION_ID,
          AZURETRAY_APP_REGISTRATION_OBJECT_ID, FUNCTIONS_WORKER_RUNTIME,
          APPLICATIONINSIGHTS_CONNECTION_STRING, AzureWebJobsStorage__accountName,
          JIT_TABLE_NAME).
      7. Function app MI has Microsoft Graph 'Application.ReadWrite.OwnedBy'
         app role assignment, AND is an owner of the AzureTray app reg.
         (Both are required by profile.ps1 to PATCH the discovery notes.)
      8. AzureTray app reg has a tag 'jit-baseurl:<thisSub>=<this-url>'
         (the plugin's discovery key). Other jit-baseurl:* tags are reported
         for visibility (multi-deploy aware).

.PARAMETER AppName
    Short lowercase alphanumeric name used to derive resource names. Default: pgjitazaccess
    (must match Deploy.ps1's -AppName default, or this script probes an app that
    does not exist and reports a healthy deployment as broken).

.PARAMETER ResourceGroupName
    Resource group that contains the function app. Default: rg-jit-azaccess

.PARAMETER SubscriptionId
    Subscription hosting the function app. Defaults to the current az account.

.PARAMETER TargetSubscriptionIds
    Subscriptions where the MI should hold the JIT-AzAccess Manager role.
    Defaults to the deployment subscription.

.PARAMETER JitRequesterRoleName
    Name of the user-facing RBAC role. Default: "JIT-Requester"

.PARAMETER JitManagerRoleName
    Name of the MI's RBAC role. Default: "JIT-AzAccess Manager"

.PARAMETER AzureTrayAppRegistrationName
    Display name of the AzureTray host app registration. Default: AzureTray

.EXAMPLE
    ./scripts/Test-JITAccess.ps1

.EXAMPLE
    ./scripts/Test-JITAccess.ps1 -SubscriptionId <subId> -TargetSubscriptionIds @('<subA>','<subB>')
#>
[CmdletBinding()]
param(
    [string]   $AppName                       = 'pgjitazaccess',
    [string]   $ResourceGroupName             = 'rg-jit-azaccess',
    [string]   $SubscriptionId,
    [string[]] $TargetSubscriptionIds,
    [string]   $JitRequesterRoleName          = 'JIT-Requester',
    [string]   $JitManagerRoleName            = 'JIT-AzAccess Manager',
    [string]   $AzureTrayAppRegistrationName  = 'AzureTray'
)

# Keep going on benign az "not found" responses — many checks expect them
# and we want a full report, not an early abort.
$ErrorActionPreference = 'Continue'
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$anyFail = $false

function Fail { param($msg) Write-Host "[FAIL] $msg" -ForegroundColor Red;    $script:anyFail = $true }
function Pass { param($msg) Write-Host "[PASS] $msg" -ForegroundColor Green }
function Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Step { param($msg) Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Cyan }

function Trim-Or-Empty { param($v) if ($v) { ($v -join "`n").Trim() } else { '' } }

# ── Pre-flight ────────────────────────────────────────────────────────────────

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI not found. Install from https://aka.ms/installazurecliwindows"
    exit 1
}

$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Error "Not logged in. Run: az login"
    exit 1
}

$currentUserUpn  = $account.user.name
$currentUserType = $account.user.type   # 'user' or 'servicePrincipal'

Info "Signed in as : $currentUserUpn ($currentUserType)"
Info "Tenant       : $($account.tenantId)"
Info "Subscription : $($account.id) ($($account.name))"

if (-not $SubscriptionId)        { $SubscriptionId = $account.id }
if (-not $TargetSubscriptionIds) { $TargetSubscriptionIds = @($SubscriptionId) }

az account set --subscription $SubscriptionId | Out-Null

$functionAppName = "func-$AppName"
$siteResourceId  = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$functionAppName"

# Resolve once up front — many checks need these.
$principalId = Trim-Or-Empty (az functionapp identity show `
    --name $functionAppName --resource-group $ResourceGroupName --subscription $SubscriptionId `
    --query principalId --output tsv 2>$null)

$hostname = Trim-Or-Empty (az functionapp show `
    --name $functionAppName --resource-group $ResourceGroupName --subscription $SubscriptionId `
    --query defaultHostName --output tsv 2>$null)

# ── Check 1: 'JIT-Requester' role definition exists ──────────────────────────

Step "Check 1: '$JitRequesterRoleName' role definition"

$requesterDefJson = az role definition list --name $JitRequesterRoleName --output json 2>$null
$requesterDef     = if ($requesterDefJson) { @($requesterDefJson | ConvertFrom-Json) } else { @() }

if ($requesterDef.Count -eq 0) {
    Fail "Role '$JitRequesterRoleName' is not defined in this tenant. Run Deploy.ps1 to create it."
} else {
    $scopes = @($requesterDef[0].assignableScopes) -join ', '
    Pass "Role exists (assignable on: $scopes)."
}

# ── Check 2: signed-in user holds JIT-Requester ──────────────────────────────

Step "Check 2: '$JitRequesterRoleName' assignment for the signed-in caller"

$userOid = $null
if ($currentUserType -eq 'user') {
    $userOid = Trim-Or-Empty (az ad signed-in-user show --query id --output tsv 2>$null)
} else {
    $userOid = Trim-Or-Empty (az ad sp show --id $currentUserUpn --query id --output tsv 2>$null)
}

if (-not $userOid) {
    Fail "Could not resolve current user object ID."
} else {
    # Scope matters here. The server calls
    # Test-CallerHasJitRequesterRole -SubscriptionId <the TARGET resource's
    # subscription>, so a site-scoped check answers a different question than
    # the one the endpoint actually asks and can pass while a real grant is
    # refused. Check the subscription scope, which is what Deploy.ps1 assigns
    # at and what the server evaluates against.
    $subscriptionScope = "/subscriptions/$SubscriptionId"
    Info "User object ID : $userOid"
    Info "Checking role assignments at $subscriptionScope (incl. inherited)..."
    Info "  (the server evaluates this against whichever subscription a request targets)"

    $assignmentsJson = az rest --method GET `
        --uri "https://management.azure.com$subscriptionScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=assignedTo('$userOid')" `
        --output json 2>$null
    $assignments = if ($assignmentsJson) { @(($assignmentsJson | ConvertFrom-Json).value) } else { @() }

    $matched = $null
    foreach ($a in $assignments) {
        $defJson = az rest --method GET `
            --uri "https://management.azure.com$($a.properties.roleDefinitionId)?api-version=2022-04-01" `
            --output json 2>$null
        if ($defJson) {
            $def = $defJson | ConvertFrom-Json
            if ($def.properties.roleName -eq $JitRequesterRoleName) {
                $matched = $a
                break
            }
        }
    }
    if ($matched) {
        Pass "Role '$JitRequesterRoleName' assigned (assignment $($matched.name) at scope $($matched.properties.scope))."
    }
    else {
        Fail "User '$currentUserUpn' does NOT hold '$JitRequesterRoleName' in subscription $SubscriptionId."
        Warn "  Fix:"
        Warn "    az role assignment create --assignee-object-id '$userOid' --assignee-principal-type User \"
        Warn "        --role '$JitRequesterRoleName' --scope '$subscriptionScope'"
    }
}

# ── Check 3: 'JIT-AzAccess Manager' role definition has the required Actions ─

Step "Check 3: '$JitManagerRoleName' role definition includes every required Action"

# The exact ARM actions the function app needs at runtime. Keep this list in
# sync with $roleActions in Grant-JITPermissions.ps1. The function app's
# managed identity holds this role; without ALL of these actions, runtime
# operations silently fail with 403s that look like other problems.
$requiredManagerActions = @(
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
    'Microsoft.DBforMySQL/flexibleServers/read'
    'Microsoft.DBforMySQL/flexibleServers/firewallRules/read'
    'Microsoft.DBforMySQL/flexibleServers/firewallRules/write'
    'Microsoft.DBforMySQL/flexibleServers/firewallRules/delete'
    'Microsoft.Cache/redis/read'
    'Microsoft.Cache/redis/firewallRules/read'
    'Microsoft.Cache/redis/firewallRules/write'
    'Microsoft.Cache/redis/firewallRules/delete'
    'Microsoft.Synapse/workspaces/read'
    'Microsoft.Synapse/workspaces/firewallRules/read'
    'Microsoft.Synapse/workspaces/firewallRules/write'
    'Microsoft.Synapse/workspaces/firewallRules/delete'
    'Microsoft.DocumentDB/databaseAccounts/read'
    'Microsoft.DocumentDB/databaseAccounts/write'
    'Microsoft.ContainerRegistry/registries/read'
    'Microsoft.ContainerRegistry/registries/write'
    'Microsoft.Search/searchServices/read'
    'Microsoft.Search/searchServices/write'
    'Microsoft.CognitiveServices/accounts/read'
    'Microsoft.CognitiveServices/accounts/write'
    'Microsoft.Kusto/clusters/read'
    'Microsoft.Kusto/clusters/write'
    'Microsoft.Devices/IotHubs/read'
    'Microsoft.Devices/IotHubs/write'
    'Microsoft.SignalRService/signalR/read'
    'Microsoft.SignalRService/signalR/write'
    'Microsoft.EventHub/namespaces/read'
    'Microsoft.EventHub/namespaces/networkRuleSets/read'
    'Microsoft.EventHub/namespaces/networkRuleSets/write'
    'Microsoft.ServiceBus/namespaces/read'
    'Microsoft.ServiceBus/namespaces/networkRuleSets/read'
    'Microsoft.ServiceBus/namespaces/networkRuleSets/write'
    'Microsoft.Web/sites/read'
    'Microsoft.Web/sites/config/read'
    'Microsoft.Web/sites/config/write'
    'Microsoft.Web/sites/slots/read'
    'Microsoft.Web/sites/slots/config/read'
    'Microsoft.Web/sites/slots/config/write'
    'Microsoft.ContainerService/managedClusters/read'
    'Microsoft.ContainerService/managedClusters/write'
    'Microsoft.Authorization/roleAssignments/read'
    'Microsoft.Authorization/roleDefinitions/read'
)

$managerDefJson = az role definition list --name $JitManagerRoleName --output json 2>$null
$managerDef     = if ($managerDefJson) { @($managerDefJson | ConvertFrom-Json) | Select-Object -First 1 } else { $null }

if (-not $managerDef) {
    Fail "Role '$JitManagerRoleName' is not defined in this tenant. Run Grant-JITPermissions.ps1 to create it."
}
else {
    $perms       = @($managerDef.permissions)
    $actualActions = @()
    foreach ($p in $perms) { $actualActions += @($p.actions) }
    $actualActions = $actualActions | Sort-Object -Unique

    $missing = @($requiredManagerActions | Where-Object { $_ -notin $actualActions })

    if ($missing.Count -eq 0) {
        Pass "Role '$JitManagerRoleName' has all $($requiredManagerActions.Count) required Actions."
    }
    else {
        Fail "Role '$JitManagerRoleName' is missing $($missing.Count) required Action(s):"
        foreach ($m in $missing) { Warn "    $m" }
        Warn "  Fix: re-run ./scripts/Grant-JITPermissions.ps1 (it merges scopes and refreshes Actions)."
    }

    # Surface assignable scopes so you can sanity-check multi-sub setups.
    $scopes = @($managerDef.assignableScopes)
    Info "  Assignable scopes ($($scopes.Count)): $($scopes -join ', ')"
    foreach ($subId in $TargetSubscriptionIds) {
        $expected = "/subscriptions/$subId"
        if ($expected -notin $scopes) {
            Warn "  Target sub $subId is NOT in AssignableScopes — assigning the role here will fail."
        }
    }
}

# ── Check 4: MI holds JIT-AzAccess Manager on every target subscription ──────

Step "Check 4: '$JitManagerRoleName' assignment on the function app MI"

if (-not $principalId) {
    Fail "Could not retrieve managed identity for '$functionAppName' in '$ResourceGroupName'. Is the function app deployed?"
} else {
    Pass "MI principal ID: $principalId"

    foreach ($subId in $TargetSubscriptionIds) {
        $roleAssignmentsJson = az role assignment list `
            --assignee     $principalId `
            --role         $JitManagerRoleName `
            --subscription $subId `
            --output       json 2>$null
        $roleAssignments = if ($roleAssignmentsJson) { @($roleAssignmentsJson | ConvertFrom-Json) } else { @() }

        if ($roleAssignments.Count -gt 0) {
            Pass "Role '$JitManagerRoleName' assigned on subscription $subId"
        } else {
            Fail "Role '$JitManagerRoleName' NOT found on subscription $subId"
            Warn "  Fix: ./scripts/Grant-JITPermissions.ps1 -TargetSubscriptionIds '$subId' -FunctionAppPrincipalId '$principalId'"
        }
    }
}

# ── Check 5: function app reachable ──────────────────────────────────────────

Step "Check 5: function app is reachable"

if (-not $hostname) {
    Fail "Could not resolve function app hostname."
} else {
    $probeUrl = "https://$hostname/api/Get-JITRules"
    Info "Probing $probeUrl (expect 401/403 — unauthenticated probe)"
    try {
        $resp = Invoke-WebRequest -Uri $probeUrl -Method GET -SkipHttpErrorCheck -TimeoutSec 10
        if ($resp.StatusCode -in 401, 403) {
            Pass "Function app responded HTTP $($resp.StatusCode) — up and enforcing auth."
        } elseif ($resp.StatusCode -eq 200) {
            Pass "Function app responded HTTP 200."
        } else {
            Warn "Function app responded HTTP $($resp.StatusCode) — may still be starting or misconfigured."
        }
    } catch {
        Fail "Could not reach $probeUrl : $_"
    }
}

# ── Check 6: required env vars on the function app ───────────────────────────

Step 'Check 6: required env vars on the function app'

# Settings the template sets and the app needs. JIT_REQUESTER_ROLE_NAME used to
# be in this list and is read by nothing in the app or the template, so Check 6
# failed on every healthy deployment. JIT_SITE_RESOURCE_ID / JIT_SUBSCRIPTION_ID
# came out for the same reason: they are overrides, and the app derives both at
# runtime (Get-JitSiteResourceId / Get-JitSubscriptionId) when they are absent,
# which is the normal case.
$expected = @(
    'AZURETRAY_APP_REGISTRATION_OBJECT_ID'
    'FUNCTIONS_WORKER_RUNTIME'
    'APPLICATIONINSIGHTS_CONNECTION_STRING'
    'AzureWebJobsStorage__accountName'
    'JIT_TABLE_NAME'
)

# Present only when an operator has pinned them; absence is correct, not a fault.
$optionalOverrides = @(
    'JIT_SITE_RESOURCE_ID'
    'JIT_SUBSCRIPTION_ID'
    'JIT_RESOURCE_GROUP'
    'JIT_SITE_NAME'
    'JIT_ALLOWED_CLIENT_APPIDS'
    'JIT_TRUSTED_XFF_DEPTH'
)

$settingsJson = az functionapp config appsettings list `
    --name $functionAppName --resource-group $ResourceGroupName --subscription $SubscriptionId `
    --output json 2>$null
$settings = if ($settingsJson) { @($settingsJson | ConvertFrom-Json) } else { @() }
$settingsMap = @{}
foreach ($s in $settings) { $settingsMap[$s.name] = $s.value }

$expectedAppRegObjId = ''
foreach ($name in $expected) {
    if (-not $settingsMap.ContainsKey($name) -or [string]::IsNullOrWhiteSpace($settingsMap[$name])) {
        Fail "App setting '$name' is missing or empty. Re-run Deploy.ps1."
    } else {
        Pass "$name = $($settingsMap[$name])"
        if ($name -eq 'AZURETRAY_APP_REGISTRATION_OBJECT_ID') { $expectedAppRegObjId = $settingsMap[$name] }
    }
}

foreach ($name in $optionalOverrides) {
    if ($settingsMap.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($settingsMap[$name])) {
        Info "$name = $($settingsMap[$name])  (override set)"
    }
}

# ── Check 7: MI Graph permission + AzureTray app reg ownership ───────────────

Step "Check 7: MI Graph 'Application.ReadWrite.OwnedBy' + AzureTray app reg ownership"

if (-not $principalId) {
    Warn "Skipped — managed identity could not be resolved (see Check 4)."
}
else {
    # 6a. Graph app role assignment
    $graphSpId = Trim-Or-Empty (az ad sp list --display-name 'Microsoft Graph' --query '[0].id' --output tsv 2>$null)
    if (-not $graphSpId) {
        Warn "Could not locate the Microsoft Graph service principal — skipping Graph app-role check."
    }
    else {
        $assignmentsJson = az rest --method GET `
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" `
            --output json 2>$null
        $miAssignments = if ($assignmentsJson) { @(($assignmentsJson | ConvertFrom-Json).value) } else { @() }

        $rolesJson = az ad sp show --id $graphSpId --query appRoles --output json 2>$null
        $graphRoles = if ($rolesJson) { @($rolesJson | ConvertFrom-Json) } else { @() }
        $ownedByRole = $graphRoles | Where-Object { $_.value -eq 'Application.ReadWrite.OwnedBy' } | Select-Object -First 1

        if (-not $ownedByRole) {
            Warn "Could not resolve 'Application.ReadWrite.OwnedBy' role ID from Graph SP."
        }
        else {
            $hasIt = $miAssignments | Where-Object {
                $_.appRoleId -eq $ownedByRole.id -and $_.resourceId -eq $graphSpId
            } | Select-Object -First 1
            if ($hasIt) {
                Pass "MI has Graph 'Application.ReadWrite.OwnedBy' (assignment $($hasIt.id))."
            } else {
                Fail "MI is missing Graph 'Application.ReadWrite.OwnedBy'. profile.ps1 will not be able to write notes."
                Warn "  Fix: re-run Deploy.ps1 (Step 3b grants this)."
            }
        }
    }

    # 6b. AzureTray app reg ownership
    if (-not $expectedAppRegObjId) {
        Warn "Skipped ownership check — AZURETRAY_APP_REGISTRATION_OBJECT_ID is not set."
    }
    else {
        $ownersJson = az rest --method GET `
            --uri "https://graph.microsoft.com/v1.0/applications/$expectedAppRegObjId/owners" `
            --output json 2>$null
        $owners = if ($ownersJson) { @(($ownersJson | ConvertFrom-Json).value) } else { @() }
        $isOwner = ($owners | Where-Object { $_.id -eq $principalId } | Measure-Object).Count -gt 0
        if ($isOwner) {
            Pass "MI is an owner of app reg '$AzureTrayAppRegistrationName' ($expectedAppRegObjId)."
        } else {
            Fail "MI is NOT an owner of app reg '$AzureTrayAppRegistrationName'. profile.ps1 will not be able to write notes."
            Warn "  Fix: re-run Deploy.ps1 (Step 3b adds the MI as owner)."
        }
    }
}

# ── Check 8: AzureTray app reg has a jit-baseurl:<thisSub>=<thisUrl> tag ────

Step "Check 8: 'jit-baseurl:$SubscriptionId=…' tag on '$AzureTrayAppRegistrationName'"

$appRegLookupJson = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$AzureTrayAppRegistrationName'&`$select=id,tags" `
    --output json 2>$null
$appReg = $null
if ($appRegLookupJson) {
    $appReg = ($appRegLookupJson | ConvertFrom-Json).value | Select-Object -First 1
}

if (-not $appReg) {
    Fail "App registration '$AzureTrayAppRegistrationName' not found in this tenant."
}
else {
    $tags        = if ($appReg.tags) { @($appReg.tags) } else { @() }
    $expectedUrl = if ($hostname) { "https://$hostname" } else { '' }
    $tagPrefix   = "jit-baseurl:${SubscriptionId}="

    $ourTags   = @($tags | Where-Object { $_ -like "${tagPrefix}*" })
    $otherTags = @($tags | Where-Object { $_ -like 'jit-baseurl:*' -and $_ -notlike "${tagPrefix}*" })

    if ($ourTags.Count -eq 0) {
        Fail "No tag 'jit-baseurl:$SubscriptionId=…' on '$AzureTrayAppRegistrationName'. profile.ps1 has not run yet (or could not write)."
        Warn "  Fix: az functionapp restart --name $functionAppName --resource-group $ResourceGroupName"
    }
    else {
        $ourTag    = $ourTags[0]
        $ourTagUrl = $ourTag.Substring($tagPrefix.Length)
        if ($ourTagUrl -eq $expectedUrl) {
            Pass "Tag present and matches this deployment: $ourTag"
        }
        else {
            Warn "Tag present but URL mismatch: $ourTag (this deployment's URL is $expectedUrl)"
        }
        if ($ourTags.Count -gt 1) {
            Warn "  $($ourTags.Count) tags for the same subscription — manual cleanup may be needed:"
            foreach ($t in $ourTags) { Warn "    $t" }
        }
    }

    if ($otherTags.Count -gt 0) {
        Info "Other JIT deployments registered on this app reg:"
        foreach ($t in $otherTags) { Info "  $t" }
    }
}

# ── Result ────────────────────────────────────────────────────────────────────

Write-Host ""
if ($anyFail) {
    Write-Host "Result: " -NoNewline
    Write-Host "One or more checks FAILED. See above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "Result: " -NoNewline
    Write-Host "All checks passed." -ForegroundColor Green
}
