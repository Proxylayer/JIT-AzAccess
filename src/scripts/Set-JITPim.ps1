<#
.SYNOPSIS
    Configures Azure PIM (Privileged Identity Management) for Azure resource
    roles on a list of subscriptions so a group can hold the JIT role
    permanently — both as a permanent ELIGIBLE assignment and a permanent
    ACTIVE assignment.

.DESCRIPTION
    This is "PIM for Azure resources" (a subscription-scoped Azure RBAC role),
    NOT PIM for Entra ID directory roles.

    For each subscription in -Subscriptions, the script:

      1. Resolves the role definition for -RoleName at subscription scope. If
         the role is not defined in that subscription, the subscription is
         SKIPPED with a warning (it must be created first — see
         Grant-JITPermissions.ps1) rather than failing the whole run.

      2. Relaxes the role's PIM role-management policy so PERMANENT assignments
         are allowed. By default the policy usually forces an expiration on
         eligible/active assignments, so a permanent request is rejected. The
         script sets isExpirationRequired = $false on the two expiration rules:
             - Expiration_Admin_Eligibility  (eligible assignment expiration)
             - Expiration_Admin_Assignment   (active   assignment expiration)
         via Get-AzRoleManagementPolicyAssignment -> Get-AzRoleManagementPolicy
         -> Update-AzRoleManagementPolicy.

      3. Creates a PERMANENT (NoExpiration) ELIGIBLE assignment of the role to
         the Entra group named by -EligibleAssignment
         (New-AzRoleEligibilityScheduleRequest -ExpirationType NoExpiration).

      4. Creates a PERMANENT (NoExpiration) ACTIVE assignment of the role to
         the Entra group named by -ActiveAssignment
         (New-AzRoleAssignmentScheduleRequest -ExpirationType NoExpiration).

    Steps 3 and 4 are idempotent: an existing permanent schedule for the same
    principal + role + scope is detected up front (Get-AzRoleEligibilitySchedule
    / Get-AzRoleAssignmentSchedule) and left in place, and a racing
    "RoleAssignmentExists" conflict is treated as "already configured".

    A per-subscription summary is printed at the end. The script exits non-zero
    if any subscription had a HARD failure; subscriptions skipped because the
    role is undefined are warnings, not failures.

    NOTE on modules: the other scripts in this folder drive the Azure CLI (az).
    PIM for Azure resources has no clean az-CLI surface, so this script uses the
    Az PowerShell modules (Az.Accounts, Az.Resources) instead — that is where
    the PIM schedule-request and role-management-policy cmdlets live.

.PARAMETER Subscriptions
    One or more subscription IDs (GUIDs) to configure. Accepts one or many.

.PARAMETER ActiveAssignment
    Display name of the Entra security group that receives the permanent ACTIVE
    assignment of the role. Resolved to an object ID once, up front.

.PARAMETER EligibleAssignment
    Display name of the Entra security group that receives the permanent
    ELIGIBLE assignment of the role. Resolved to an object ID once, up front.

.PARAMETER RoleName
    The Azure RBAC role to configure PIM for. Default: 'JIT-Requester'
    (the requester role this project creates per subscription; note the code
    and scripts use the hyphenated 'JIT-Requester').

.PARAMETER TenantId
    Optional tenant ID used for Connect-AzAccount if there is no existing
    Azure PowerShell context.

.NOTES
    LICENSING: PIM for Azure resources requires Microsoft Entra ID P2 (or
    Microsoft Entra ID Governance). Without a P2 license the schedule-request
    and role-management-policy APIs are unavailable and the calls will fail.

    PERMISSIONS: the caller must be Owner or User Access Administrator on each
    target subscription (to manage role assignments and the role-management
    policy), and must be able to read Entra groups (Get-AzADGroup).

    PREREQUISITES per subscription:
      - The -RoleName role definition already exists there
        (Grant-JITPermissions.ps1 creates 'JIT-Requester').
      - Both groups (-ActiveAssignment, -EligibleAssignment) already exist.

.EXAMPLE
    # Single subscription
    ./scripts/Set-JITPim.ps1 `
        -Subscriptions      '00000000-0000-0000-0000-000000000001' `
        -EligibleAssignment 'JIT Requesters (Eligible)' `
        -ActiveAssignment   'JIT Requesters (Active)'

.EXAMPLE
    # Multiple subscriptions, explicit tenant, custom role name
    ./scripts/Set-JITPim.ps1 `
        -Subscriptions @('00000000-0000-0000-0000-000000000001',
                         '00000000-0000-0000-0000-000000000002') `
        -EligibleAssignment 'JIT Requesters (Eligible)' `
        -ActiveAssignment   'JIT Requesters (Active)' `
        -RoleName           'JIT-Requester' `
        -TenantId           '11111111-1111-1111-1111-111111111111'

.EXAMPLE
    # Preview only — resolves everything and reports, makes no changes
    ./scripts/Set-JITPim.ps1 `
        -Subscriptions      '00000000-0000-0000-0000-000000000001' `
        -EligibleAssignment 'JIT Requesters (Eligible)' `
        -ActiveAssignment   'JIT Requesters (Active)' `
        -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string[]] $Subscriptions,

    [Parameter(Mandatory)]
    [string]   $ActiveAssignment,

    [Parameter(Mandatory)]
    [string]   $EligibleAssignment,

    [string]   $RoleName = 'JIT-Requester',

    [string]   $TenantId
)

# PIM configuration touches many returned model objects; keep going per
# subscription and surface real errors rather than aborting the whole run.
$ErrorActionPreference = 'Stop'

# The two expiration rules that gate permanent assignments.
$EligibilityExpirationRuleId = 'Expiration_Admin_Eligibility'
$AssignmentExpirationRuleId  = 'Expiration_Admin_Assignment'

function Step { param($msg) Write-Host "" ; Write-Host "=== $msg ===" -ForegroundColor Cyan }
function Info { param($msg) Write-Host "  $msg" }
function Ok   { param($msg) Write-Host "  $msg" -ForegroundColor Green }
function Warn { param($msg) Write-Host "  $msg" -ForegroundColor Yellow }
function Err  { param($msg) Write-Host "  $msg" -ForegroundColor Red }

# ── Pre-flight: modules ──────────────────────────────────────────────────────

foreach ($mod in @('Az.Accounts', 'Az.Resources')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "Required module '$mod' is not installed. Install with: Install-Module $mod -Scope CurrentUser"
        exit 1
    }
}

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop

# ── Pre-flight: connected context ────────────────────────────────────────────

Step 'Ensuring an Azure PowerShell context'

$context = $null
try { $context = Get-AzContext } catch { $context = $null }

if (-not $context) {
    Info "No existing context. Connecting..."
    if ($TenantId) {
        Connect-AzAccount -Tenant $TenantId | Out-Null
    }
    else {
        Connect-AzAccount | Out-Null
    }
    $context = Get-AzContext
}

if (-not $context) {
    Write-Error "Could not establish an Azure PowerShell context. Run Connect-AzAccount and retry."
    exit 1
}

Info "Signed in as : $($context.Account.Id)"
Info "Tenant       : $($context.Tenant.Id)"

# ── Resolve the two groups once, up front ────────────────────────────────────

function Resolve-Group {
    param([string]$DisplayName)

    $groups = @(Get-AzADGroup -DisplayName $DisplayName)
    if ($groups.Count -eq 0) {
        throw "No Entra group found with display name '$DisplayName'."
    }
    if ($groups.Count -gt 1) {
        throw "Multiple ($($groups.Count)) Entra groups match display name '$DisplayName'. Use a unique name."
    }
    return $groups[0]
}

Step 'Resolving assignment groups'

try {
    $eligibleGroup = Resolve-Group -DisplayName $EligibleAssignment
    Info "Eligible group : '$EligibleAssignment' -> $($eligibleGroup.Id)"

    $activeGroup = Resolve-Group -DisplayName $ActiveAssignment
    Info "Active group   : '$ActiveAssignment' -> $($activeGroup.Id)"
}
catch {
    Write-Error "Group resolution failed: $($_.Exception.Message)"
    exit 1
}

$eligibleOid = $eligibleGroup.Id
$activeOid   = $activeGroup.Id

# ── Helpers ──────────────────────────────────────────────────────────────────

# Last path segment (role definition GUID) of an ARM role-definition id, so
# comparisons are robust to leading slashes / casing / full-vs-relative paths.
function Get-RoleDefGuid {
    param([string]$Id)
    if (-not $Id) { return $null }
    return ($Id -split '/')[-1]
}

# Create a PIM schedule request, retrying briefly if the policy relaxation has
# not propagated yet (the service can still report an expiration requirement
# for a few seconds after Update-AzRoleManagementPolicy returns).
function Invoke-PimCreate {
    param([scriptblock]$Create)

    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            return & $Create
        }
        catch {
            $msg = $_.Exception.Message
            $notPropagated = $msg -match 'ExpirationRule' -or
                             $msg -match 'expiration is required' -or
                             $msg -match 'RoleManagementPolicy'
            if ($attempt -lt $maxAttempts -and $notPropagated) {
                Warn "Policy may not have propagated yet (attempt $attempt/$maxAttempts): $msg"
                Start-Sleep -Seconds 15
                continue
            }
            throw
        }
    }
}

# Relax the expiration rules on the role's PIM policy so permanent assignments
# are permitted. Returns $true if an update was performed (or would be under
# -WhatIf), $false if the policy already allowed permanent assignments.
function Set-PermanentAllowed {
    param(
        [string]$Scope,
        [string]$RoleDefGuid
    )

    $assignments = @(Get-AzRoleManagementPolicyAssignment -Scope $Scope)
    $match = $assignments | Where-Object {
        (Get-RoleDefGuid $_.RoleDefinitionId) -eq $RoleDefGuid
    } | Select-Object -First 1

    if (-not $match) {
        throw "No role-management policy assignment found for role $RoleDefGuid at $Scope."
    }

    $policyName = ($match.PolicyId -split '/')[-1]
    $policy     = Get-AzRoleManagementPolicy -Scope $Scope -Name $policyName

    $targetRuleIds = @($EligibilityExpirationRuleId, $AssignmentExpirationRuleId)
    $rulesToUpdate = @()

    foreach ($rule in @($policy.EffectiveRule)) {
        if ($rule.Id -in $targetRuleIds) {
            # Only relax if expiration is currently required.
            if ($rule.IsExpirationRequired -eq $true) {
                $rule.IsExpirationRequired = $false
                $rulesToUpdate += $rule
            }
        }
    }

    if ($rulesToUpdate.Count -eq 0) {
        Info "Policy already allows permanent assignments — no change."
        return $false
    }

    if ($PSCmdlet.ShouldProcess("policy $policyName at $Scope",
            "Relax expiration rules ($($rulesToUpdate.Count)) to allow permanent assignments")) {
        Update-AzRoleManagementPolicy -Scope $Scope -Name $policyName -Rule $rulesToUpdate | Out-Null
        Ok "Relaxed $($rulesToUpdate.Count) expiration rule(s) to allow permanent assignments."
        return $true
    }

    return $true
}

# ── Per-subscription processing ──────────────────────────────────────────────

$results        = @()
$hadHardFailure = $false

foreach ($subId in $Subscriptions) {

    Step "Subscription: $subId"

    $result = [ordered]@{
        Subscription  = $subId
        RoleResolved  = $false
        PolicyUpdated = 'n/a'
        Eligible      = 'n/a'
        Active        = 'n/a'
    }

    try {
        # a. Context + scope
        Set-AzContext -Subscription $subId -ErrorAction Stop | Out-Null
        $scope = "/subscriptions/$subId"

        # b. Resolve role definition at this scope
        $roleDef = Get-AzRoleDefinition -Name $RoleName -Scope $scope -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if (-not $roleDef) {
            Warn "Role '$RoleName' is not defined in subscription $subId — skipping."
            Warn "  Create it first (e.g. via Grant-JITPermissions.ps1), then re-run."
            $result.Eligible = 'skipped (no role)'
            $result.Active   = 'skipped (no role)'
            $results += [pscustomobject]$result
            continue
        }

        $roleDefGuid  = $roleDef.Id
        $fullRoleDefId = "$scope/providers/Microsoft.Authorization/roleDefinitions/$roleDefGuid"
        $result.RoleResolved = $true
        Info "Role '$RoleName' -> $roleDefGuid"

        # c. Relax the PIM policy so permanent assignments are allowed
        $updated = Set-PermanentAllowed -Scope $scope -RoleDefGuid $roleDefGuid
        $result.PolicyUpdated = if ($updated) { 'updated' } else { 'already-allowed' }

        # d. Permanent ELIGIBLE assignment (idempotent)
        $existingEligible = @(Get-AzRoleEligibilitySchedule -Scope $scope -ErrorAction SilentlyContinue) |
            Where-Object {
                $_.PrincipalId -eq $eligibleOid -and
                (Get-RoleDefGuid $_.RoleDefinitionId) -eq $roleDefGuid
            } | Select-Object -First 1

        if ($existingEligible) {
            Info "Eligible assignment already configured for '$EligibleAssignment' — no change."
            $result.Eligible = 'existing'
        }
        elseif ($PSCmdlet.ShouldProcess("$scope",
                    "Create PERMANENT eligible assignment of '$RoleName' to '$EligibleAssignment'")) {
            try {
                Invoke-PimCreate {
                    New-AzRoleEligibilityScheduleRequest `
                        -Name                      (New-Guid).Guid `
                        -Scope                     $scope `
                        -PrincipalId               $eligibleOid `
                        -RoleDefinitionId          $fullRoleDefId `
                        -RequestType               AdminAssign `
                        -ScheduleInfoStartDateTime (Get-Date) `
                        -ExpirationType            NoExpiration | Out-Null
                }
                Ok "Created permanent eligible assignment for '$EligibleAssignment'."
                $result.Eligible = 'created'
            }
            catch {
                if ($_.Exception.Message -match 'RoleAssignmentExists' -or
                    $_.Exception.Message -match 'already exists') {
                    Info "Eligible assignment already exists (race) — treating as configured."
                    $result.Eligible = 'existing'
                }
                else { throw }
            }
        }
        else {
            $result.Eligible = 'skipped (WhatIf)'
        }

        # e. Permanent ACTIVE assignment (idempotent)
        $existingActive = @(Get-AzRoleAssignmentSchedule -Scope $scope -ErrorAction SilentlyContinue) |
            Where-Object {
                $_.PrincipalId -eq $activeOid -and
                (Get-RoleDefGuid $_.RoleDefinitionId) -eq $roleDefGuid
            } | Select-Object -First 1

        if ($existingActive) {
            Info "Active assignment already configured for '$ActiveAssignment' — no change."
            $result.Active = 'existing'
        }
        elseif ($PSCmdlet.ShouldProcess("$scope",
                    "Create PERMANENT active assignment of '$RoleName' to '$ActiveAssignment'")) {
            try {
                Invoke-PimCreate {
                    New-AzRoleAssignmentScheduleRequest `
                        -Name                      (New-Guid).Guid `
                        -Scope                     $scope `
                        -PrincipalId               $activeOid `
                        -RoleDefinitionId          $fullRoleDefId `
                        -RequestType               AdminAssign `
                        -ScheduleInfoStartDateTime (Get-Date) `
                        -ExpirationType            NoExpiration | Out-Null
                }
                Ok "Created permanent active assignment for '$ActiveAssignment'."
                $result.Active = 'created'
            }
            catch {
                if ($_.Exception.Message -match 'RoleAssignmentExists' -or
                    $_.Exception.Message -match 'already exists') {
                    Info "Active assignment already exists (race) — treating as configured."
                    $result.Active = 'existing'
                }
                else { throw }
            }
        }
        else {
            $result.Active = 'skipped (WhatIf)'
        }
    }
    catch {
        $hadHardFailure = $true
        Err "Subscription $subId failed: $($_.Exception.Message)"
        if ($result.Eligible -eq 'n/a') { $result.Eligible = 'failed' }
        if ($result.Active   -eq 'n/a') { $result.Active   = 'failed' }
    }

    $results += [pscustomobject]$result
}

# ── Summary ──────────────────────────────────────────────────────────────────

Step 'Summary'

$results | Format-Table -AutoSize Subscription, RoleResolved, PolicyUpdated, Eligible, Active |
    Out-String | Write-Host

if ($hadHardFailure) {
    Write-Host ""
    Write-Host "Result: one or more subscriptions had a HARD failure. See above." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Result: completed. (Subscriptions skipped for a missing role are warnings, not failures.)" -ForegroundColor Green
