<#
.SYNOPSIS
    Configures Azure PIM (Privileged Identity Management) for Azure resource
    roles on a list of subscriptions so one or more groups can hold the JIT role
    permanently — as permanent ELIGIBLE assignments and (optionally) permanent
    ACTIVE assignments.

.DESCRIPTION
    This is "PIM for Azure resources" (a subscription-scoped Azure RBAC role),
    NOT PIM for Entra ID directory roles.

    You supply one or more ELIGIBLE groups and/or one or more ACTIVE groups.
    At least one of -EligibleAssignment / -ActiveAssignment must be provided.
    If no ACTIVE groups are given, no active assignments are created and the
    active PIM policy is left untouched (the common case: eligible-only).

    For each subscription in -Subscriptions, the script:

      1. Resolves the role definition for -RoleName at subscription scope. If
         the role is not defined in that subscription, the subscription is
         SKIPPED with a warning (it must be created first — see
         Grant-JITPermissions.ps1) rather than failing the whole run.

      2. Relaxes the role's PIM role-management policy so PERMANENT assignments
         are allowed — but only for the assignment kinds actually requested.
         By default the policy usually forces an expiration on eligible/active
         assignments, so a permanent request is rejected. The script sets
         isExpirationRequired = $false only on the relevant expiration rule(s):
             - Expiration_Admin_Eligibility  relaxed only when ELIGIBLE groups
               were supplied ("Allow permanent eligible assignment = true").
             - Expiration_Admin_Assignment   relaxed only when ACTIVE groups
               were supplied.
         via Get-AzRoleManagementPolicyAssignment -> Get-AzRoleManagementPolicy
         -> Update-AzRoleManagementPolicy.

      3. Creates a PERMANENT (NoExpiration) ELIGIBLE assignment of the role to
         EACH group in -EligibleAssignment
         (New-AzRoleEligibilityScheduleRequest -ExpirationType NoExpiration).

      4. Creates a PERMANENT (NoExpiration) ACTIVE assignment of the role to
         EACH group in -ActiveAssignment, if any
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

.PARAMETER EligibleAssignment
    Zero or more identifiers of Entra security groups that receive a permanent
    ELIGIBLE assignment of the role. Each identifier may be a display name, a
    mail address, or a mail nickname (see NOTES on resolution). Resolved to
    object IDs once, up front. Optional, but at least one of
    -EligibleAssignment / -ActiveAssignment must be supplied.

.PARAMETER ActiveAssignment
    Zero or more identifiers of Entra security groups that receive a permanent
    ACTIVE assignment of the role. Each identifier may be a display name, a mail
    address, or a mail nickname. Optional — when omitted, no active assignments
    are created and the active PIM policy is not modified. At least one of
    -EligibleAssignment / -ActiveAssignment must be supplied.

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

    GROUP RESOLUTION: each identifier is resolved to a single Entra group by
    trying, in order, display name, then mail, then mail nickname. Resolution
    fails clearly if an identifier matches zero or multiple groups.

    PREREQUISITES per subscription:
      - The -RoleName role definition already exists there
        (Grant-JITPermissions.ps1 creates 'JIT-Requester').
      - Every supplied group already exists in Entra.

.EXAMPLE
    # Single subscription, one eligible + one active group
    ./scripts/Set-JITPim.ps1 `
        -Subscriptions      '00000000-0000-0000-0000-000000000001' `
        -EligibleAssignment 'JIT Requesters (Eligible)' `
        -ActiveAssignment   'JIT Requesters (Active)'

.EXAMPLE
    # Eligible-only for TWO groups across several subscriptions.
    # No active assignments are created; the active PIM policy is left untouched.
    ./scripts/Set-JITPim.ps1 `
        -Subscriptions      @('00000000-0000-0000-0000-000000000001',
                              '00000000-0000-0000-0000-000000000002',
                              '00000000-0000-0000-0000-000000000003') `
        -EligibleAssignment 'Cloud Operations', 'Group - Software Engineers' `
        -RoleName           'JIT-Requester'

.EXAMPLE
    # Groups identified by mail address instead of display name
    ./scripts/Set-JITPim.ps1 `
        -Subscriptions      '00000000-0000-0000-0000-000000000001' `
        -EligibleAssignment 'CloudOps@pgcfo.com', 'SoftwareEngineers@pgcfo.com'

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
        -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string[]] $Subscriptions,

    [string[]] $EligibleAssignment,

    [string[]] $ActiveAssignment,

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

# Normalise the (optional) group lists to arrays with empties dropped.
$EligibleAssignment = @($EligibleAssignment | Where-Object { $_ -and $_.Trim() })
$ActiveAssignment   = @($ActiveAssignment   | Where-Object { $_ -and $_.Trim() })

if ($EligibleAssignment.Count -eq 0 -and $ActiveAssignment.Count -eq 0) {
    Write-Error "You must supply at least one group via -EligibleAssignment and/or -ActiveAssignment."
    exit 1
}

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

# ── Resolve the groups once, up front ────────────────────────────────────────

# Resolve a single identifier to one Entra group, trying (in order) display
# name, then mail, then mail nickname. Fails if it matches zero or many groups.
function Resolve-Group {
    param([string]$Identifier)

    # Escape single quotes for OData filter literals.
    $literal = $Identifier -replace "'", "''"

    $attempts = @(
        @{ How = 'display name'; Get = { @(Get-AzADGroup -DisplayName $Identifier -ErrorAction SilentlyContinue) } },
        @{ How = 'mail';         Get = { @(Get-AzADGroup -Filter "mail eq '$literal'" -ErrorAction SilentlyContinue) } },
        @{ How = 'mail nickname'; Get = { @(Get-AzADGroup -Filter "mailNickname eq '$literal'" -ErrorAction SilentlyContinue) } }
    )

    foreach ($a in $attempts) {
        $groups = & $a.Get
        if ($groups.Count -eq 1) { return $groups[0] }
        if ($groups.Count -gt 1) {
            throw "Multiple ($($groups.Count)) Entra groups match '$Identifier' by $($a.How). Use a unique identifier."
        }
    }

    throw "No Entra group found matching '$Identifier' by display name, mail, or mail nickname."
}

Step 'Resolving assignment groups'

$eligibleGroups = @()   # [pscustomobject] Identifier, Oid
$activeGroups   = @()

try {
    foreach ($id in $EligibleAssignment) {
        $g = Resolve-Group -Identifier $id
        Info "Eligible group : '$id' -> $($g.Id)"
        $eligibleGroups += [pscustomobject]@{ Identifier = $id; Oid = $g.Id }
    }

    foreach ($id in $ActiveAssignment) {
        $g = Resolve-Group -Identifier $id
        Info "Active group   : '$id' -> $($g.Id)"
        $activeGroups += [pscustomobject]@{ Identifier = $id; Oid = $g.Id }
    }
}
catch {
    Write-Error "Group resolution failed: $($_.Exception.Message)"
    exit 1
}

# ── Helpers ──────────────────────────────────────────────────────────────────

# Last path segment (role definition GUID) of an ARM role-definition id, so
# comparisons are robust to leading slashes / casing / full-vs-relative paths.
function Get-RoleDefGuid {
    param([string]$Id)
    if (-not $Id) { return $null }
    return ($Id -split '/')[-1]
}

# Summarise a list of per-group outcome strings for the summary table, e.g.
# @('created','existing','created') -> "2 created, 1 existing". Empty -> 'n/a'.
function Format-Outcomes {
    param([string[]]$Outcomes)
    if (-not $Outcomes -or $Outcomes.Count -eq 0) { return 'n/a' }
    return (($Outcomes | Group-Object | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')
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

# Relax the given expiration rule(s) on the role's PIM policy so permanent
# assignments are permitted. Only the rule IDs in -RuleIds are touched. Returns
# $true if an update was performed (or would be under -WhatIf), $false if the
# policy already allowed permanent assignments for those rules. If -RuleIds is
# empty there is nothing to do.
function Set-PermanentAllowed {
    param(
        [string]   $Scope,
        [string]   $RoleDefGuid,
        [string[]] $RuleIds
    )

    if (-not $RuleIds -or $RuleIds.Count -eq 0) {
        return $false
    }

    $assignments = @(Get-AzRoleManagementPolicyAssignment -Scope $Scope)
    $match = $assignments | Where-Object {
        (Get-RoleDefGuid $_.RoleDefinitionId) -eq $RoleDefGuid
    } | Select-Object -First 1

    if (-not $match) {
        throw "No role-management policy assignment found for role $RoleDefGuid at $Scope."
    }

    $policyName = ($match.PolicyId -split '/')[-1]
    $policy     = Get-AzRoleManagementPolicy -Scope $Scope -Name $policyName

    $rulesToUpdate = @()

    foreach ($rule in @($policy.EffectiveRule)) {
        if ($rule.Id -in $RuleIds) {
            # Only relax if expiration is currently required.
            if ($rule.IsExpirationRequired -eq $true) {
                $rule.IsExpirationRequired = $false
                $rulesToUpdate += $rule
            }
        }
    }

    if ($rulesToUpdate.Count -eq 0) {
        Info "Policy already allows permanent assignments for the requested kind(s) — no change."
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
            $result.Eligible = if ($eligibleGroups.Count -gt 0) { 'skipped (no role)' } else { 'n/a' }
            $result.Active   = if ($activeGroups.Count   -gt 0) { 'skipped (no role)' } else { 'n/a' }
            $results += [pscustomobject]$result
            continue
        }

        $roleDefGuid   = $roleDef.Id
        $fullRoleDefId = "$scope/providers/Microsoft.Authorization/roleDefinitions/$roleDefGuid"
        $result.RoleResolved = $true
        Info "Role '$RoleName' -> $roleDefGuid"

        # c. Relax the PIM policy so permanent assignments are allowed — only
        #    for the assignment kinds we were actually asked to create.
        $ruleIdsToRelax = @()
        if ($eligibleGroups.Count -gt 0) { $ruleIdsToRelax += $EligibilityExpirationRuleId }
        if ($activeGroups.Count   -gt 0) { $ruleIdsToRelax += $AssignmentExpirationRuleId }

        $updated = Set-PermanentAllowed -Scope $scope -RoleDefGuid $roleDefGuid -RuleIds $ruleIdsToRelax
        $result.PolicyUpdated = if ($updated) { 'updated' } else { 'already-allowed' }

        # d. Permanent ELIGIBLE assignments (idempotent), one per group
        if ($eligibleGroups.Count -eq 0) {
            $result.Eligible = 'n/a'
        }
        else {
            $eligibleOutcomes = @()
            foreach ($g in $eligibleGroups) {
                $existingEligible = @(Get-AzRoleEligibilitySchedule -Scope $scope -ErrorAction SilentlyContinue) |
                    Where-Object {
                        $_.PrincipalId -eq $g.Oid -and
                        (Get-RoleDefGuid $_.RoleDefinitionId) -eq $roleDefGuid
                    } | Select-Object -First 1

                if ($existingEligible) {
                    Info "Eligible assignment already configured for '$($g.Identifier)' — no change."
                    $eligibleOutcomes += 'existing'
                }
                elseif ($PSCmdlet.ShouldProcess("$scope",
                            "Create PERMANENT eligible assignment of '$RoleName' to '$($g.Identifier)'")) {
                    try {
                        Invoke-PimCreate {
                            New-AzRoleEligibilityScheduleRequest `
                                -Name                      (New-Guid).Guid `
                                -Scope                     $scope `
                                -PrincipalId               $g.Oid `
                                -RoleDefinitionId          $fullRoleDefId `
                                -RequestType               AdminAssign `
                                -ScheduleInfoStartDateTime (Get-Date) `
                                -ExpirationType            NoExpiration | Out-Null
                        }
                        Ok "Created permanent eligible assignment for '$($g.Identifier)'."
                        $eligibleOutcomes += 'created'
                    }
                    catch {
                        if ($_.Exception.Message -match 'RoleAssignmentExists' -or
                            $_.Exception.Message -match 'already exists') {
                            Info "Eligible assignment already exists (race) for '$($g.Identifier)' — treating as configured."
                            $eligibleOutcomes += 'existing'
                        }
                        else { throw }
                    }
                }
                else {
                    $eligibleOutcomes += 'skipped (WhatIf)'
                }
            }
            $result.Eligible = Format-Outcomes $eligibleOutcomes
        }

        # e. Permanent ACTIVE assignments (idempotent), one per group — only if
        #    any active groups were supplied.
        if ($activeGroups.Count -eq 0) {
            $result.Active = 'n/a'
        }
        else {
            $activeOutcomes = @()
            foreach ($g in $activeGroups) {
                $existingActive = @(Get-AzRoleAssignmentSchedule -Scope $scope -ErrorAction SilentlyContinue) |
                    Where-Object {
                        $_.PrincipalId -eq $g.Oid -and
                        (Get-RoleDefGuid $_.RoleDefinitionId) -eq $roleDefGuid
                    } | Select-Object -First 1

                if ($existingActive) {
                    Info "Active assignment already configured for '$($g.Identifier)' — no change."
                    $activeOutcomes += 'existing'
                }
                elseif ($PSCmdlet.ShouldProcess("$scope",
                            "Create PERMANENT active assignment of '$RoleName' to '$($g.Identifier)'")) {
                    try {
                        Invoke-PimCreate {
                            New-AzRoleAssignmentScheduleRequest `
                                -Name                      (New-Guid).Guid `
                                -Scope                     $scope `
                                -PrincipalId               $g.Oid `
                                -RoleDefinitionId          $fullRoleDefId `
                                -RequestType               AdminAssign `
                                -ScheduleInfoStartDateTime (Get-Date) `
                                -ExpirationType            NoExpiration | Out-Null
                        }
                        Ok "Created permanent active assignment for '$($g.Identifier)'."
                        $activeOutcomes += 'created'
                    }
                    catch {
                        if ($_.Exception.Message -match 'RoleAssignmentExists' -or
                            $_.Exception.Message -match 'already exists') {
                            Info "Active assignment already exists (race) for '$($g.Identifier)' — treating as configured."
                            $activeOutcomes += 'existing'
                        }
                        else { throw }
                    }
                }
                else {
                    $activeOutcomes += 'skipped (WhatIf)'
                }
            }
            $result.Active = Format-Outcomes $activeOutcomes
        }
    }
    catch {
        $hadHardFailure = $true
        Err "Subscription $subId failed: $($_.Exception.Message)"
        if ($result.Eligible -eq 'n/a' -and $eligibleGroups.Count -gt 0) { $result.Eligible = 'failed' }
        if ($result.Active   -eq 'n/a' -and $activeGroups.Count   -gt 0) { $result.Active   = 'failed' }
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
