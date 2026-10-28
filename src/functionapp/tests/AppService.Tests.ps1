# Tests for the App Service (Microsoft.Web/sites) JIT handler in
# JITTargets\Targets\AppService.ps1 — Add-JITAppServiceRule / Remove-JITAppServiceRule
# and their module-internal helpers.
#
# Covers BOTH halves of the handler:
#   • The site's own config/web behavior — the never-lock-down-an-open-site guard,
#     by-caller-IP "already present" detection, the SCM/Kudu list and its
#     scmIpSecurityRestrictionsUseMain inheritance, and removal idempotency.
#   • Deployment-slot coverage (FEAT-0004) — one grant/revoke fans out to every
#     slot, the guard is re-evaluated per slot, the priority is chosen per
#     resource, the same RuleId is used everywhere, paging over the slots
#     collection, and the best-effort partial-failure reporting in Details.
#
# The handler talks to ARM only through Invoke-ArmRestRaw (directly for the slots
# collection, and via the shared Invoke-JITArmReadModifyWrite helper for every
# config/web read-modify-write), so a single `Mock -ModuleName JITTargets
# Invoke-ArmRestRaw` fakes the whole ARM surface. HttpHelpers is imported
# (globally) so that command exists and is therefore mockable inside the
# JITTargets scope; JITHelpers is imported for Get-AvailableNsgPriority, which
# the handler uses to pick a free priority. No network / Az.* is touched.
#
# Fake ARM state is served out of $global:* hashtables keyed by ARM path, because
# the mock scriptblocks run in the module's session state and cannot see the test
# file's locals. Everything is reset in BeforeEach.
#
# Pester 5+ (setup in BeforeAll, `Should -Verb` syntax, native `Should -Throw`).
#
# Run:  ./test.ps1 -Target AppService

BeforeAll {

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

# ── Fixture constants ─────────────────────────────────────────────────────────
$script:Sub      = '11111111-1111-1111-1111-111111111111'
$script:Rg       = 'rg-jit'
$script:Site     = 'contoso-web'
$script:CallerIp = '203.0.113.5'
$script:RuleId   = 'jit-abc123'

$script:SitePath = "/subscriptions/$script:Sub/resourceGroups/$script:Rg/providers/Microsoft.Web/sites/$script:Site/config/web"
$script:SlotsUrl = "/subscriptions/$script:Sub/resourceGroups/$script:Rg/providers/Microsoft.Web/sites/$script:Site/slots"

function script:Get-SlotConfigPath {
    param([string]$Slot)
    return "/subscriptions/$script:Sub/resourceGroups/$script:Rg/providers/Microsoft.Web/sites/$script:Site/slots/$Slot/config/web"
}

# ── Fixture builders ──────────────────────────────────────────────────────────
function script:New-IpRule {
    param([string]$Ip, [int]$Priority = 100, [string]$Name = 'existing', [string]$Action = 'Allow')
    return @{ ipAddress = $Ip; action = $Action; priority = $Priority; name = $Name }
}

function script:New-VnetRule {
    param([string]$SubnetId = '/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/virtualNetworks/v/subnets/s',
          [int]$Priority = 200, [string]$Name = 'vnet-rule')
    return @{ vnetSubnetResourceId = $SubnetId; action = 'Allow'; priority = $Priority; name = $Name }
}

function script:New-ConfigJson {
    # Serializes a config/web resource the way ARM returns it.
    param(
        $Main        = @(),
        $Scm         = @(),
        [string]$MainDefault = 'Allow',
        [string]$ScmDefault  = 'Allow',
        [bool]$ScmUseMain    = $false
    )
    return (@{
        id         = 'irrelevant'
        properties = @{
            ipSecurityRestrictions                 = @($Main)
            scmIpSecurityRestrictions              = @($Scm)
            ipSecurityRestrictionsDefaultAction    = $MainDefault
            scmIpSecurityRestrictionsDefaultAction = $ScmDefault
            scmIpSecurityRestrictionsUseMain       = $ScmUseMain
        }
    } | ConvertTo-Json -Depth 10)
}

function script:New-SlotPageJson {
    # ARM reports each slot's `name` as the COMPOUND "<site>/<slot>".
    param([string[]]$Slots = @(), [string]$NextLink)
    $o = @{ value = @($Slots | ForEach-Object { @{ name = "$script:Site/$_"; type = 'Microsoft.Web/sites/slots' } }) }
    if ($NextLink) { $o['nextLink'] = $NextLink }
    return ($o | ConvertTo-Json -Depth 10)
}

# ── Convenience: an open vs a restricted config ───────────────────────────────
function script:New-OpenConfigJson {
    # No concrete rule anywhere and both defaults Allow => unrestricted.
    return (New-ConfigJson -Main @() -Scm @() -MainDefault 'Allow' -ScmDefault 'Allow')
}

function script:New-RestrictedConfigJson {
    # A concrete rule on main => restricted; SCM inherits main so only one list.
    param([int]$Priority = 100, [string]$Ip = '198.51.100.7/32')
    return (New-ConfigJson -Main @((New-IpRule -Ip $Ip -Priority $Priority -Name 'corp-hq')) `
                           -Scm @() -MainDefault 'Allow' -ScmDefault 'Allow' -ScmUseMain $true)
}

function script:New-JitRow {
    param([string]$RuleIdentifier = $script:RuleId)
    return [PSCustomObject]@{
        PartitionKey   = 'appService'
        RowKey         = 'row-1'
        TargetType     = 'appService'
        RuleIdentifier = $RuleIdentifier
        SubscriptionId = $script:Sub
        ResourceRg     = $script:Rg
        ResourceName   = $script:Site
        CallerIp       = $script:CallerIp
    }
}

# ── Assertion helpers over the recorded PATCH log ─────────────────────────────
function script:Get-PatchesFor {
    # `return ,@(...)` — the leading comma keeps a single match an ARRAY; a bare
    # `return @($x)` unrolls to the scalar and `(...)[0]` would then index the
    # hashtable by the key '0' and silently yield $null.
    param([string]$PathLike)
    return ,@($global:AppSvcPatches | Where-Object { $_.Path -like $PathLike })
}

function script:Get-JitEntry {
    # The JIT entry this handler appended to one of the two lists in a PATCH body.
    param($Patch, [string]$List = 'ipSecurityRestrictions')
    return @($Patch.Body.properties.$List | Where-Object { $_.name -eq $script:RuleId })[0]
}

}   # end BeforeAll

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Add-JITAppServiceRule — deployment slot coverage' {

    BeforeEach {
        $global:AppSvcConfigs      = @{}      # ARM path -> config/web JSON
        $global:AppSvcSlotPages    = @()      # ordered JSON pages for the slots collection
        $global:AppSvcSlotCalls    = 0
        $global:AppSvcSlotThrow    = $false
        $global:AppSvcGetFailPaths = @()
        $global:AppSvcPatchFailPaths = @()
        $global:AppSvcPatches      = @()
        $global:AppSvcGets         = @()

        Mock -ModuleName JITTargets Write-Warning { }
        Mock -ModuleName JITTargets Wait-JITArmAsyncOperation { }

        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            if ($Method -eq 'GET') {
                $global:AppSvcGets += $Path
                # Anything that is not a config/web read is a slots-collection read
                # (first page by relative path, later pages by absolute nextLink).
                if ($Path -notlike '*/config/web') {
                    if ($global:AppSvcSlotThrow) { throw 'ARM 403 AuthorizationFailed listing slots' }
                    $i = $global:AppSvcSlotCalls
                    $global:AppSvcSlotCalls++
                    if ($i -ge $global:AppSvcSlotPages.Count) { throw "unexpected slots page request #$i" }
                    return @{ StatusCode = 200; Headers = @{}; Content = $global:AppSvcSlotPages[$i] }
                }
                if ($global:AppSvcGetFailPaths -contains $Path) { throw "ARM 500 reading $Path" }
                if (-not $global:AppSvcConfigs.ContainsKey($Path)) { throw "test fixture has no config registered for $Path" }
                return @{ StatusCode = 200; Headers = @{ ETag = '"etag-1"' }; Content = $global:AppSvcConfigs[$Path] }
            }

            $global:AppSvcPatches += @{ Path = $Path; Method = $Method; Body = $Body; ApiVersion = $ApiVersion }
            if ($global:AppSvcPatchFailPaths -contains $Path) { throw "ARM 500 writing $Path" }
            return @{ StatusCode = 200; Headers = @{}; Content = '' }
        }
    }

    # ── (1) Site + two restricted slots: all three written, one shared RuleId ──

    It 'writes the rule to the site and to every restricted slot' {
        $global:AppSvcConfigs[$script:SitePath]                = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')]   = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]        = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging', 'qa')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                     | Should -Be 'Created'
        $r.RuleIdentifier             | Should -Be $script:RuleId
        $r.Details.site               | Should -Be 'Created'
        $r.Details.slotCount          | Should -Be 2
        $r.Details.slots['staging']   | Should -Be 'Created'
        $r.Details.slots['qa']        | Should -Be 'Created'
        $global:AppSvcPatches.Count   | Should -Be 3
    }

    It 'PATCHes the site config and each slot config path exactly once' {
        $global:AppSvcConfigs[$script:SitePath]                = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')]   = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]        = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging', 'qa')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter {
            $Method -eq 'PATCH' -and $Path -like '*/sites/contoso-web/config/web'
        }
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter {
            $Method -eq 'PATCH' -and $Path -like '*/sites/contoso-web/slots/staging/config/web'
        }
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter {
            $Method -eq 'PATCH' -and $Path -like '*/sites/contoso-web/slots/qa/config/web'
        }
    }

    It 'uses the SAME rule name on the site and on every slot' {
        $global:AppSvcConfigs[$script:SitePath]                = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')]   = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]        = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging', 'qa')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        foreach ($p in $global:AppSvcPatches) {
            $entry = Get-JitEntry -Patch $p
            $entry               | Should -Not -BeNullOrEmpty
            $entry.name          | Should -Be $script:RuleId
            $entry.ipAddress     | Should -Be "$script:CallerIp/32"
            $entry.action        | Should -Be 'Allow'
        }
    }

    It 'sends the slot writes to the sites/{name}/slots/{slot}/config/web child with the 2024-04-01 api-version' {
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        $slotPatch = @(Get-PatchesFor '*/slots/staging/config/web')
        $slotPatch.Count            | Should -Be 1
        $slotPatch[0].ApiVersion    | Should -Be '2024-04-01'
    }

    It 'enumerates slots with GET on the sites/{name}/slots collection at 2024-04-01' {
        $global:AppSvcConfigs[$script:SitePath] = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @()))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter {
            $Method -eq 'GET' -and $Path -like '*/sites/contoso-web/slots' -and $ApiVersion -eq '2024-04-01'
        }
    }

    # ── (2) An OPEN slot is never locked down ─────────────────────────────────

    It 'leaves an OPEN slot untouched while still granting on the restricted site' {
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-OpenConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                   | Should -Be 'Created'
        $r.Details.site             | Should -Be 'Created'
        $r.Details.slots['staging'] | Should -Be 'SkippedOpen'
        (Get-PatchesFor '*/slots/staging/config/web').Count | Should -Be 0
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 0 -Scope It -ParameterFilter {
            $Method -eq 'PATCH' -and $Path -like '*/slots/staging/config/web'
        }
    }

    It 'treats a slot whose only rule is the catch-all Any as open' {
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] =
            New-ConfigJson -Main @((New-IpRule -Ip 'Any' -Priority 2147483647 -Name 'Allow all')) -Scm @() -ScmUseMain $true
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Details.slots['staging'] | Should -Be 'SkippedOpen'
        (Get-PatchesFor '*/slots/staging/config/web').Count | Should -Be 0
    }

    It 'treats a slot with DefaultAction Deny and no rules as restricted' {
        $global:AppSvcConfigs[$script:SitePath]              = New-OpenConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] =
            New-ConfigJson -Main @() -Scm @() -MainDefault 'Deny' -ScmUseMain $true
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Details.slots['staging'] | Should -Be 'Created'
    }

    It 'treats a slot holding only a vnet rule as restricted' {
        $global:AppSvcConfigs[$script:SitePath]              = New-OpenConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] =
            New-ConfigJson -Main @((New-VnetRule)) -Scm @() -ScmUseMain $true
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Details.slots['staging'] | Should -Be 'Created'
    }

    # ── (3) Aggregation is NOT site-driven ────────────────────────────────────

    It 'reports Created when only a slot was restricted and the site was open' {
        $global:AppSvcConfigs[$script:SitePath]              = New-OpenConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                   | Should -Be 'Created'
        $r.Details.site             | Should -Be 'SkippedOpen'
        $r.Details.slots['staging'] | Should -Be 'Created'
        $r.Details.note             | Should -BeNullOrEmpty
        (Get-PatchesFor '*/sites/contoso-web/config/web').Count | Should -Be 0
    }

    # ── (4) Everything open ───────────────────────────────────────────────────

    It 'reports SkippedOpen and writes nothing when the site and all slots are open' {
        $global:AppSvcConfigs[$script:SitePath]              = New-OpenConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-OpenConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]      = New-OpenConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging', 'qa')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                   | Should -Be 'SkippedOpen'
        $r.Details.site             | Should -Be 'SkippedOpen'
        $r.Details.slots['staging'] | Should -Be 'SkippedOpen'
        $r.Details.slots['qa']      | Should -Be 'SkippedOpen'
        $r.Details.note             | Should -Not -BeNullOrEmpty
        $global:AppSvcPatches.Count | Should -Be 0
    }

    # ── (5) Already present, by caller IP ─────────────────────────────────────

    It 'reports AlreadyPresent and writes nothing when the caller IP is allowed everywhere' {
        $present = New-ConfigJson -Main @((New-IpRule -Ip "$script:CallerIp/32" -Priority 3000 -Name 'someone-elses-name')) `
                                  -Scm @() -MainDefault 'Deny' -ScmUseMain $true
        $global:AppSvcConfigs[$script:SitePath]              = $present
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = $present
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                   | Should -Be 'AlreadyPresent'
        $r.Details.site             | Should -Be 'AlreadyPresent'
        $r.Details.slots['staging'] | Should -Be 'AlreadyPresent'
        $r.Details.note             | Should -Not -BeNullOrEmpty
        $global:AppSvcPatches.Count | Should -Be 0
    }

    It 'detects the caller IP in bare (non-CIDR) form too' {
        $present = New-ConfigJson -Main @((New-IpRule -Ip $script:CallerIp -Priority 3000 -Name 'bare-form')) `
                                  -Scm @() -MainDefault 'Deny' -ScmUseMain $true
        $global:AppSvcConfigs[$script:SitePath] = $present
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @()))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status | Should -Be 'AlreadyPresent'
    }

    # ── (6) Priority is computed PER RESOURCE ─────────────────────────────────

    It 'gives a slot its own free priority instead of reusing the site priority' {
        # Site has nothing in the JIT band -> picks 3000. The slot already holds a
        # rule at 3000, so it must pick a different, still-in-band priority.
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson -Priority 100
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-RestrictedConfigJson -Priority 3000
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        $sitePri = (Get-JitEntry -Patch (Get-PatchesFor '*/sites/contoso-web/config/web')[0]).priority
        $slotPri = (Get-JitEntry -Patch (Get-PatchesFor '*/slots/staging/config/web')[0]).priority

        $sitePri | Should -Be 3000
        $slotPri | Should -Not -Be 3000
        ($slotPri -ge 3000 -and $slotPri -le 3900) | Should -Be $true
    }

    It 'keeps the existing rules in the slot body (read-modify-write, not replace)' {
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-RestrictedConfigJson -Ip '198.51.100.9/32'
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        $body = (Get-PatchesFor '*/slots/staging/config/web')[0].Body
        @($body.properties.ipSecurityRestrictions).Count | Should -Be 2
        @($body.properties.ipSecurityRestrictions | Where-Object { $_.ipAddress -eq '198.51.100.9/32' }).Count | Should -Be 1
    }

    # ── (7) SCM list handling per slot ────────────────────────────────────────

    It 'touches only the main list on a slot whose SCM inherits main (UseMain = true)' {
        $global:AppSvcConfigs[$script:SitePath] = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] =
            New-ConfigJson -Main @((New-IpRule -Ip '198.51.100.7/32' -Priority 100 -Name 'corp')) `
                           -Scm  @((New-IpRule -Ip '198.51.100.8/32' -Priority 100 -Name 'kudu')) `
                           -ScmUseMain $true
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        $body = (Get-PatchesFor '*/slots/staging/config/web')[0].Body
        $body.properties.ContainsKey('ipSecurityRestrictions')    | Should -Be $true
        $body.properties.ContainsKey('scmIpSecurityRestrictions') | Should -Be $false
    }

    It 'writes both lists on a slot whose SCM is separately restricted' {
        $global:AppSvcConfigs[$script:SitePath] = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] =
            New-ConfigJson -Main @((New-IpRule -Ip '198.51.100.7/32' -Priority 100 -Name 'corp')) `
                           -Scm  @((New-IpRule -Ip '198.51.100.8/32' -Priority 100 -Name 'kudu')) `
                           -ScmUseMain $false
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        $body = (Get-PatchesFor '*/slots/staging/config/web')[0].Body
        $body.properties.ContainsKey('ipSecurityRestrictions')    | Should -Be $true
        $body.properties.ContainsKey('scmIpSecurityRestrictions') | Should -Be $true
        (Get-JitEntry -Patch (Get-PatchesFor '*/slots/staging/config/web')[0] -List 'scmIpSecurityRestrictions').name |
            Should -Be $script:RuleId
    }

    It 'writes only the SCM list on a slot whose main list is open but SCM is restricted' {
        $global:AppSvcConfigs[$script:SitePath] = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] =
            New-ConfigJson -Main @() -Scm @((New-IpRule -Ip '198.51.100.8/32' -Priority 100 -Name 'kudu')) `
                           -MainDefault 'Allow' -ScmUseMain $false
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
            -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId | Out-Null

        $body = (Get-PatchesFor '*/slots/staging/config/web')[0].Body
        $body.properties.ContainsKey('ipSecurityRestrictions')    | Should -Be $false
        $body.properties.ContainsKey('scmIpSecurityRestrictions') | Should -Be $true
    }

    # ── (8) Paging over the slots collection ──────────────────────────────────

    It 'follows nextLink and grants on slots from both pages' {
        $nextLink = 'https://management.azure.com/subscriptions/x/resourceGroups/y/providers/Microsoft.Web/sites/contoso-web/slots?api-version=2024-04-01&%24skiptoken=page2'
        $global:AppSvcSlotPages = @(
            (New-SlotPageJson -Slots @('staging') -NextLink $nextLink),
            (New-SlotPageJson -Slots @('qa'))
        )
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]      = New-RestrictedConfigJson

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $global:AppSvcSlotCalls     | Should -Be 2
        $r.Details.slotCount        | Should -Be 2
        $r.Details.slots['staging'] | Should -Be 'Created'
        $r.Details.slots['qa']      | Should -Be 'Created'
        (Get-PatchesFor '*/slots/qa/config/web').Count | Should -Be 1
    }

    # ── (9) A site with no slots behaves exactly like the old site-only path ──

    It 'reports slotCount 0 and an empty slots map when the site has no slots' {
        $global:AppSvcConfigs[$script:SitePath] = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @()))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                   | Should -Be 'Created'
        $r.Details.site             | Should -Be 'Created'
        $r.Details.slotCount        | Should -Be 0
        $r.Details.slots.Count      | Should -Be 0
        $global:AppSvcPatches.Count | Should -Be 1
        $r.Details.ContainsKey('slotFailures') | Should -Be $false
    }

    # ── (10) Slot enumeration failure is non-fatal ────────────────────────────

    It 'still returns the site outcome and flags Details when slot enumeration throws' {
        $global:AppSvcConfigs[$script:SitePath] = New-RestrictedConfigJson
        $global:AppSvcSlotThrow = $true

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                       | Should -Be 'Created'
        $r.Details.site                 | Should -Be 'Created'
        $r.Details.slotEnumerationFailed | Should -Be $true
        $r.Details.slotEnumerationError | Should -Not -BeNullOrEmpty
        $r.Details.slotCount            | Should -Be 0
        $global:AppSvcPatches.Count     | Should -Be 1
        Should -Invoke -CommandName Write-Warning -ModuleName JITTargets -Times 1 -Scope It
    }

    # ── (11) A single slot's write failure does not cost the others ───────────

    It 'marks only the failing slot Failed and still processes the remaining slots' {
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]      = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging', 'qa')))
        $global:AppSvcPatchFailPaths = @((Get-SlotConfigPath 'staging'))

        $r = Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
                -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId

        $r.Status                          | Should -Be 'Created'
        $r.Details.slots['staging']        | Should -Be 'Failed'
        $r.Details.slots['qa']             | Should -Be 'Created'
        $r.Details.slotFailures['staging'] | Should -Not -BeNullOrEmpty
        $r.Details.slotFailures.ContainsKey('qa') | Should -Be $false
        (Get-PatchesFor '*/slots/qa/config/web').Count | Should -Be 1
    }

    # ── (12) A SITE-level failure must NOT be swallowed ───────────────────────

    It 'propagates a failure on the site itself' {
        $global:AppSvcGetFailPaths = @($script:SitePath)
        $global:AppSvcSlotPages    = @((New-SlotPageJson -Slots @()))

        { Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
              -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId } | Should -Throw
    }

    It 'propagates a failed WRITE on the site itself' {
        $global:AppSvcConfigs[$script:SitePath] = New-RestrictedConfigJson
        $global:AppSvcPatchFailPaths = @($script:SitePath)
        $global:AppSvcSlotPages      = @((New-SlotPageJson -Slots @()))

        { Add-JITAppServiceRule -SubscriptionId $script:Sub -ResourceGroup $script:Rg `
              -ResourceName $script:Site -CallerIp $script:CallerIp -RuleId $script:RuleId } | Should -Throw
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Remove-JITAppServiceRule' {

    BeforeEach {
        $global:AppSvcConfigs      = @{}
        $global:AppSvcSlotPages    = @()
        $global:AppSvcSlotCalls    = 0
        $global:AppSvcSlotThrow    = $false
        $global:AppSvcGetFailPaths = @()
        $global:AppSvcPatchFailPaths = @()
        $global:AppSvcPatches      = @()
        $global:AppSvcGets         = @()

        Mock -ModuleName JITTargets Write-Warning { }
        Mock -ModuleName JITTargets Wait-JITArmAsyncOperation { }

        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            if ($Method -eq 'GET') {
                $global:AppSvcGets += $Path
                if ($Path -notlike '*/config/web') {
                    if ($global:AppSvcSlotThrow) { throw 'ARM 403 AuthorizationFailed listing slots' }
                    $i = $global:AppSvcSlotCalls
                    $global:AppSvcSlotCalls++
                    if ($i -ge $global:AppSvcSlotPages.Count) { throw "unexpected slots page request #$i" }
                    return @{ StatusCode = 200; Headers = @{}; Content = $global:AppSvcSlotPages[$i] }
                }
                if ($global:AppSvcGetFailPaths -contains $Path) { throw "ARM 500 reading $Path" }
                if (-not $global:AppSvcConfigs.ContainsKey($Path)) { throw "test fixture has no config registered for $Path" }
                return @{ StatusCode = 200; Headers = @{ ETag = '"etag-1"' }; Content = $global:AppSvcConfigs[$Path] }
            }

            $global:AppSvcPatches += @{ Path = $Path; Method = $Method; Body = $Body; ApiVersion = $ApiVersion }
            if ($global:AppSvcPatchFailPaths -contains $Path) { throw "ARM 500 writing $Path" }
            return @{ StatusCode = 200; Headers = @{}; Content = '' }
        }
    }

    # A config that still carries the JIT rule alongside a pre-existing rule.
    function script:New-ConfigWithJitRuleJson {
        return (New-ConfigJson -Main @(
                    (New-IpRule -Ip '198.51.100.7/32' -Priority 100 -Name 'corp-hq'),
                    (New-IpRule -Ip "$script:CallerIp/32" -Priority 3000 -Name $script:RuleId)
                ) -Scm @() -ScmUseMain $true)
    }

    It 'strips the rule from the site and every slot and reports Removed' {
        $global:AppSvcConfigs[$script:SitePath]              = New-ConfigWithJitRuleJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-ConfigWithJitRuleJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]      = New-ConfigWithJitRuleJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging', 'qa')))

        $r = Remove-JITAppServiceRule -Row (New-JitRow)

        $r.Status                   | Should -Be 'Removed'
        $r.Details.site             | Should -Be 'Removed'
        $r.Details.slotCount        | Should -Be 2
        $r.Details.slots['staging'] | Should -Be 'Removed'
        $r.Details.slots['qa']      | Should -Be 'Removed'
        $global:AppSvcPatches.Count | Should -Be 3
    }

    It 'leaves the other rules in place when stripping the JIT rule' {
        $global:AppSvcConfigs[$script:SitePath] = New-ConfigWithJitRuleJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @()))

        Remove-JITAppServiceRule -Row (New-JitRow) | Out-Null

        $body = (Get-PatchesFor '*/sites/contoso-web/config/web')[0].Body
        @($body.properties.ipSecurityRestrictions).Count | Should -Be 1
        @($body.properties.ipSecurityRestrictions)[0].name | Should -Be 'corp-hq'
    }

    It 'reports NotFound and writes nothing when the rule is already gone everywhere' {
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-RestrictedConfigJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Remove-JITAppServiceRule -Row (New-JitRow)

        $r.Status                   | Should -Be 'NotFound'
        $r.Details.site             | Should -Be 'NotFound'
        $r.Details.slots['staging'] | Should -Be 'NotFound'
        $global:AppSvcPatches.Count | Should -Be 0
    }

    It 'reports Removed when the rule only survived on a slot' {
        $global:AppSvcConfigs[$script:SitePath]              = New-RestrictedConfigJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-ConfigWithJitRuleJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging')))

        $r = Remove-JITAppServiceRule -Row (New-JitRow)

        $r.Status                   | Should -Be 'Removed'
        $r.Details.site             | Should -Be 'NotFound'
        $r.Details.slots['staging'] | Should -Be 'Removed'
        (Get-PatchesFor '*/slots/staging/config/web').Count | Should -Be 1
        (Get-PatchesFor '*/sites/contoso-web/config/web').Count | Should -Be 0
    }

    It 'strips the rule from the SCM list as well' {
        $global:AppSvcConfigs[$script:SitePath] = New-ConfigJson `
            -Main @((New-IpRule -Ip "$script:CallerIp/32" -Priority 3000 -Name $script:RuleId)) `
            -Scm  @((New-IpRule -Ip "$script:CallerIp/32" -Priority 3000 -Name $script:RuleId)) `
            -ScmUseMain $false
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @()))

        $r = Remove-JITAppServiceRule -Row (New-JitRow)

        $r.Status | Should -Be 'Removed'
        $body = (Get-PatchesFor '*/sites/contoso-web/config/web')[0].Body
        @($body.properties.ipSecurityRestrictions).Count    | Should -Be 0
        @($body.properties.scmIpSecurityRestrictions).Count | Should -Be 0
    }

    It 'still reports the site outcome and flags Details when slot enumeration throws' {
        $global:AppSvcConfigs[$script:SitePath] = New-ConfigWithJitRuleJson
        $global:AppSvcSlotThrow = $true

        $r = Remove-JITAppServiceRule -Row (New-JitRow)

        $r.Status                        | Should -Be 'Removed'
        $r.Details.slotEnumerationFailed | Should -Be $true
        $r.Details.slotCount             | Should -Be 0
        Should -Invoke -CommandName Write-Warning -ModuleName JITTargets -Times 1 -Scope It
    }

    It 'marks only the failing slot Failed during revocation' {
        $global:AppSvcConfigs[$script:SitePath]              = New-ConfigWithJitRuleJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'staging')] = New-ConfigWithJitRuleJson
        $global:AppSvcConfigs[(Get-SlotConfigPath 'qa')]      = New-ConfigWithJitRuleJson
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @('staging', 'qa')))
        $global:AppSvcPatchFailPaths = @((Get-SlotConfigPath 'staging'))

        $r = Remove-JITAppServiceRule -Row (New-JitRow)

        $r.Status                          | Should -Be 'Removed'
        $r.Details.slots['staging']        | Should -Be 'Failed'
        $r.Details.slots['qa']             | Should -Be 'Removed'
        $r.Details.slotFailures['staging'] | Should -Not -BeNullOrEmpty
    }

    It 'falls back to RowKey when RuleIdentifier is missing' {
        $row = New-JitRow -RuleIdentifier $null
        $global:AppSvcConfigs[$script:SitePath] = New-ConfigJson `
            -Main @((New-IpRule -Ip "$script:CallerIp/32" -Priority 3000 -Name 'row-1')) -Scm @() -ScmUseMain $true
        $global:AppSvcSlotPages = @((New-SlotPageJson -Slots @()))

        $r = Remove-JITAppServiceRule -Row $row

        $r.Status | Should -Be 'Removed'
    }

    It 'returns NotFound without any ARM call when the row has no identifier at all' {
        $row = [PSCustomObject]@{
            RuleIdentifier = $null; RowKey = $null
            SubscriptionId = $script:Sub; ResourceRg = $script:Rg; ResourceName = $script:Site
        }

        $r = Remove-JITAppServiceRule -Row $row

        $r.Status               | Should -Be 'NotFound'
        $r.Details.reason       | Should -Be 'no-identifier'
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 0 -Scope It
    }

    It 'propagates a failure on the site itself during revocation' {
        $global:AppSvcGetFailPaths = @($script:SitePath)
        $global:AppSvcSlotPages    = @((New-SlotPageJson -Slots @()))

        { Remove-JITAppServiceRule -Row (New-JitRow) } | Should -Throw
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Module-internal helpers, reached through InModuleScope.
# ─────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-AppServiceSlotShortName' {

    It 'takes the segment after the last slash of the compound ARM name' {
        InModuleScope JITTargets {
            ConvertTo-AppServiceSlotShortName 'mysite/staging' | Should -Be 'staging'
        }
    }

    It 'passes a name that is already short through unchanged' {
        InModuleScope JITTargets {
            ConvertTo-AppServiceSlotShortName 'staging' | Should -Be 'staging'
        }
    }

    It 'returns $null for a null or empty name' {
        InModuleScope JITTargets {
            ConvertTo-AppServiceSlotShortName $null | Should -BeNullOrEmpty
            ConvertTo-AppServiceSlotShortName ''    | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-AppServiceConfigPath' {

    It 'builds the site config/web path when no slot is given' {
        InModuleScope JITTargets {
            Get-AppServiceConfigPath -SubscriptionId 's' -ResourceGroup 'rg' -ResourceName 'web' |
                Should -Be '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/web/config/web'
        }
    }

    It 'nests slots one level deeper' {
        InModuleScope JITTargets {
            Get-AppServiceConfigPath -SubscriptionId 's' -ResourceGroup 'rg' -ResourceName 'web' -Slot 'staging' |
                Should -Be '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/web/slots/staging/config/web'
        }
    }
}

Describe 'Test-AppServiceListRestricted' {

    It 'treats a DefaultAction of Deny as restricted even with no rules' {
        InModuleScope JITTargets {
            Test-AppServiceListRestricted -Rules @() -DefaultAction 'Deny' | Should -Be $true
        }
    }

    It 'treats an empty list with DefaultAction Allow as open' {
        InModuleScope JITTargets {
            Test-AppServiceListRestricted -Rules @() -DefaultAction 'Allow' | Should -Be $false
        }
    }

    It 'treats a list holding only the catch-all Any rule as open' {
        InModuleScope JITTargets {
            $rules = @([PSCustomObject]@{ ipAddress = 'Any'; action = 'Allow'; priority = 2147483647 })
            Test-AppServiceListRestricted -Rules $rules -DefaultAction 'Allow' | Should -Be $false
        }
    }

    It 'treats a concrete ipAddress rule as restricted' {
        InModuleScope JITTargets {
            $rules = @([PSCustomObject]@{ ipAddress = '198.51.100.7/32'; action = 'Allow'; priority = 100 })
            Test-AppServiceListRestricted -Rules $rules -DefaultAction 'Allow' | Should -Be $true
        }
    }

    It 'treats a vnet rule as restricted' {
        InModuleScope JITTargets {
            $rules = @([PSCustomObject]@{ vnetSubnetResourceId = '/subscriptions/x/.../subnets/s'; action = 'Allow'; priority = 100 })
            Test-AppServiceListRestricted -Rules $rules -DefaultAction 'Allow' | Should -Be $true
        }
    }
}
