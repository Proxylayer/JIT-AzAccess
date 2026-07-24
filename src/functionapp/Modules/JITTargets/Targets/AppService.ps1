# AppService.ps1
#region ── Azure App Service (Microsoft.Web/sites) ─────────────────────────────
# https://learn.microsoft.com/rest/api/appservice/web-apps/update-configuration
#
# The IP allowlist is an ARRAY-OF-OBJECTS on the site CONFIG child, at
# .../sites/{name}/config/web:
#   properties.ipSecurityRestrictions[]     — restrictions on the main site
#   properties.scmIpSecurityRestrictions[]  — restrictions on the SCM/Kudu site
# Each entry is shaped { ipAddress: '<cidr>', action: 'Allow'|'Deny',
# priority: <int>, name: '<id>', description: '<text>' }. Writes go via a
# SYNCHRONOUS PATCH on .../config/web (200, NOT long-running) sending the FULL
# mutated array(s) — PATCH replaces array properties wholesale, so we always
# re-send existing rules + our new one (read-modify-write) and never touch
# ipSecurityRestrictionsDefaultAction / scmIpSecurityRestrictionsDefaultAction.
#
# CRITICAL GUARD — never lock down an open site:
#   An App Service whose ipSecurityRestrictions list is empty (only the implicit
#   "Allow all / Any" rule) is UNRESTRICTED; adding a single Allow rule flips it
#   to implicit-deny-everyone-else. So we ONLY add the JIT rule when the site is
#   ALREADY restricted — i.e. it has at least one concrete rule (a specific
#   ipAddress/vnet, not the catch-all 'Any'), OR its DefaultAction == 'Deny'. A
#   currently-open site is left untouched (no-op result), never restricted.
#
# We whitelist BOTH the main site and the SCM/Kudu site, evaluating the guard
# independently per list. If scmIpSecurityRestrictionsUseMain is true the SCM
# site inherits the main rules, so we only touch the main list in that case.
#
# RuleIdentifier stored = the rule name (RuleId), the key we remove by.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:AppServiceApi = '2024-04-01'   # Microsoft.Web/sites/config

# ── JIT priority band ─────────────────────────────────────────────────────────
# Free-priority band for JIT rules, kept clear of the low priorities operators
# typically hand-assign (100–1000). We reuse the shared NSG free-priority scan
# (a generic "lowest unused priority in [Min,Max]" finder) so both lists get a
# priority that collides with neither existing rule.
$script:AppServiceJitPriorityMin = 3000
$script:AppServiceJitPriorityMax = 3900

function script:Test-AppServiceListRestricted {
    # A list is "restricted" (safe to add an Allow rule to) when its default
    # action is Deny, or it already contains a concrete rule (a specific address
    # or a vnet rule — anything other than the implicit catch-all 'Any' Allow).
    param($Rules, $DefaultAction)
    if ($DefaultAction -eq 'Deny') { return $true }
    foreach ($r in @($Rules)) {
        if ($r.vnetSubnetResourceId) { return $true }
        $ip = $r.ipAddress
        if ($ip -and $ip -ne 'Any') { return $true }
    }
    return $false
}

function Add-JITAppServiceRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.Web/sites/$ResourceName/config/web"

    # Set by the -Modify block so the handler can distinguish the two no-write
    # outcomes: SkippedOpen (site open/unrestricted, no list eligible) vs
    # AlreadyPresent (an eligible restricted list already carries our rule).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:AppServiceApi -WriteMethod PATCH -Modify {
        param($resource)
        $props = if ($resource.properties) { $resource.properties } else { $null }
        if (-not $props) { $outcome.Reason = 'SkippedOpen'; return $false }

        $mainList = @(); if ($props.ipSecurityRestrictions)    { $mainList = @($props.ipSecurityRestrictions) }
        $scmList  = @(); if ($props.scmIpSecurityRestrictions) { $scmList  = @($props.scmIpSecurityRestrictions) }
        $mainDefault = $props.ipSecurityRestrictionsDefaultAction
        $scmDefault  = $props.scmIpSecurityRestrictionsDefaultAction
        $scmUseMain  = [bool]$props.scmIpSecurityRestrictionsUseMain

        # Pick one free priority that collides with neither list, so the same
        # rule slots into both. (Reuse of the shared NSG "lowest free priority"
        # scan — the NSG naming is incidental; it is a generic band finder.)
        $used = @()
        foreach ($e in $mainList) { if ($null -ne $e.priority) { $used += [int]$e.priority } }
        foreach ($e in $scmList)  { if ($null -ne $e.priority) { $used += [int]$e.priority } }
        $priority = Get-AvailableNsgPriority `
            -Nsg @{ SecurityRules = @($used | ForEach-Object { [pscustomobject]@{ Direction = 'Inbound'; Priority = $_ } }) } `
            -Min $script:AppServiceJitPriorityMin -Max $script:AppServiceJitPriorityMax

        $entry = @{
            ipAddress   = "$CallerIp/32"
            action      = 'Allow'
            priority    = $priority
            name        = $RuleId
            description  = "JIT temporary access for $CallerIp"
        }

        $bodyProps = @{}
        $changed      = $false
        $anyRestricted = $false   # at least one eligible (restricted) list exists

        # "Already present" is detected by the caller IP (an Allow rule for this
        # IP, under ANY name), not by our per-request rule name — so a re-grant
        # for an already-whitelisted IP is a no-op instead of stacking duplicate
        # rules under fresh names.
        $ipCidr = "$CallerIp/32"
        $ipPresent = {
            param($list)
            [bool]($list | Where-Object {
                ($_.ipAddress -eq $ipCidr -or $_.ipAddress -eq $CallerIp) -and
                ($_.action -eq 'Allow' -or -not $_.action)
            })
        }

        # MAIN site — only if already restricted and the IP isn't already allowed.
        if (Test-AppServiceListRestricted -Rules $mainList -DefaultAction $mainDefault) {
            $anyRestricted = $true
            if (-not (& $ipPresent $mainList)) {
                $bodyProps.ipSecurityRestrictions = @($mainList) + @($entry)
                $changed = $true
            }
        }

        # SCM site — skip entirely when it inherits main; else same guard.
        if (-not $scmUseMain) {
            if (Test-AppServiceListRestricted -Rules $scmList -DefaultAction $scmDefault) {
                $anyRestricted = $true
                if (-not (& $ipPresent $scmList)) {
                    $bodyProps.scmIpSecurityRestrictions = @($scmList) + @($entry)
                    $changed = $true
                }
            }
        }

        if (-not $changed) {
            # An eligible restricted list existed but our rule was already on every
            # one => AlreadyPresent; otherwise no list was restricted => SkippedOpen.
            $outcome.Reason = if ($anyRestricted) { 'AlreadyPresent' } else { 'SkippedOpen' }
            return $false
        }
        return @{ properties = $bodyProps }
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $RuleId; Status = $outcome.Reason; Details = @{ note = 'no change (site is open/unrestricted, or rule already present)' } }
    }
    return @{ RuleIdentifier = $RuleId; Status = 'Created'; Details = @{} }
}

function Remove-JITAppServiceRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the RowKey fallback rationale — App Service stores
    # RuleIdentifier = the rule name (RuleId).
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  App Service row has neither RuleIdentifier nor RowKey — cannot identify rule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.Web/sites/$($Row.ResourceName)/config/web"

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:AppServiceApi -WriteMethod PATCH -Modify {
        param($resource)
        $props = if ($resource.properties) { $resource.properties } else { $null }
        if (-not $props) { return $false }

        $mainList = @(); if ($props.ipSecurityRestrictions)    { $mainList = @($props.ipSecurityRestrictions) }
        $scmList  = @(); if ($props.scmIpSecurityRestrictions) { $scmList  = @($props.scmIpSecurityRestrictions) }

        $newMain = @($mainList | Where-Object { $_.name -ne $ruleName })
        $newScm  = @($scmList  | Where-Object { $_.name -ne $ruleName })

        $bodyProps = @{}
        $changed   = $false
        # Removing our own Allow rule never opens the site (default action and all
        # other rules are preserved), so there is no empty-array danger here.
        if ($newMain.Count -ne $mainList.Count) { $bodyProps.ipSecurityRestrictions    = $newMain; $changed = $true }
        if ($newScm.Count  -ne $scmList.Count)  { $bodyProps.scmIpSecurityRestrictions = $newScm;  $changed = $true }

        if (-not $changed) { return $false }   # already gone (idempotent)
        return @{ properties = $bodyProps }
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = 'NotFound'; Details = @{} }
}

#endregion
