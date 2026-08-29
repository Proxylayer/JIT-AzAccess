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
# DEPLOYMENT SLOTS — one grant covers the whole site:
#   A deployment slot is a separate ARM child with its OWN, completely
#   independent config/web at .../sites/{name}/slots/{slot}/config/web, so a
#   grant against the site alone leaves every slot's allowlist untouched. That
#   is almost never what the requester wants (a developer granted access to a
#   web app expects to reach its staging slot too), so a grant/revoke for a site
#   is applied to the site AND to EVERY deployment slot it has:
#     • Slots are enumerated with GET .../sites/{name}/slots (paged via
#       nextLink). Each returned entry's `name` is the COMPOUND "<site>/<slot>";
#       we take the segment after the last '/' as the slot's short name.
#     • The open-site guard above is re-evaluated INDEPENDENTLY PER SLOT — an
#       open slot is left open even when the site itself is restricted, and vice
#       versa. We never convert an open resource to implicit-deny.
#     • The free priority is computed PER RESOURCE, because each slot's config
#       has its own, independent priority space.
#     • The SAME RuleId (rule name) is used for the site and every slot. Removal
#       keys off the rule name, so one identifier covering all of them is what
#       lets a single JITRules row revoke every resource it touched.
#   CONSEQUENCE, accepted by design: a grant against a production site also
#   whitelists that site's staging/QA slots. One JITRules row therefore drives
#   N ARM writes.
#
# PARTIAL FAILURE — best effort, always visible in the audit row:
#   Slot enumeration failing (or a single slot's write failing) must not abort
#   the rest of the operation, so both are caught, warned about, and recorded in
#   the returned Details hashtable (slotCount / slots / slotFailures /
#   slotEnumerationFailed). Details flows into the audit row, so a partial grant
#   or partial revoke is visible there rather than being silently reported as a
#   clean Created/Removed.
#
# RuleIdentifier stored = the rule name (RuleId), the key we remove by — shared
# by the site and all of its slots.

# ── ARM API version ───────────────────────────────────────────────────────────
$script:AppServiceApi = '2024-04-01'   # Microsoft.Web/sites/config, /sites/slots

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

function script:Get-AppServiceConfigPath {
    # ARM path of the config/web child for either the site itself (-Slot omitted)
    # or one of its deployment slots. Slots nest one level deeper:
    #   site:  /providers/Microsoft.Web/sites/{name}/config/web
    #   slot:  /providers/Microsoft.Web/sites/{name}/slots/{slot}/config/web
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [string]$Slot
    )
    $p = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
         "/providers/Microsoft.Web/sites/$ResourceName"
    if ($Slot) { $p += "/slots/$Slot" }
    return "$p/config/web"
}

function script:ConvertTo-AppServiceSlotShortName {
    # ARM reports a slot's `name` as the COMPOUND "<site>/<slot>" (e.g.
    # "contoso-web/staging") on the .../sites/{name}/slots collection, while the
    # slot segment of the child ARM path is the SHORT name ("staging") only. So
    # we take everything after the last '/'.
    #
    # The compound form is what the Web Apps REST API documents and returns
    # today; we do NOT rely on it blindly — a name with no '/' is passed through
    # unchanged, which is exactly the right answer if the RP ever starts
    # returning short names directly.
    param([string]$Name)
    if (-not $Name) { return $null }
    $i = $Name.LastIndexOf('/')
    if ($i -lt 0) { return $Name }
    return $Name.Substring($i + 1)
}

function script:Get-AppServiceSlotNames {
    <#
        Lists the SHORT names of every deployment slot on a site, following
        nextLink so a site with many slots is fully enumerated.

            GET /subscriptions/{sub}/resourceGroups/{rg}
                /providers/Microsoft.Web/sites/{name}/slots?api-version=...
            -> { "value": [ { "name": "<site>/<slot>", ... } ], "nextLink": ... }

        Always returns an ARRAY (empty when the site has no slots), never $null,
        so callers can foreach over the result unguarded. Throws on an ARM
        failure — callers decide whether that is fatal (it never is; see the
        header note on partial failure).
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName
    )

    $names = @()
    $next  = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
             "/providers/Microsoft.Web/sites/$ResourceName/slots"

    do {
        # nextLink is absolute and already carries its own api-version; the
        # -ApiVersion below is ignored in that case (Invoke-ArmRestRaw only
        # appends one when the URL has none), so the same call serves both pages.
        $resp = Invoke-ArmRestRaw -Method GET -Path $next -ApiVersion $script:AppServiceApi
        $page = if ($resp.Content) { $resp.Content | ConvertFrom-Json } else { $null }

        foreach ($slot in @($page.value)) {
            $short = ConvertTo-AppServiceSlotShortName ([string]$slot.name)
            if ($short) { $names += $short }
        }

        $next = if ($page) { [string]$page.nextLink } else { $null }
    } while ($next)

    return ,@($names)
}

function script:Add-JITAppServiceRuleToConfig {
    <#
        Applies the JIT Allow rule to ONE config/web resource — the site's own or
        a single slot's; the two are byte-identical in schema, so one function
        serves both. Returns the per-resource outcome as a string:
          'Created'        — the rule was written
          'AlreadyPresent' — an eligible restricted list already allows the IP
          'SkippedOpen'    — no list on this resource is restricted; left alone
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    # Set by the -Modify block so the caller can distinguish the two no-write
    # outcomes: SkippedOpen (resource open/unrestricted, no list eligible) vs
    # AlreadyPresent (an eligible restricted list already carries our rule).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $Path -ApiVersion $script:AppServiceApi -WriteMethod PATCH -Modify {
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
        # This is computed per CONFIG RESOURCE: every slot has its own, entirely
        # separate priority space, so a slot must never inherit the priority
        # chosen for the site.
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

    if ($r.Changed) { return 'Created' }
    return $outcome.Reason
}

function script:Remove-JITAppServiceRuleFromConfig {
    <#
        Strips the named JIT rule from ONE config/web resource (the site's own or
        a single slot's). Returns 'Removed' when the rule was actually stripped,
        'NotFound' when it was already gone (idempotent).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RuleName
    )

    $r = Invoke-JITArmReadModifyWrite -Path $Path -ApiVersion $script:AppServiceApi -WriteMethod PATCH -Modify {
        param($resource)
        $props = if ($resource.properties) { $resource.properties } else { $null }
        if (-not $props) { return $false }

        $mainList = @(); if ($props.ipSecurityRestrictions)    { $mainList = @($props.ipSecurityRestrictions) }
        $scmList  = @(); if ($props.scmIpSecurityRestrictions) { $scmList  = @($props.scmIpSecurityRestrictions) }

        $newMain = @($mainList | Where-Object { $_.name -ne $RuleName })
        $newScm  = @($scmList  | Where-Object { $_.name -ne $RuleName })

        $bodyProps = @{}
        $changed   = $false
        # Removing our own Allow rule never opens the site (default action and all
        # other rules are preserved), so there is no empty-array danger here.
        if ($newMain.Count -ne $mainList.Count) { $bodyProps.ipSecurityRestrictions    = $newMain; $changed = $true }
        if ($newScm.Count  -ne $scmList.Count)  { $bodyProps.scmIpSecurityRestrictions = $newScm;  $changed = $true }

        if (-not $changed) { return $false }   # already gone (idempotent)
        return @{ properties = $bodyProps }
    }

    if ($r.Changed) { return 'Removed' }
    return 'NotFound'
}

function Add-JITAppServiceRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $details  = @{}
    $statuses = @()   # per-resource outcomes, site first, then each slot

    # ── 1. The site's own config/web (unchanged behavior) ─────────────────────
    # Deliberately NOT wrapped in a try: a failure to grant on the site itself is
    # a real grant failure and must surface to the dispatcher.
    $sitePath   = Get-AppServiceConfigPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ResourceName $ResourceName
    $siteStatus = Add-JITAppServiceRuleToConfig -Path $sitePath -CallerIp $CallerIp -RuleId $RuleId
    $statuses  += $siteStatus

    # ── 2. Every deployment slot, same rule name, guard re-evaluated per slot ──
    # Enumeration is best effort: if the slots list can't be read we still report
    # the site's outcome (the site grant already succeeded) and flag it in
    # Details so the audit row shows the coverage was incomplete.
    $slots = @()
    try {
        $slots = Get-AppServiceSlotNames -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ResourceName $ResourceName
    }
    catch {
        Write-Warning "  App Service '$ResourceName': could not enumerate deployment slots — slots were NOT granted access. $($_.Exception.Message)"
        $details.slotEnumerationFailed = $true
        $details.slotEnumerationError  = $_.Exception.Message
    }

    $slotStatuses = @{}
    $slotFailures = @{}
    foreach ($slot in @($slots)) {
        # Per-slot isolation: one slot failing (deleted mid-flight, RBAC gap,
        # persistent 412) must not cost the remaining slots their grant.
        try {
            $slotPath = Get-AppServiceConfigPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ResourceName $ResourceName -Slot $slot
            $s = Add-JITAppServiceRuleToConfig -Path $slotPath -CallerIp $CallerIp -RuleId $RuleId
            $slotStatuses[$slot] = $s
            $statuses += $s
        }
        catch {
            Write-Warning "  App Service '$ResourceName' slot '$slot': grant failed — $($_.Exception.Message)"
            $slotStatuses[$slot] = 'Failed'
            $slotFailures[$slot] = $_.Exception.Message
        }
    }

    $details.site      = $siteStatus
    $details.slotCount = @($slots).Count
    $details.slots     = $slotStatuses
    if ($slotFailures.Count -gt 0) { $details.slotFailures = $slotFailures }

    # ── 3. Aggregate across site + slots ──────────────────────────────────────
    # Created wins over AlreadyPresent wins over SkippedOpen: any real write
    # makes this a grant, and a rule present on at least one restricted resource
    # is meaningfully "already present" even if the others were open.
    $status =
        if     ($statuses -contains 'Created')        { 'Created' }
        elseif ($statuses -contains 'AlreadyPresent') { 'AlreadyPresent' }
        else                                          { 'SkippedOpen' }

    if ($status -ne 'Created') {
        $details.note = 'no change (site and slots are open/unrestricted, or rule already present)'
    }

    return @{ RuleIdentifier = $RuleId; Status = $status; Details = $details }
}

function Remove-JITAppServiceRule {
    param([Parameter(Mandatory)]$Row)

    # See Remove-JITNsgRule for the RowKey fallback rationale — App Service stores
    # RuleIdentifier = the rule name (RuleId), shared by the site and its slots.
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    if (-not $ruleName) {
        Write-Warning "  App Service row has neither RuleIdentifier nor RowKey — cannot identify rule to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $subscriptionId = [string]$Row.SubscriptionId
    $resourceGroup  = [string]$Row.ResourceRg
    $resourceName   = [string]$Row.ResourceName

    $details  = @{}
    $statuses = @()

    # ── 1. The site's own config/web ──────────────────────────────────────────
    $sitePath   = Get-AppServiceConfigPath -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -ResourceName $resourceName
    $siteStatus = Remove-JITAppServiceRuleFromConfig -Path $sitePath -RuleName $ruleName
    $statuses  += $siteStatus

    # ── 2. Every deployment slot ──────────────────────────────────────────────
    # TRADEOFF, deliberate: if slot enumeration fails during REVOCATION we still
    # return the site's outcome instead of throwing. Throwing would leave the
    # JITRules row un-reaped and it would be retried forever, stranding the row
    # while the site's rule is already gone. The warning below plus the
    # slotEnumerationFailed marker in Details (which lands in the audit row) is
    # the compensating signal that a slot may still carry the rule.
    $slots = @()
    try {
        $slots = Get-AppServiceSlotNames -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -ResourceName $resourceName
    }
    catch {
        Write-Warning "  App Service '$resourceName': could not enumerate deployment slots during revocation — a slot may still carry rule '$ruleName'. $($_.Exception.Message)"
        $details.slotEnumerationFailed = $true
        $details.slotEnumerationError  = $_.Exception.Message
    }

    $slotStatuses = @{}
    $slotFailures = @{}
    foreach ($slot in @($slots)) {
        try {
            $slotPath = Get-AppServiceConfigPath -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -ResourceName $resourceName -Slot $slot
            $s = Remove-JITAppServiceRuleFromConfig -Path $slotPath -RuleName $ruleName
            $slotStatuses[$slot] = $s
            $statuses += $s
        }
        catch {
            Write-Warning "  App Service '$resourceName' slot '$slot': revocation failed — rule '$ruleName' may still be present. $($_.Exception.Message)"
            $slotStatuses[$slot] = 'Failed'
            $slotFailures[$slot] = $_.Exception.Message
        }
    }

    $details.site      = $siteStatus
    $details.slotCount = @($slots).Count
    $details.slots     = $slotStatuses
    if ($slotFailures.Count -gt 0) { $details.slotFailures = $slotFailures }

    # Removed if the rule came off ANY resource; NotFound only when it was
    # already absent everywhere we managed to look.
    if ($statuses -contains 'Removed') { return @{ Status = 'Removed'; Details = $details } }
    return @{ Status = 'NotFound'; Details = $details }
}

#endregion
