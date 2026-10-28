# Tests for the justification-policy and audit-history helpers in JITHelpers.psm1
# (FEAT-0003, items 2 & 6):
#   • Test-JustificationRequired — server-authoritative opt-out via the AzureTray
#     app-reg tag `JustificationRequired:false` (fail-safe: required when unknown).
#   • Add-JITAuditRow            — appends one row per lifecycle event to the
#     JITRulesAudit history table (unique RowKey, arbitrary Action strings).
#   • Update-JITTableRow         — MERGE (partial update) keyed by PK+RK, used to
#     refresh a JITRules row's ExpiryUtc on the extend path.
#
# Plus (TODO-0017) the target-handler Details column on the audit row:
#   • ConvertTo-JITAuditDetails  — module-internal serializer (depth 6, 8192-char
#     cap with an explicit truncation envelope, $null on empty or on failure).
#   • Add-JITAuditRow -Details   — stores that JSON in a single `Details` column,
#     omitted entirely when there is nothing to store.
#   • The call-site wiring in the three function-app entry points, including the
#     one deliberate omission in the Remove-ExpiredRules outer catch.
#
# The table layer (Invoke-TableRest, defined in HttpHelpers and imported globally)
# is mocked with `-ModuleName JITHelpers` so the mocks intercept the calls the
# JITHelpers functions make — nothing touches Table Storage or the network.
# Get-AzureTrayAppRegTags is likewise mocked so Test-JustificationRequired never
# calls Graph. Cross-scope capture uses $global:* (mock scriptblocks run in the
# module scope), reset in BeforeEach.
#
# Pester 3.4.0 compatible (no BeforeAll at top level, no Should -Verb syntax).
#
# Run:  Invoke-Pester ./src/functionapp/tests/JITHelpers.Audit.Tests.ps1

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force

# Pester 3.4's `Should Throw` does not work under PowerShell 7, so terminating
# (or, here, deliberately NON-terminating) behavior is asserted with try/catch.
function script:Test-Throws {
    param([scriptblock]$Action)
    try { & $Action | Out-Null; return $false } catch { return $true }
}

# The 14 columns Add-JITAuditRow has always written. Used as the regression
# guard for the 18 handlers that report no Details: their rows must keep exactly
# this shape.
$script:BaseAuditColumns = @(
    'PartitionKey','RowKey','Action','EventUtc','TargetType','ResourceName',
    'ResourceRg','SubscriptionId','RuleIdentifier','CallerIp','Port',
    'RequestedBy','ExpiryUtc','Justification'
)

function script:Get-AuditRowCallSites {
    # Every Add-JITAuditRow invocation in a function-app entry point, with the
    # Action it stamps and whether it forwards -Details. Parsed from the AST so
    # the wiring is pinned without having to stand up the whole function host.
    param([string]$RelativePath)
    $full = Join-Path $PSScriptRoot $RelativePath
    $ast  = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$null, [ref]$null)
    $cmds = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.CommandAst] -and
        $n.GetCommandName() -eq 'Add-JITAuditRow'
    }, $true)

    return @($cmds | ForEach-Object {
        $elements = $_.CommandElements
        $action   = ''
        for ($i = 0; $i -lt $elements.Count; $i++) {
            if ($elements[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and
                $elements[$i].ParameterName -eq 'Action' -and ($i + 1) -lt $elements.Count) {
                $action = $elements[$i + 1].Extent.Text.Trim("'", '"')
            }
        }
        $hasDetails = @($elements | Where-Object {
            $_ -is [System.Management.Automation.Language.CommandParameterAst] -and
            $_.ParameterName -eq 'Details'
        }).Count -gt 0

        [pscustomobject]@{
            Line       = $_.Extent.StartLineNumber
            Action     = $action
            HasDetails = $hasDetails
        }
    })
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Test-JustificationRequired' {

    # ── Fail-safe: justification REQUIRED when the policy can't be determined ───

    It 'requires justification when the tags cannot be read ($null / fail-safe)' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return $null }
        Test-JustificationRequired | Should -Be $true
    }

    It 'requires justification when the tag array is empty (opt-out tag absent)' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @() }
        Test-JustificationRequired | Should -Be $true
    }

    It 'requires justification when other tags are present but the opt-out is absent' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('Env:Prod', 'Team:Security') }
        Test-JustificationRequired | Should -Be $true
    }

    # ── Opt-out: justification NOT required when the tag is present ─────────────

    It 'does not require justification when the opt-out tag is present' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('JustificationRequired:false') }
        Test-JustificationRequired | Should -Be $false
    }

    It 'matches the opt-out tag case-insensitively' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('justificationREQUIRED:FALSE') }
        Test-JustificationRequired | Should -Be $false
    }

    It 'trims surrounding whitespace before matching the opt-out tag' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('  JustificationRequired:false  ') }
        Test-JustificationRequired | Should -Be $false
    }

    It 'finds the opt-out tag among other tags' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('Env:Prod', 'JustificationRequired:false', 'Team:Sec') }
        Test-JustificationRequired | Should -Be $false
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Add-JITAuditRow' {

    BeforeEach {
        $global:__AuditRowBodies = @()
        # Capture every non-/Tables POST body (i.e. the row insert). Get-JITAuditTableName
        # also POSTs to /Tables to ensure-exists; we ignore those.
        Mock -ModuleName JITHelpers Invoke-TableRest {
            if ($Path -ne '/Tables') { $global:__AuditRowBodies += ,$Body }
            return $null
        }
    }

    AfterEach {
        Remove-Variable -Name __AuditRowBodies -Scope Global -ErrorAction SilentlyContinue
    }

    It 'writes a row carrying the supplied Action and the JITRules fields' {
        Add-JITAuditRow -Action 'Grant' `
            -SubscriptionId 'sub-123' -TargetType 'nsg' `
            -ResourceName 'res1' -ResourceRg 'rg1' `
            -RuleIdentifier 'jit-rule-1' -CallerIp '10.0.0.9' `
            -Port '443' -RequestedBy 'alice@contoso.com' `
            -ExpiryUtc '2026-01-01T00:00:00.0000000Z' -Justification 'ticket-42'

        $global:__AuditRowBodies.Count | Should -Be 1
        $b = $global:__AuditRowBodies[0]
        $b.Action         | Should -Be 'Grant'
        $b.PartitionKey   | Should -Be 'sub-123'
        $b.SubscriptionId | Should -Be 'sub-123'
        $b.TargetType     | Should -Be 'nsg'
        $b.ResourceName   | Should -Be 'res1'
        $b.ResourceRg     | Should -Be 'rg1'
        $b.RuleIdentifier | Should -Be 'jit-rule-1'
        $b.CallerIp       | Should -Be '10.0.0.9'
        $b.Port           | Should -Be '443'
        $b.RequestedBy    | Should -Be 'alice@contoso.com'
        $b.ExpiryUtc      | Should -Be '2026-01-01T00:00:00.0000000Z'
        $b.Justification  | Should -Be 'ticket-42'
    }

    It 'stamps an EventUtc and a RowKey of the form <ISO8601>-<guid8>' {
        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x'
        $b = $global:__AuditRowBodies[0]
        $b.EventUtc | Should -Not -BeNullOrEmpty
        # RowKey = "<EventUtc>-<8 hex chars>"
        $b.RowKey   | Should -Match '^.+-[0-9a-f]{8}$'
        $b.RowKey   | Should -Match ([regex]::Escape($b.EventUtc))
    }

    It 'generates a unique RowKey per event so multiple events for one rule coexist' {
        Add-JITAuditRow -Action 'Grant'  -SubscriptionId 'sub-x' -RuleIdentifier 'same-rule'
        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x' -RuleIdentifier 'same-rule'
        $global:__AuditRowBodies.Count | Should -Be 2
        $global:__AuditRowBodies[0].RowKey | Should -Not -Be $global:__AuditRowBodies[1].RowKey
    }

    It 'defaults Justification to an empty string when none is supplied' {
        Add-JITAuditRow -Action 'Revoke' -SubscriptionId 'sub-x'
        $global:__AuditRowBodies[0].Justification | Should -Be ''
    }

    It 'merges Extra columns into the row' {
        Add-JITAuditRow -Action 'RemoveFailed' -SubscriptionId 'sub-x' `
            -Extra @{ reason = 'refused-would-open-cluster' }
        $global:__AuditRowBodies[0].reason | Should -Be 'refused-would-open-cluster'
    }

    # Confirms the helper accepts arbitrary Action strings without a ValidateSet,
    # so future event kinds need no change here.
    It 'accepts arbitrary Action strings' {
        foreach ($action in @('Grant', 'Extend', 'AlreadyExternal', 'SkippedOpen', 'Revoke', 'Expire', 'RemoveFailed')) {
            $global:__AuditRowBodies = @()
            Add-JITAuditRow -Action $action -SubscriptionId 'sub-x'
            $global:__AuditRowBodies[0].Action | Should -Be $action
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# TODO-0017 — the target-handler Details hashtable reaches the audit row.
#
# Same Invoke-TableRest body-capture harness as the Describe above (the /Tables
# ensure-exists POST is ignored; every other POST body is the row that would be
# written). Assertions are made against the entity Add-JITAuditRow hands to the
# table layer, so they pin what actually lands in JITRulesAudit.
Describe 'Add-JITAuditRow — target handler Details' {

    BeforeEach {
        $global:__AuditRowBodies = @()
        Mock -ModuleName JITHelpers Invoke-TableRest {
            if ($Path -ne '/Tables') { $global:__AuditRowBodies += ,$Body }
            return $null
        }
    }

    AfterEach {
        Remove-Variable -Name __AuditRowBodies -Scope Global -ErrorAction SilentlyContinue
    }

    # ── 1. Rich nested Details survive at full fidelity (depth 6) ───────────────

    It 'stores a rich App Service Details hashtable as JSON that round-trips' {
        $details = @{
            site                  = 'Removed'
            slotCount             = 2
            slots                 = @{ staging = 'Removed'; qa = 'Failed' }
            slotFailures          = @{ qa = '403 Forbidden' }
            slotEnumerationFailed = $true
        }
        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x' -TargetType 'appService' -Details $details

        $b = $global:__AuditRowBodies[0]
        $b.ContainsKey('Details') | Should -Be $true

        $parsed = $b.Details | ConvertFrom-Json
        $parsed.site                  | Should -Be 'Removed'
        $parsed.slotCount             | Should -Be 2
        $parsed.slotEnumerationFailed | Should -Be $true
        # The nested levels are the point: the default ConvertTo-Json depth would
        # flatten these into "System.Collections.Hashtable".
        $parsed.slots.staging         | Should -Be 'Removed'
        $parsed.slots.qa              | Should -Be 'Failed'
        $parsed.slotFailures.qa       | Should -Be '403 Forbidden'
    }

    It 'serializes to depth 6, not the ConvertTo-Json default of 2' {
        # Five levels of nesting below the root: at the default depth of 2 the
        # third level collapses to the literal string "System.Collections.Hashtable".
        $details = @{ l1 = @{ l2 = @{ l3 = @{ l4 = @{ l5 = 'leaf' } } } } }
        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x' -Details $details

        $b = $global:__AuditRowBodies[0]
        $b.Details | Should -Not -Match 'System.Collections.Hashtable'
        ($b.Details | ConvertFrom-Json).l1.l2.l3.l4.l5 | Should -Be 'leaf'
    }

    It 'stores the Details JSON compactly (no pretty-printing whitespace)' {
        Add-JITAuditRow -Action 'Revoke' -SubscriptionId 'sub-x' -Details @{ site = 'Removed' }
        $global:__AuditRowBodies[0].Details | Should -Be '{"site":"Removed"}'
    }

    # ── 2/3. Empty means absent — no "{}" on the 18 quiet handlers' rows ────────

    It 'omits the Details property entirely when Details is $null' {
        Add-JITAuditRow -Action 'Grant' -SubscriptionId 'sub-x' -Details $null
        $global:__AuditRowBodies[0].ContainsKey('Details') | Should -Be $false
    }

    It 'omits the Details property entirely when Details is an empty hashtable' {
        Add-JITAuditRow -Action 'Grant' -SubscriptionId 'sub-x' -Details @{}
        $global:__AuditRowBodies[0].ContainsKey('Details') | Should -Be $false
    }

    It 'writes neither an empty string nor "{}" for an empty Details' {
        Add-JITAuditRow -Action 'Grant' -SubscriptionId 'sub-x' -Details @{}
        $b = $global:__AuditRowBodies[0]
        # Absent, so the lookup yields $null rather than '' or '{}'.
        $b['Details'] | Should -BeNullOrEmpty
        ($b.Keys -contains 'Details') | Should -Be $false
    }

    # ── 4/5. The 8192-char cap and its truncation envelope ─────────────────────

    It 'replaces an over-cap payload with a valid truncation envelope' {
        $slots = @{}
        1..400 | ForEach-Object { $slots["slot-$('{0:d3}' -f $_)"] = "Removed-after-retry-$_" }
        $details = @{ site = 'Removed'; slots = $slots }

        # Same instance the helper serializes, so the expected length is exact.
        $expectedJson = $details | ConvertTo-Json -Compress -Depth 6
        $expectedJson.Length | Should -BeGreaterThan 8192

        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x' -Details $details

        $stored = $global:__AuditRowBodies[0].Details
        $stored | Should -Not -BeNullOrEmpty
        # Still parses as JSON — truncation never chops the string mid-token.
        $parsed = $stored | ConvertFrom-Json
        $parsed._truncated      | Should -Be $true
        $parsed._originalLength | Should -Be $expectedJson.Length
        $parsed._preview.Length | Should -Be 1024
        $parsed._preview        | Should -Be $expectedJson.Substring(0, 1024)
        # The envelope itself stays comfortably inside the cap.
        $stored.Length          | Should -BeLessThan 8192
    }

    It 'does not truncate an under-cap payload' {
        $slots = @{}
        1..20 | ForEach-Object { $slots["slot-$_"] = 'Removed' }
        $details = @{ site = 'Removed'; slots = $slots }

        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x' -Details $details

        $stored = $global:__AuditRowBodies[0].Details
        $stored.Length | Should -BeLessThan 8192
        $parsed = $stored | ConvertFrom-Json
        (@($parsed.PSObject.Properties.Name) -contains '_truncated') | Should -Be $false
        $parsed.site           | Should -Be 'Removed'
        $parsed.slots.'slot-1' | Should -Be 'Removed'
        @($parsed.slots.PSObject.Properties).Count | Should -Be 20
    }

    # ── 6. Auditing is observability, never a transaction participant ──────────
    # Own Context: Pester 3.4 tears mocks down at Describe/Context exit rather
    # than after each It, so the throwing ConvertTo-Json must be quarantined or
    # it leaks into every later test in the block.
    Context 'when Details cannot be serialized' {

        It 'still writes the row, without Details, and does not throw' {
            Mock -ModuleName JITHelpers ConvertTo-Json { throw 'serializer exploded' }

            $threw = Test-Throws {
                Add-JITAuditRow -Action 'Grant' -SubscriptionId 'sub-x' -RuleIdentifier 'rule-1' `
                    -Details @{ site = 'Removed' } -WarningAction SilentlyContinue
            }
            $threw | Should -Be $false

            $global:__AuditRowBodies.Count | Should -Be 1
            $b = $global:__AuditRowBodies[0]
            $b.ContainsKey('Details') | Should -Be $false
            # The rest of the row is intact — the grant is still auditable.
            $b.Action         | Should -Be 'Grant'
            $b.RuleIdentifier | Should -Be 'rule-1'
        }
    }

    # ── 7. Extra and Details compose (the refused-revoke row carries both) ─────

    It 'carries Extra columns and Details together without either clobbering the other' {
        Add-JITAuditRow -Action 'RemoveFailed' -SubscriptionId 'sub-x' -TargetType 'aks' `
            -Extra @{ reason = 'refused-would-open-cluster' } `
            -Details @{ site = 'Retained'; slots = @{ staging = 'Retained' } }

        $b = $global:__AuditRowBodies[0]
        $b.reason | Should -Be 'refused-would-open-cluster'
        $parsed = $b.Details | ConvertFrom-Json
        $parsed.site          | Should -Be 'Retained'
        $parsed.slots.staging | Should -Be 'Retained'
    }

    It 'does not let Extra overwrite the Details column' {
        # Details is applied after Extra, so a stray Extra key of the same name
        # loses — the handler's own Details are authoritative.
        Add-JITAuditRow -Action 'Revoke' -SubscriptionId 'sub-x' `
            -Extra @{ Details = 'from-extra' } -Details @{ site = 'Removed' }
        $global:__AuditRowBodies[0].Details | Should -Be '{"site":"Removed"}'
    }

    # ── 8. Regression guard for the 18 handlers that report no Details ─────────

    It 'writes exactly the pre-existing 14 columns when -Details is not supplied' {
        Add-JITAuditRow -Action 'Grant' -SubscriptionId 'sub-x' -TargetType 'nsg' `
            -ResourceName 'res1' -ResourceRg 'rg1' -RuleIdentifier 'jit-rule-1' `
            -CallerIp '10.0.0.9' -Port '443' -RequestedBy 'alice@contoso.com' `
            -ExpiryUtc '2026-01-01T00:00:00.0000000Z' -Justification 'ticket-42'

        $b = $global:__AuditRowBodies[0]
        $b.Keys.Count | Should -Be 14
        foreach ($col in $script:BaseAuditColumns) {
            $b.ContainsKey($col) | Should -Be $true
        }
        $b.ContainsKey('Details') | Should -Be $false
    }

    It 'produces the same row shape whether -Details is omitted or empty' {
        $rowArgs = @{
            Action = 'Grant'; SubscriptionId = 'sub-x'; TargetType = 'nsg'
            ResourceName = 'res1'; ResourceRg = 'rg1'; RuleIdentifier = 'jit-rule-1'
            CallerIp = '10.0.0.9'; Port = '443'; RequestedBy = 'alice@contoso.com'
            ExpiryUtc = '2026-01-01T00:00:00.0000000Z'; Justification = 'ticket-42'
        }
        Add-JITAuditRow @rowArgs
        Add-JITAuditRow @rowArgs -Details @{}
        Add-JITAuditRow @rowArgs -Details $null

        $global:__AuditRowBodies.Count | Should -Be 3
        $baseline = $global:__AuditRowBodies[0]
        foreach ($row in $global:__AuditRowBodies) {
            (($row.Keys | Sort-Object) -join ',') | Should -Be (($baseline.Keys | Sort-Object) -join ',')
            # Every column but the per-event identity pair is byte-identical.
            foreach ($col in $script:BaseAuditColumns) {
                if ($col -in @('RowKey', 'EventUtc')) { continue }
                $row[$col] | Should -Be $baseline[$col]
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# The internal serializer, exercised directly for the cases that are easier to
# state without a table round-trip. Not exported, so reached via InModuleScope.
Describe 'ConvertTo-JITAuditDetails' {

    It 'returns $null for $null Details' {
        InModuleScope JITHelpers { ConvertTo-JITAuditDetails -Details $null } | Should -BeNullOrEmpty
    }

    It 'returns $null for an empty hashtable' {
        InModuleScope JITHelpers { ConvertTo-JITAuditDetails -Details @{} } | Should -BeNullOrEmpty
    }

    It 'returns compact JSON for a populated hashtable' {
        InModuleScope JITHelpers {
            ConvertTo-JITAuditDetails -Details @{ site = 'Removed' }
        } | Should -Be '{"site":"Removed"}'
    }

    It 'caps the serialized output at 8192 characters' {
        $result = InModuleScope JITHelpers {
            $slots = @{}
            1..400 | ForEach-Object { $slots["slot-$('{0:d3}' -f $_)"] = "Removed-after-retry-$_" }
            ConvertTo-JITAuditDetails -Details @{ slots = $slots }
        }
        $result.Length | Should -BeLessThan 8192
        ($result | ConvertFrom-Json)._truncated | Should -Be $true
    }

    # Quarantined for the same mock-teardown reason as the Add-JITAuditRow case.
    Context 'when ConvertTo-Json fails' {

        It 'returns $null instead of throwing' {
            # ConvertTo-JITAuditDetails is a simple function (no [Parameter()]
            # attribute) so it takes no common parameters — the warning is
            # quieted by preference instead of -WarningAction.
            $result = InModuleScope JITHelpers {
                $WarningPreference = 'SilentlyContinue'
                Mock ConvertTo-Json { throw 'serializer exploded' }
                ConvertTo-JITAuditDetails -Details @{ site = 'Removed' }
            }
            $result | Should -BeNullOrEmpty
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Call-site wiring. Parsed from the entry points' ASTs rather than executed, so
# these stay meaningful independently of the function-host harnesses.
Describe 'Add-JITAuditRow Details wiring at the call sites' {

    # Six call sites: the four normal outcomes, plus the two on the
    # compensating-remove path taken when the JITRules row cannot be written
    # (GrantRolledBack = the rule was undone, OrphanedGrant = it could not be
    # and a human must remove it). All six carry Details.
    It 'forwards Details on all six Request-JITAccess audit rows' {
        $calls = Get-AuditRowCallSites '../Request-JITAccess/run.ps1'
        $calls.Count | Should -Be 6
        (($calls.Action | Sort-Object) -join ',') | Should -Be 'AlreadyExternal,Extend,Grant,GrantRolledBack,OrphanedGrant,SkippedOpen'
        @($calls | Where-Object { -not $_.HasDetails }).Count | Should -Be 0
    }

    It 'forwards Details on both Revoke-JITAccess audit rows' {
        $calls = Get-AuditRowCallSites '../Revoke-JITAccess/run.ps1'
        $calls.Count | Should -Be 2
        (($calls.Action | Sort-Object) -join ',') | Should -Be 'RemoveFailed,Revoke'
        @($calls | Where-Object { -not $_.HasDetails }).Count | Should -Be 0
    }

    # The outer catch runs when the remove handler THREW, so there is no result
    # to describe and $removeResult still holds the PREVIOUS loop iteration's
    # value — forwarding it would attribute one resource's slot state to another.
    # The omission is deliberate; this pins it.
    It 'omits Details on the Remove-ExpiredRules outer-catch RemoveFailed row only' {
        $calls = Get-AuditRowCallSites '../Remove-ExpiredRules/run.ps1'
        $calls.Count | Should -Be 3

        $without = @($calls | Where-Object { -not $_.HasDetails })
        $without.Count     | Should -Be 1
        $without[0].Action | Should -Be 'RemoveFailed'
        # It is the last of the three — the per-resource outer catch, not the
        # in-loop Refused/Expire rows, both of which do carry Details.
        $without[0].Line   | Should -Be ($calls.Line | Measure-Object -Maximum).Maximum

        $with = @($calls | Where-Object { $_.HasDetails })
        (($with.Action | Sort-Object) -join ',') | Should -Be 'Expire,RemoveFailed'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Update-JITTableRow' {

    BeforeEach {
        $global:__MergeCall = $null
        Mock -ModuleName JITHelpers Invoke-TableRest {
            $global:__MergeCall = @{ Method = $Method; Path = $Path; Body = $Body; ExtraHeaders = $ExtraHeaders }
            return $null
        }
    }

    AfterEach {
        Remove-Variable -Name __MergeCall -Scope Global -ErrorAction SilentlyContinue
    }

    It 'issues a MERGE keyed by PartitionKey and RowKey' {
        Update-JITTableRow -TableName 'JITRules' -PartitionKey 'sub-1' -RowKey 'jit-abc' `
            -Properties @{ ExpiryUtc = '2026-02-02T00:00:00.0000000Z' }
        $global:__MergeCall               | Should -Not -BeNullOrEmpty
        $global:__MergeCall.Method        | Should -Be 'MERGE'
        $global:__MergeCall.Path          | Should -Be "/JITRules(PartitionKey='sub-1',RowKey='jit-abc')"
    }

    It 'carries the supplied properties plus the keys in the MERGE body' {
        Update-JITTableRow -TableName 'JITRules' -PartitionKey 'sub-1' -RowKey 'jit-abc' `
            -Properties @{ ExpiryUtc = '2026-02-02T00:00:00.0000000Z' }
        $global:__MergeCall.Body.ExpiryUtc    | Should -Be '2026-02-02T00:00:00.0000000Z'
        $global:__MergeCall.Body.PartitionKey | Should -Be 'sub-1'
        $global:__MergeCall.Body.RowKey       | Should -Be 'jit-abc'
    }

    It 'sends an unconditional If-Match (*) header (last-writer-wins refresh)' {
        Update-JITTableRow -TableName 'JITRules' -PartitionKey 'sub-1' -RowKey 'jit-abc' `
            -Properties @{ ExpiryUtc = 'x' }
        $global:__MergeCall.ExtraHeaders['If-Match'] | Should -Be '*'
    }

    It 'URL-encodes reserved characters in the partition and row keys' {
        Update-JITTableRow -TableName 'JITRules' -PartitionKey 'a b' -RowKey "o'brien" `
            -Properties @{ ExpiryUtc = 'x' }
        # [Uri]::EscapeDataString: space -> %20, apostrophe -> %27
        $global:__MergeCall.Path | Should -Be "/JITRules(PartitionKey='a%20b',RowKey='o%27brien')"
    }
}
