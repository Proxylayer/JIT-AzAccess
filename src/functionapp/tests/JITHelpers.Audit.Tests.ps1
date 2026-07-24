# Tests for the justification-policy and audit-history helpers in JITHelpers.psm1
# (FEAT-0003, items 2 & 6):
#   • Test-JustificationRequired — server-authoritative opt-out via the AzureTray
#     app-reg tag `JustificationRequired:false` (fail-safe: required when unknown).
#   • Add-JITAuditRow            — appends one row per lifecycle event to the
#     JITRulesAudit history table (unique RowKey, arbitrary Action strings).
#   • Update-JITTableRow         — MERGE (partial update) keyed by PK+RK, used to
#     refresh a JITRules row's ExpiryUtc on the extend path.
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

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Test-JustificationRequired' {

    # ── Fail-safe: justification REQUIRED when the policy can't be determined ───

    It 'requires justification when the tags cannot be read ($null / fail-safe)' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return $null }
        Test-JustificationRequired | Should Be $true
    }

    It 'requires justification when the tag array is empty (opt-out tag absent)' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @() }
        Test-JustificationRequired | Should Be $true
    }

    It 'requires justification when other tags are present but the opt-out is absent' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('Env:Prod', 'Team:Security') }
        Test-JustificationRequired | Should Be $true
    }

    # ── Opt-out: justification NOT required when the tag is present ─────────────

    It 'does not require justification when the opt-out tag is present' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('JustificationRequired:false') }
        Test-JustificationRequired | Should Be $false
    }

    It 'matches the opt-out tag case-insensitively' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('justificationREQUIRED:FALSE') }
        Test-JustificationRequired | Should Be $false
    }

    It 'trims surrounding whitespace before matching the opt-out tag' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('  JustificationRequired:false  ') }
        Test-JustificationRequired | Should Be $false
    }

    It 'finds the opt-out tag among other tags' {
        Mock -ModuleName JITHelpers Get-AzureTrayAppRegTags { return @('Env:Prod', 'JustificationRequired:false', 'Team:Sec') }
        Test-JustificationRequired | Should Be $false
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

        $global:__AuditRowBodies.Count | Should Be 1
        $b = $global:__AuditRowBodies[0]
        $b.Action         | Should Be 'Grant'
        $b.PartitionKey   | Should Be 'sub-123'
        $b.SubscriptionId | Should Be 'sub-123'
        $b.TargetType     | Should Be 'nsg'
        $b.ResourceName   | Should Be 'res1'
        $b.ResourceRg     | Should Be 'rg1'
        $b.RuleIdentifier | Should Be 'jit-rule-1'
        $b.CallerIp       | Should Be '10.0.0.9'
        $b.Port           | Should Be '443'
        $b.RequestedBy    | Should Be 'alice@contoso.com'
        $b.ExpiryUtc      | Should Be '2026-01-01T00:00:00.0000000Z'
        $b.Justification  | Should Be 'ticket-42'
    }

    It 'stamps an EventUtc and a RowKey of the form <ISO8601>-<guid8>' {
        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x'
        $b = $global:__AuditRowBodies[0]
        $b.EventUtc | Should Not BeNullOrEmpty
        # RowKey = "<EventUtc>-<8 hex chars>"
        $b.RowKey   | Should Match '^.+-[0-9a-f]{8}$'
        $b.RowKey   | Should Match ([regex]::Escape($b.EventUtc))
    }

    It 'generates a unique RowKey per event so multiple events for one rule coexist' {
        Add-JITAuditRow -Action 'Grant'  -SubscriptionId 'sub-x' -RuleIdentifier 'same-rule'
        Add-JITAuditRow -Action 'Expire' -SubscriptionId 'sub-x' -RuleIdentifier 'same-rule'
        $global:__AuditRowBodies.Count | Should Be 2
        $global:__AuditRowBodies[0].RowKey | Should Not Be $global:__AuditRowBodies[1].RowKey
    }

    It 'defaults Justification to an empty string when none is supplied' {
        Add-JITAuditRow -Action 'Revoke' -SubscriptionId 'sub-x'
        $global:__AuditRowBodies[0].Justification | Should Be ''
    }

    It 'merges Extra columns into the row' {
        Add-JITAuditRow -Action 'RemoveFailed' -SubscriptionId 'sub-x' `
            -Extra @{ reason = 'refused-would-open-cluster' }
        $global:__AuditRowBodies[0].reason | Should Be 'refused-would-open-cluster'
    }

    # Confirms the helper accepts arbitrary Action strings without a ValidateSet,
    # so future event kinds need no change here.
    It 'accepts arbitrary Action strings' {
        foreach ($action in @('Grant', 'Extend', 'AlreadyExternal', 'SkippedOpen', 'Revoke', 'Expire', 'RemoveFailed')) {
            $global:__AuditRowBodies = @()
            Add-JITAuditRow -Action $action -SubscriptionId 'sub-x'
            $global:__AuditRowBodies[0].Action | Should Be $action
        }
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
        $global:__MergeCall               | Should Not BeNullOrEmpty
        $global:__MergeCall.Method        | Should Be 'MERGE'
        $global:__MergeCall.Path          | Should Be "/JITRules(PartitionKey='sub-1',RowKey='jit-abc')"
    }

    It 'carries the supplied properties plus the keys in the MERGE body' {
        Update-JITTableRow -TableName 'JITRules' -PartitionKey 'sub-1' -RowKey 'jit-abc' `
            -Properties @{ ExpiryUtc = '2026-02-02T00:00:00.0000000Z' }
        $global:__MergeCall.Body.ExpiryUtc    | Should Be '2026-02-02T00:00:00.0000000Z'
        $global:__MergeCall.Body.PartitionKey | Should Be 'sub-1'
        $global:__MergeCall.Body.RowKey       | Should Be 'jit-abc'
    }

    It 'sends an unconditional If-Match (*) header (last-writer-wins refresh)' {
        Update-JITTableRow -TableName 'JITRules' -PartitionKey 'sub-1' -RowKey 'jit-abc' `
            -Properties @{ ExpiryUtc = 'x' }
        $global:__MergeCall.ExtraHeaders['If-Match'] | Should Be '*'
    }

    It 'URL-encodes reserved characters in the partition and row keys' {
        Update-JITTableRow -TableName 'JITRules' -PartitionKey 'a b' -RowKey "o'brien" `
            -Properties @{ ExpiryUtc = 'x' }
        # [Uri]::EscapeDataString: space -> %20, apostrophe -> %27
        $global:__MergeCall.Path | Should Be "/JITRules(PartitionKey='a%20b',RowKey='o%27brien')"
    }
}
