# Tests for Remove-ExpiredRules/run.ps1 and Remove-JITNsgRule
#
# Covers:
#   • Timer trigger dispatches to the correct Remove-* function per targetType
#   • Expired NSG rules are removed; active rules are left alone
#   • Table record is deleted only after a successful resource removal
#   • Failed removal leaves the table record so it retries on the next tick
#   • Correct audit events are written (JITExpired / JITRemoveFailed)
#   • Remove-JITNsgRule calls the Azure SDK correctly and is idempotent
#
# Pester 3.4.0 compatible — Assert-MockCalled uses -Scope It to prevent
# mock call counts from accumulating across It blocks in the same Describe.
#
# Run:  Invoke-Pester ./src/functionapp/tests/Remove-ExpiredRules.Tests.ps1

Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1" -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1" -Force

# ── Azure cmdlet stubs ────────────────────────────────────────────────────────
# Pester 3 can only mock commands that already exist in the session.
# The Az cmdlets below are not loaded in the test environment, so we declare
# lightweight stubs here that the Mocks in BeforeEach will replace at runtime.
if (-not (Get-Command Get-AzTableRow              -ErrorAction SilentlyContinue)) { function global:Get-AzTableRow              { } }
if (-not (Get-Command Remove-AzTableRow           -ErrorAction SilentlyContinue)) { function global:Remove-AzTableRow           { } }
if (-not (Get-Command Set-AzContext               -ErrorAction SilentlyContinue)) { function global:Set-AzContext               { } }
if (-not (Get-Command Get-AzNetworkSecurityGroup  -ErrorAction SilentlyContinue)) { function global:Get-AzNetworkSecurityGroup  { } }

# These two stubs are ALWAYS redefined (without the -not check) because the real
# Az cmdlets have strongly-typed [PSNetworkSecurityGroup] pipeline parameters that
# reject PSCustomObject mocks.  Untyped stubs let Pester intercept pipeline calls.
function global:Remove-AzNetworkSecurityRuleConfig {
    [CmdletBinding()] param(
        [Parameter(ValueFromPipeline=$true)] $NetworkSecurityGroup,
        [string]$Name, [string]$ErrorAction
    )
    process { return $NetworkSecurityGroup }
}
function global:Set-AzNetworkSecurityGroup {
    [CmdletBinding()] param(
        [Parameter(ValueFromPipeline=$true)] $NetworkSecurityGroup
    )
    process { return $NetworkSecurityGroup }
}

$script:RunScript = "$PSScriptRoot/../Remove-ExpiredRules/run.ps1"

function script:New-ExpiredRow {
    param([string]$TargetType = 'nsg', [string]$RuleId = 'jit-test-rule')
    [PSCustomObject]@{
        PartitionKey   = $TargetType
        RowKey         = $RuleId
        TargetType     = $TargetType
        RuleIdentifier = $RuleId
        ResourceName   = 'test-resource'
        ResourceRg     = 'test-rg'
        SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        CallerIp       = '10.0.0.1'
        RequestedBy    = 'tester@contoso.com'
        ExpiryUtc      = ([DateTime]::UtcNow.AddHours(-1)).ToString('o')
    }
}

function script:New-ActiveRow {
    param([string]$TargetType = 'nsg', [string]$RuleId = 'jit-active-rule')
    $row = New-ExpiredRow -TargetType $TargetType -RuleId $RuleId
    $row.ExpiryUtc = ([DateTime]::UtcNow.AddHours(2)).ToString('o')
    return $row
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Remove-ExpiredRules timer trigger' {

    BeforeEach {
        $script:MockTable = [PSCustomObject]@{ Name = 'JITRules' }

        # Suppress the run.ps1's own Import-Module calls
        Mock Import-Module { }

        Mock Get-JITCloudTable             { return $script:MockTable }
        Mock Get-AzTableRow                { return @() }
        Mock Remove-JITNsgRule             { }
        Mock Remove-JITSqlFirewallRule     { }
        Mock Remove-JITStorageNetworkRule  { }
        Mock Remove-JITKeyVaultNetworkRule { }
        Mock Remove-AzTableRow             { }
        Mock Write-JITAuditEvent           { }

        $Timer = [PSCustomObject]@{ IsPastDue = $false }
    }

    # ── Happy path — NSG ──────────────────────────────────────────────────────

    It 'calls Remove-JITNsgRule for an expired NSG rule' {
        Mock Get-AzTableRow { return @(New-ExpiredRow -TargetType 'nsg') }
        . $script:RunScript
        Assert-MockCalled Remove-JITNsgRule -Times 1 -Scope It
    }

    It 'deletes the table record after a successful NSG removal' {
        Mock Get-AzTableRow { return @(New-ExpiredRow -TargetType 'nsg') }
        . $script:RunScript
        Assert-MockCalled Remove-AzTableRow -Times 1 -Scope It
    }

    It 'writes a JITExpired audit event on successful NSG removal' {
        Mock Get-AzTableRow { return @(New-ExpiredRow -TargetType 'nsg') }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITExpired'
        }
    }

    # ── Failure path — retry semantics ────────────────────────────────────────

    It 'does NOT delete the table record when NSG removal throws' {
        Mock Get-AzTableRow    { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { throw 'ARM API error' }
        . $script:RunScript
        Assert-MockCalled Remove-AzTableRow -Exactly -Times 0 -Scope It
    }

    It 'writes a JITRemoveFailed audit event when NSG removal throws' {
        Mock Get-AzTableRow    { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { throw 'ARM API error' }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITRemoveFailed'
        }
    }

    # ── Active rules are left alone ───────────────────────────────────────────

    It 'does not remove a rule that has not yet expired' {
        Mock Get-AzTableRow { return @(New-ActiveRow -TargetType 'nsg') }
        . $script:RunScript
        Assert-MockCalled Remove-JITNsgRule -Exactly -Times 0 -Scope It
        Assert-MockCalled Remove-AzTableRow -Exactly -Times 0 -Scope It
    }

    It 'processes only the expired subset when active and expired rows are mixed' {
        Mock Get-AzTableRow {
            return @(
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'expired-1'),
                (New-ActiveRow  -TargetType 'nsg' -RuleId 'active-1'),
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'expired-2')
            )
        }
        . $script:RunScript
        Assert-MockCalled Remove-JITNsgRule -Exactly -Times 2 -Scope It
        Assert-MockCalled Remove-AzTableRow -Exactly -Times 2 -Scope It
    }

    # ── Multiple expired rows ─────────────────────────────────────────────────

    It 'removes all expired NSG rules in one run' {
        Mock Get-AzTableRow {
            return @(
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'expired-1'),
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'expired-2'),
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'expired-3')
            )
        }
        . $script:RunScript
        Assert-MockCalled Remove-JITNsgRule -Exactly -Times 3 -Scope It
        Assert-MockCalled Remove-AzTableRow -Exactly -Times 3 -Scope It
    }

    It 'continues processing remaining rules when one removal fails' {
        Mock Get-AzTableRow {
            return @(
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'fail-rule'),
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'pass-rule')
            )
        }
        $script:NsgCallNum = 0
        Mock Remove-JITNsgRule {
            $script:NsgCallNum++
            if ($script:NsgCallNum -eq 1) { throw 'First call fails' }
        }
        . $script:RunScript
        Assert-MockCalled Remove-JITNsgRule -Exactly -Times 2 -Scope It
        Assert-MockCalled Remove-AzTableRow -Exactly -Times 1 -Scope It
    }

    # ── Other target types dispatched correctly ───────────────────────────────

    It 'calls Remove-JITSqlFirewallRule for an expired sqlServer rule' {
        Mock Get-AzTableRow { return @(New-ExpiredRow -TargetType 'sqlServer') }
        . $script:RunScript
        Assert-MockCalled Remove-JITSqlFirewallRule -Times 1 -Scope It
        Assert-MockCalled Remove-JITNsgRule         -Exactly -Times 0 -Scope It
    }

    It 'calls Remove-JITStorageNetworkRule for an expired storageAccount rule' {
        Mock Get-AzTableRow { return @(New-ExpiredRow -TargetType 'storageAccount') }
        . $script:RunScript
        Assert-MockCalled Remove-JITStorageNetworkRule -Times 1 -Scope It
        Assert-MockCalled Remove-JITNsgRule            -Exactly -Times 0 -Scope It
    }

    It 'calls Remove-JITKeyVaultNetworkRule for an expired keyVault rule' {
        Mock Get-AzTableRow { return @(New-ExpiredRow -TargetType 'keyVault') }
        . $script:RunScript
        Assert-MockCalled Remove-JITKeyVaultNetworkRule -Times 1 -Scope It
        Assert-MockCalled Remove-JITNsgRule             -Exactly -Times 0 -Scope It
    }

    # ── Edge cases ────────────────────────────────────────────────────────────

    It 'does nothing and does not throw when the table is empty' {
        Mock Get-AzTableRow { return @() }
        { . $script:RunScript } | Should Not Throw
        Assert-MockCalled Remove-JITNsgRule -Exactly -Times 0 -Scope It
    }

    It 'deletes the table record for an unknown targetType (stale record cleanup)' {
        Mock Get-AzTableRow { return @(New-ExpiredRow -TargetType 'unknownType') }
        . $script:RunScript
        Assert-MockCalled Remove-AzTableRow -Times 1 -Scope It
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# The Remove-JITNsgRule tests call the real function inside the JITTargets module.
# Mocks must use -ModuleName JITTargets so they intercept calls made from within
# the module's scope.  Closures (.GetNewClosure()) are used to pass PSCustomObject
# return values across the module scope boundary.
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Remove-JITNsgRule' {

    BeforeEach {
        $script:ExistingRule = [PSCustomObject]@{ Name = 'jit-test-rule'; Direction = 'Inbound' }
        $script:NsgWithRule  = [PSCustomObject]@{ SecurityRules = @($script:ExistingRule) }
        $script:NsgEmpty     = [PSCustomObject]@{ SecurityRules = @() }

        # Capture for use in closures (module scope can't see $script: from test)
        $nsgWithRule = $script:NsgWithRule

        Mock -ModuleName JITTargets Set-AzContext               { }
        Mock -ModuleName JITTargets Get-AzNetworkSecurityGroup  { return $nsgWithRule }.GetNewClosure()
        Mock -ModuleName JITTargets Remove-AzNetworkSecurityRuleConfig { return $nsgWithRule }.GetNewClosure()
        Mock -ModuleName JITTargets Set-AzNetworkSecurityGroup  { }

        $script:Row = [PSCustomObject]@{
            SubscriptionId = 'sub-id'
            ResourceName   = 'test-nsg'
            ResourceRg     = 'test-rg'
            RuleIdentifier = 'jit-test-rule'
        }
    }

    It 'removes the security rule when it exists on the NSG' {
        Remove-JITNsgRule -Row $script:Row
        Assert-MockCalled -ModuleName JITTargets Remove-AzNetworkSecurityRuleConfig -Times 1 -Scope It -ParameterFilter {
            $Name -eq 'jit-test-rule'
        }
    }

    It 'calls Set-AzNetworkSecurityGroup to commit the change' {
        Remove-JITNsgRule -Row $script:Row
        Assert-MockCalled -ModuleName JITTargets Set-AzNetworkSecurityGroup -Times 1 -Scope It
    }

    It 'sets the correct subscription context before making ARM calls' {
        Remove-JITNsgRule -Row $script:Row
        Assert-MockCalled -ModuleName JITTargets Set-AzContext -Times 1 -Scope It
    }

    It 'does not throw when the rule is already absent (idempotent)' {
        $emptyNsg = $script:NsgEmpty
        Mock -ModuleName JITTargets Get-AzNetworkSecurityGroup { return $emptyNsg }.GetNewClosure()
        { Remove-JITNsgRule -Row $script:Row } | Should Not Throw
    }

    It 'does not call Remove-AzNetworkSecurityRuleConfig when rule is already absent' {
        $emptyNsg = $script:NsgEmpty
        Mock -ModuleName JITTargets Get-AzNetworkSecurityGroup { return $emptyNsg }.GetNewClosure()
        Remove-JITNsgRule -Row $script:Row
        Assert-MockCalled -ModuleName JITTargets Remove-AzNetworkSecurityRuleConfig -Exactly -Times 0 -Scope It
    }

    It 'does not call Set-AzNetworkSecurityGroup when no change was needed' {
        $emptyNsg = $script:NsgEmpty
        Mock -ModuleName JITTargets Get-AzNetworkSecurityGroup { return $emptyNsg }.GetNewClosure()
        Remove-JITNsgRule -Row $script:Row
        Assert-MockCalled -ModuleName JITTargets Set-AzNetworkSecurityGroup -Exactly -Times 0 -Scope It
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# postgresqlFlexibleServer dispatch (FEAT-0001)
#
# These tests target the CURRENT run.ps1 data path, which reads/writes the rules
# table via Get-JITTableName / Get-JITTableRows / Remove-JITTableRow (all backed
# by Invoke-TableRest) — NOT the Az.Table cmdlets. They deliberately mock those
# current helpers plus the JITTargets remove-handlers and Write-JITAuditEvent, so
# no network or Az.* dependency is exercised. (The neighbouring "Remove-ExpiredRules
# timer trigger" Describe still mocks the removed Get-JITCloudTable/Get-AzTableRow
# commands and is stale — that is tracked separately as TODO-0006 and left untouched.)
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Remove-ExpiredRules postgresqlFlexibleServer dispatch' {

    BeforeEach {
        # Suppress run.ps1's own Import-Module calls; the real modules are already
        # imported at the top of this file, so the functions below exist to be mocked.
        Mock Import-Module { }

        # Mock the ACTUAL table-access helpers run.ps1 calls (Invoke-TableRest-backed),
        # so nothing touches storage. Get-JITTableRows is overridden per test.
        Mock Get-JITTableName  { return 'JITRules' }
        Mock Get-JITTableRows  { return @() }
        Mock Remove-JITTableRow { }
        Mock Write-JITAuditEvent { }

        # Mock every dispatch handler so we can assert exactly which one fires.
        Mock Remove-JITPostgresFirewallRule { }
        Mock Remove-JITNsgRule              { }
        Mock Remove-JITSqlFirewallRule      { }
        Mock Remove-JITStorageNetworkRule   { }
        Mock Remove-JITKeyVaultNetworkRule  { }

        $Timer = [PSCustomObject]@{ IsPastDue = $false }
    }

    # ── Happy path ────────────────────────────────────────────────────────────

    It 'calls Remove-JITPostgresFirewallRule exactly once for an expired postgresqlFlexibleServer rule' {
        Mock Get-JITTableRows { return @(New-ExpiredRow -TargetType 'postgresqlFlexibleServer') }
        . $script:RunScript
        Assert-MockCalled Remove-JITPostgresFirewallRule -Exactly -Times 1 -Scope It
    }

    It 'does not invoke other remove handlers for a postgresqlFlexibleServer rule' {
        Mock Get-JITTableRows { return @(New-ExpiredRow -TargetType 'postgresqlFlexibleServer') }
        . $script:RunScript
        Assert-MockCalled Remove-JITNsgRule             -Exactly -Times 0 -Scope It
        Assert-MockCalled Remove-JITSqlFirewallRule     -Exactly -Times 0 -Scope It
        Assert-MockCalled Remove-JITStorageNetworkRule  -Exactly -Times 0 -Scope It
        Assert-MockCalled Remove-JITKeyVaultNetworkRule -Exactly -Times 0 -Scope It
    }

    It 'deletes the table row after a successful postgresqlFlexibleServer removal' {
        Mock Get-JITTableRows { return @(New-ExpiredRow -TargetType 'postgresqlFlexibleServer') }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 1 -Scope It
    }

    It 'writes a JITExpired audit event on successful postgresqlFlexibleServer removal' {
        Mock Get-JITTableRows { return @(New-ExpiredRow -TargetType 'postgresqlFlexibleServer') }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITExpired'
        }
    }

    # ── Failure path — row preserved for retry ────────────────────────────────

    It 'does NOT delete the table row when Remove-JITPostgresFirewallRule throws' {
        Mock Get-JITTableRows               { return @(New-ExpiredRow -TargetType 'postgresqlFlexibleServer') }
        Mock Remove-JITPostgresFirewallRule { throw 'ARM async operation failed' }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 0 -Scope It
    }

    It 'writes a JITRemoveFailed audit event when Remove-JITPostgresFirewallRule throws' {
        Mock Get-JITTableRows               { return @(New-ExpiredRow -TargetType 'postgresqlFlexibleServer') }
        Mock Remove-JITPostgresFirewallRule { throw 'ARM async operation failed' }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITRemoveFailed'
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# New target-type dispatch (FEAT-0002)
#
# Same CURRENT data path as the postgres dispatch Describe above: run.ps1 reads
# and writes the rules table via Get-JITTableName / Get-JITTableRows /
# Remove-JITTableRow (Invoke-TableRest-backed) and audits via Write-JITAuditEvent
# — all mocked here so nothing touches storage or the network. Every one of the
# 19 Remove-JIT*Rule handlers is mocked so each It can assert that EXACTLY the
# expected handler fired for its targetType and that no other handler was called.
#
# The per-type happy-path assertions are data-driven over the 14 new tokens
# (Pester-3.4-safe: the foreach runs the It blocks inline). A representative
# failure-path pair is exercised for one child type (mysqlFlexibleServer) and
# one array-on-resource type (cosmosDb).
# ─────────────────────────────────────────────────────────────────────────────

# targetType -> its own Remove-JIT*Rule handler (mirrors run.ps1's dispatch switch)
$script:NewDispatchCases = @(
    @{ Type = 'mysqlFlexibleServer'; Handler = 'Remove-JITMysqlFlexibleServerRule' }
    @{ Type = 'redis';               Handler = 'Remove-JITRedisRule' }
    @{ Type = 'synapse';             Handler = 'Remove-JITSynapseRule' }
    @{ Type = 'cosmosDb';            Handler = 'Remove-JITCosmosDbRule' }
    @{ Type = 'containerRegistry';   Handler = 'Remove-JITContainerRegistryRule' }
    @{ Type = 'aiSearch';            Handler = 'Remove-JITAiSearchRule' }
    @{ Type = 'cognitiveServices';   Handler = 'Remove-JITCognitiveServicesRule' }
    @{ Type = 'kusto';               Handler = 'Remove-JITKustoRule' }
    @{ Type = 'iotHub';              Handler = 'Remove-JITIotHubRule' }
    @{ Type = 'signalR';             Handler = 'Remove-JITSignalRRule' }
    @{ Type = 'eventHub';            Handler = 'Remove-JITEventHubRule' }
    @{ Type = 'serviceBus';          Handler = 'Remove-JITServiceBusRule' }
    @{ Type = 'appService';          Handler = 'Remove-JITAppServiceRule' }
    @{ Type = 'aks';                 Handler = 'Remove-JITAksRule' }
)

# Every remove handler run.ps1 can dispatch to (5 original + 14 new). Used both to
# mock them all and to assert non-target handlers stay untouched.
$script:AllRemoveHandlers = @(
    'Remove-JITNsgRule'
    'Remove-JITSqlFirewallRule'
    'Remove-JITPostgresFirewallRule'
    'Remove-JITStorageNetworkRule'
    'Remove-JITKeyVaultNetworkRule'
) + ($script:NewDispatchCases | ForEach-Object { $_.Handler })

Describe 'Remove-ExpiredRules new target-type dispatch (FEAT-0002)' {

    BeforeEach {
        # Suppress run.ps1's own Import-Module calls; real modules already imported.
        Mock Import-Module { }

        # CURRENT table-access helpers (Invoke-TableRest-backed) — nothing hits storage.
        Mock Get-JITTableName   { return 'JITRules' }
        Mock Get-JITTableRows   { return @() }
        Mock Remove-JITTableRow { }
        Mock Write-JITAuditEvent { }

        # Mock every dispatch handler so we can assert exactly which one fires.
        foreach ($h in $script:AllRemoveHandlers) { Mock $h { } }

        $Timer = [PSCustomObject]@{ IsPastDue = $false }
    }

    # ── Happy path — one It per new token, data-driven ─────────────────────────

    foreach ($case in $script:NewDispatchCases) {
        $caseType    = $case.Type
        $caseHandler = $case.Handler

        It "routes an expired $caseType row to $caseHandler exactly once and to no other handler" {
            $script:DispatchType    = $caseType
            $script:DispatchHandler = $caseHandler
            Mock Get-JITTableRows { return @(New-ExpiredRow -TargetType $script:DispatchType) }

            . $script:RunScript

            Assert-MockCalled $script:DispatchHandler -Exactly -Times 1 -Scope It
            foreach ($other in $script:AllRemoveHandlers) {
                if ($other -ne $script:DispatchHandler) {
                    Assert-MockCalled $other -Exactly -Times 0 -Scope It
                }
            }
        }

        It "deletes the table row and writes JITExpired after a successful $caseType removal" {
            $script:DispatchType = $caseType
            Mock Get-JITTableRows { return @(New-ExpiredRow -TargetType $script:DispatchType) }

            . $script:RunScript

            Assert-MockCalled Remove-JITTableRow -Exactly -Times 1 -Scope It
            Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
                $EventType -eq 'JITExpired'
            }
        }
    }

    # ── Failure path — child type (mysqlFlexibleServer) ────────────────────────

    It 'preserves the table row when a child-type handler throws (mysqlFlexibleServer)' {
        Mock Get-JITTableRows                    { return @(New-ExpiredRow -TargetType 'mysqlFlexibleServer') }
        Mock Remove-JITMysqlFlexibleServerRule   { throw 'ARM firewall-rule delete failed' }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 0 -Scope It
    }

    It 'writes a JITRemoveFailed audit event when a child-type handler throws (mysqlFlexibleServer)' {
        Mock Get-JITTableRows                    { return @(New-ExpiredRow -TargetType 'mysqlFlexibleServer') }
        Mock Remove-JITMysqlFlexibleServerRule   { throw 'ARM firewall-rule delete failed' }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITRemoveFailed'
        }
    }

    # ── Failure path — array-on-resource type (cosmosDb) ───────────────────────

    It 'preserves the table row when an array-type handler throws (cosmosDb)' {
        Mock Get-JITTableRows      { return @(New-ExpiredRow -TargetType 'cosmosDb') }
        Mock Remove-JITCosmosDbRule { throw 'ARM read-modify-write did not converge' }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 0 -Scope It
    }

    It 'writes a JITRemoveFailed audit event when an array-type handler throws (cosmosDb)' {
        Mock Get-JITTableRows      { return @(New-ExpiredRow -TargetType 'cosmosDb') }
        Mock Remove-JITCosmosDbRule { throw 'ARM read-modify-write did not converge' }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITRemoveFailed'
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Remove-status branching (FEAT-0003, item 5)
#
# The remove handlers now return @{ Status = 'Removed' | 'NotFound' | 'Refused' }
# and run.ps1 branches on it (see Remove-ExpiredRules/run.ps1 region 5):
#   • Removed  -> JITExpired audit, Add-JITAuditRow 'Expire', table row DELETED.
#   • NotFound -> same as Removed (rule already gone from the resource): the
#                 JITRules row is still deleted and an Expire audit is written
#                 (with notFound=$true). This is the "user deleted it manually"
#                 cleanup path.
#   • Refused  -> AKS-only safety refusal (removing the IP would open the API
#                 server). The row is NOT deleted (so it stays tracked/retried)
#                 and a RemoveFailed audit is written (Write-JITAuditEvent +
#                 Add-JITAuditRow 'RemoveFailed'); the timer keeps processing.
#   • $null / no Status -> treated as Removed (legacy handlers) — kept working.
#
# Same CURRENT data path as the dispatch Describes above (Get-JITTableName /
# Get-JITTableRows / Remove-JITTableRow, all Invoke-TableRest-backed, mocked).
# Add-JITAuditRow is ALSO mocked here (the earlier Describes leave it real, where
# it fails harmlessly inside run.ps1's try/catch) so we can assert the exact
# JITRulesAudit Action written per branch without touching storage.
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Remove-ExpiredRules remove-status branching (FEAT-0003)' {

    BeforeEach {
        Mock Import-Module { }

        Mock Get-JITTableName   { return 'JITRules' }
        Mock Get-JITTableRows   { return @() }
        Mock Remove-JITTableRow { }
        Mock Write-JITAuditEvent { }
        Mock Add-JITAuditRow    { }

        # Only the two handlers exercised here need mocking; each It overrides the
        # relevant one to return a specific Status.
        Mock Remove-JITNsgRule { }
        Mock Remove-JITAksRule { }

        $Timer = [PSCustomObject]@{ IsPastDue = $false }
    }

    # ── Status = 'NotFound' — clean up the stale row, still audit an Expire ─────

    It "deletes the JITRules row when the handler returns Status='NotFound'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { return @{ Status = 'NotFound' } }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 1 -Scope It
    }

    It "writes an Expire JITRulesAudit row when the handler returns Status='NotFound'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { return @{ Status = 'NotFound' } }
        . $script:RunScript
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'Expire' }
    }

    It "writes a JITExpired audit event when the handler returns Status='NotFound'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { return @{ Status = 'NotFound' } }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter { $EventType -eq 'JITExpired' }
    }

    # ── Status = 'Refused' (aks) — keep the row, audit a RemoveFailed ───────────

    It "does NOT delete the JITRules row when an aks handler returns Status='Refused'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'aks') }
        Mock Remove-JITAksRule { return @{ Status = 'Refused' } }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 0 -Scope It
    }

    It "writes a RemoveFailed JITRulesAudit row when an aks handler returns Status='Refused'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'aks') }
        Mock Remove-JITAksRule { return @{ Status = 'Refused' } }
        . $script:RunScript
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'RemoveFailed' }
    }

    It "writes a JITRemoveFailed audit event when an aks handler returns Status='Refused'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'aks') }
        Mock Remove-JITAksRule { return @{ Status = 'Refused' } }
        . $script:RunScript
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter { $EventType -eq 'JITRemoveFailed' }
    }

    It "does NOT write an Expire audit row for a refused aks removal" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'aks') }
        Mock Remove-JITAksRule { return @{ Status = 'Refused' } }
        . $script:RunScript
        Assert-MockCalled Add-JITAuditRow -Exactly -Times 0 -Scope It -ParameterFilter { $Action -eq 'Expire' }
    }

    It 'continues processing later rows after a refused aks removal (does not throw / stop)' {
        Mock Get-JITTableRows {
            return @(
                (New-ExpiredRow -TargetType 'aks' -RuleId 'refused-aks'),
                (New-ExpiredRow -TargetType 'nsg' -RuleId 'ok-nsg')
            )
        }
        Mock Remove-JITAksRule { return @{ Status = 'Refused' } }
        Mock Remove-JITNsgRule { return @{ Status = 'Removed' } }
        . $script:RunScript
        # The nsg row (Removed) is deleted; the aks row (Refused) is retained.
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 1 -Scope It
    }

    # ── Status = 'Removed' — explicit happy path ───────────────────────────────

    It "deletes the JITRules row when the handler returns Status='Removed'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { return @{ Status = 'Removed' } }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 1 -Scope It
    }

    It "writes an Expire JITRulesAudit row when the handler returns Status='Removed'" {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { return @{ Status = 'Removed' } }
        . $script:RunScript
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'Expire' }
    }

    # ── Legacy handler returning $null is still treated as Removed ──────────────

    It 'treats a handler returning $null as Removed (row deleted, Expire audit)' {
        Mock Get-JITTableRows  { return @(New-ExpiredRow -TargetType 'nsg') }
        Mock Remove-JITNsgRule { return $null }
        . $script:RunScript
        Assert-MockCalled Remove-JITTableRow -Exactly -Times 1 -Scope It
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'Expire' }
    }
}
