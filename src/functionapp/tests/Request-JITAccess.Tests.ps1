# Tests for Request-JITAccess/run.ps1 endpoint branching (FEAT-0003, items 2 & 4).
#
# run.ps1 is dot-sourced (as the Remove-ExpiredRules tests dot-source theirs),
# passing the HTTP request via the script's own `param($Request)` — `. run.ps1
# -Request <req>`, since a dot-sourced script's param block shadows any ambient
# $Request. Every dependency the endpoint reaches is mocked in the established
# current-function style (NOT Az.*): the JWT validator, the RBAC check, the
# justification-policy gate, the target Add-JIT*Rule dispatch, the table layer,
# and both audit sinks — so nothing touches AAD, ARM, Graph, or Table Storage.
#
# Two Functions-worker dependencies are stubbed at the top: the [HttpResponseContext]
# output type (declared via Add-Type — it lives in the PowerShell worker, absent
# here) and the Push-OutputBinding cmdlet (captured into $global:__Resp so tests
# can assert the HTTP status + body). sqlServer is used as the target type so the
# NSG-only Invoke-WithBlobLock path is not exercised.
#
# Covered branches:
#   • Justification required + missing         -> 400 + JITDenied(JustificationRequired)
#   • Justification NOT required + missing      -> proceeds to Created
#   • Add handler Status = 'Created'            -> JITRules row + Grant audit
#   • Add handler Status = 'AlreadyPresent',
#       existing JIT-managed row found          -> Extend (Update-JITTableRow + Extend audit)
#   • Add handler Status = 'AlreadyPresent',
#       no JIT row (external/manual entry)      -> AlreadyExternal audit, no row/extend
#   • Add handler Status = 'SkippedOpen'        -> SkippedOpen audit, no row/extend
#
# Pester 3.4.0 compatible (no BeforeAll at top level, no Should -Verb syntax).
#
# Run:  Invoke-Pester ./src/functionapp/tests/Request-JITAccess.Tests.ps1

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

# ── Functions-worker stubs (output type + binding cmdlet) ─────────────────────
if (-not ('HttpResponseContext' -as [type])) {
    Add-Type -TypeDefinition @"
public class HttpResponseContext {
    public object StatusCode;
    public object Body;
    public object Headers;
}
"@
}
function global:Push-OutputBinding {
    param([string]$Name, $Value)
    $global:__Resp = $Value
}

$script:RunScript = "$PSScriptRoot/../Request-JITAccess/run.ps1"

# Parse the JSON body run.ps1 wrote into the captured HttpResponseContext.
function script:Get-RespStatus { ($global:__Resp.Body | ConvertFrom-Json).status }

Describe 'Request-JITAccess endpoint branching' {

    BeforeEach {
        $global:__Resp = $null

        # Suppress run.ps1's own Import-Module calls (real modules already loaded).
        Mock Import-Module { }

        # Identity / authorization / policy — all pass by default.
        Mock Get-JitTenantId                { return 'test-tenant' }
        Mock Invoke-JwtValidation           { return @{ oid = 'oid-1'; upn = 'alice@contoso.com' } }
        Mock Test-CallerHasJitRequesterRole { return $true }
        Mock Test-JustificationRequired     { return $true }
        Mock Get-CallerIp                   { return '10.1.2.3' }

        # Table layer — abuse-prevention filters (RequestedBy/ResourceName) return
        # none (below limits, no cooldown); the region-5 AlreadyPresent lookup
        # (CallerIp filter) returns whatever a test stages in $global:__ExistingRow.
        Mock Get-JITTableName { return 'JITRules' }
        Mock Get-JITTableRows {
            if ($Filter -like '*CallerIp eq*') { return @($global:__ExistingRow) }
            return @()
        }
        Mock Add-JITTableRow    { }
        Mock Update-JITTableRow { }
        Mock Add-JITAuditRow    { }
        Mock Write-JITAuditEvent { }

        # Default target handler outcome: a normal Created grant. Tests override.
        Mock Add-JITSqlFirewallRule { return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'Created' } }

        $global:__ExistingRow = $null

        $script:Req = [PSCustomObject]@{
            Headers = @{ Authorization = 'Bearer token' }
            Body    = @{
                targetType     = 'sqlServer'
                subscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                resourceGroup  = 'rg1'
                resourceName   = 'res1'
                durationHours  = 4
                justification  = 'need access for incident 42'
            }
        }
    }

    AfterEach {
        Remove-Variable -Name __Resp        -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name __ExistingRow -Scope Global -ErrorAction SilentlyContinue
    }

    # ── Justification gate (item 2) ────────────────────────────────────────────

    It 'returns 400 when justification is required but missing' {
        Mock Test-JustificationRequired { return $true }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        $global:__Resp.StatusCode | Should Be ([System.Net.HttpStatusCode]::BadRequest)
    }

    It 'writes a JITDenied(JustificationRequired) audit when justification is missing' {
        Mock Test-JustificationRequired { return $true }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITDenied' -and $DenyReason -eq 'JustificationRequired'
        }
    }

    It 'does not invoke the target handler when justification is missing' {
        Mock Test-JustificationRequired { return $true }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        Assert-MockCalled Add-JITSqlFirewallRule -Exactly -Times 0 -Scope It
    }

    It 'proceeds to grant when justification is NOT required, even if omitted' {
        Mock Test-JustificationRequired { return $false }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        $global:__Resp.StatusCode | Should Be ([System.Net.HttpStatusCode]::OK)
        Get-RespStatus | Should Be 'Created'
    }

    # ── Created (normal grant) ─────────────────────────────────────────────────

    It "records a JITRules row and a Grant audit on Status='Created'" {
        . $script:RunScript -Request $script:Req
        Get-RespStatus | Should Be 'Created'
        Assert-MockCalled Add-JITTableRow -Times 1 -Scope It
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'Grant' }
        Assert-MockCalled Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter { $EventType -eq 'JITGranted' }
    }

    # ── AlreadyPresent -> Extend (the whitelist entry is a JIT-managed row) ─────

    It "extends the existing row on Status='AlreadyPresent' when a JIT row exists" {
        Mock Add-JITSqlFirewallRule { return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'AlreadyPresent' } }
        $global:__ExistingRow = [PSCustomObject]@{
            PartitionKey = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            RowKey       = 'jit-alice-existing1'
            RuleIdentifier = 'jit-alice-existing1'
        }
        . $script:RunScript -Request $script:Req
        Get-RespStatus | Should Be 'Extended'
        Assert-MockCalled Update-JITTableRow -Times 1 -Scope It
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'Extend' }
        # An extend must NOT create a new JITRules row.
        Assert-MockCalled Add-JITTableRow -Exactly -Times 0 -Scope It
    }

    # ── AlreadyPresent -> AlreadyExternal (entry not managed by JIT) ────────────

    It "treats Status='AlreadyPresent' with no JIT row as external (no extend, no row)" {
        Mock Add-JITSqlFirewallRule { return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'AlreadyPresent' } }
        $global:__ExistingRow = $null   # region-5 CallerIp lookup returns nothing
        . $script:RunScript -Request $script:Req
        Get-RespStatus | Should Be 'AlreadyWhitelisted'
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'AlreadyExternal' }
        Assert-MockCalled Update-JITTableRow -Exactly -Times 0 -Scope It
        Assert-MockCalled Add-JITTableRow    -Exactly -Times 0 -Scope It
    }

    # ── SkippedOpen (resource open/unrestricted) ───────────────────────────────

    It "records a SkippedOpen audit and no row on Status='SkippedOpen'" {
        Mock Add-JITSqlFirewallRule { return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'SkippedOpen' } }
        . $script:RunScript -Request $script:Req
        Get-RespStatus | Should Be 'SkippedOpen'
        Assert-MockCalled Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'SkippedOpen' }
        Assert-MockCalled Add-JITTableRow    -Exactly -Times 0 -Scope It
        Assert-MockCalled Update-JITTableRow -Exactly -Times 0 -Scope It
    }
}
