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
# Pester 5+ (setup in BeforeAll, `Should -Verb` syntax).
#
# Run:  Invoke-Pester ./src/functionapp/tests/Request-JITAccess.Tests.ps1

BeforeAll {

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

}   # end BeforeAll

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
        # run.ps1 resolves the caller IP through Resolve-JITCallerIp so it can
        # also reject a client-supplied X-Forwarded-For chain. Default: a clean
        # platform-only chain.
        Mock Resolve-JITCallerIp {
            return @{ IpAddress = '10.1.2.3'; ClaimedIp = $null; Spoofed = $false; EntryCount = 1 }
        }
        Mock Get-CallerIp                   { return '10.1.2.3' }

        # Table layer — abuse-prevention filters (RequestedBy/ResourceName) return
        # none (below limits, no cooldown); the region-5 AlreadyPresent lookup
        # (CallerIp filter) returns whatever a test stages in $global:__ExistingRow.
        Mock Get-JITTableName { return 'JITRules' }
        Mock Get-JITTableRows {
            if ($Filter -like '*CallerIp eq*')     { return @($global:__ExistingRow) }
            # Abuse-prevention / cooldown lookup. $global:__ActiveRow lets a
            # test stage an already-active rule for this caller.
            if ($Filter -like '*RequestedBy eq*')  { return @($global:__ActiveRow) }
            return @()
        }
        Mock Add-JITTableRow    { }
        Mock Update-JITTableRow { }
        Mock Remove-JITTableRow { }
        Mock Add-JITAuditRow    { }
        Mock Write-JITAuditEvent { }

        # The abuse-prevention check now runs inside a caller-scoped blob
        # lock. Run the scriptblock for real and return its value, so the
        # limit/cooldown/reservation logic inside it is what these tests
        # exercise - only the lease itself is faked away.
        Mock Invoke-WithBlobLock { & $Action }

        # Default target handler outcome: a normal Created grant. Tests override.
        Mock Add-JITSqlFirewallRule { return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'Created' } }

        $global:__ExistingRow = $null
        $global:__ActiveRow   = $null

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
        Remove-Variable -Name __ActiveRow   -Scope Global -ErrorAction SilentlyContinue
    }

    # ── Justification gate (item 2) ────────────────────────────────────────────

    It 'returns 400 when justification is required but missing' {
        Mock Test-JustificationRequired { return $true }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
    }

    It 'writes a JITDenied(JustificationRequired) audit when justification is missing' {
        Mock Test-JustificationRequired { return $true }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
            $EventType -eq 'JITDenied' -and $DenyReason -eq 'JustificationRequired'
        }
    }

    It 'does not invoke the target handler when justification is missing' {
        Mock Test-JustificationRequired { return $true }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        Should -Invoke -CommandName Add-JITSqlFirewallRule -Exactly -Times 0 -Scope It
    }

    It 'proceeds to grant when justification is NOT required, even if omitted' {
        Mock Test-JustificationRequired { return $false }
        $script:Req.Body.justification = $null
        . $script:RunScript -Request $script:Req
        $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        Get-RespStatus | Should -Be 'Created'
    }

    # ── Created (normal grant) ─────────────────────────────────────────────────

    It "records a JITRules row and a Grant audit on Status='Created'" {
        . $script:RunScript -Request $script:Req
        Get-RespStatus | Should -Be 'Created'
        Should -Invoke -CommandName Add-JITTableRow -Times 1 -Scope It
        Should -Invoke -CommandName Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'Grant' }
        Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter { $EventType -eq 'JITGranted' }
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
        Get-RespStatus | Should -Be 'Extended'
        Should -Invoke -CommandName Update-JITTableRow -Times 1 -Scope It
        Should -Invoke -CommandName Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'Extend' }
        # An extend must leave exactly ONE tracked rule. The reservation is
        # written before the grant, so the check is that it is released again
        # rather than that nothing was ever inserted.
        Should -Invoke -CommandName Add-JITTableRow    -Exactly -Times 1 -Scope It
        Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 1 -Scope It
    }

    # ── AlreadyPresent -> AlreadyExternal (entry not managed by JIT) ────────────

    It "treats Status='AlreadyPresent' with no JIT row as external (no extend, no row)" {
        Mock Add-JITSqlFirewallRule { return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'AlreadyPresent' } }
        $global:__ExistingRow = $null   # region-5 CallerIp lookup returns nothing
        . $script:RunScript -Request $script:Req
        Get-RespStatus | Should -Be 'AlreadyWhitelisted'
        Should -Invoke -CommandName Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'AlreadyExternal' }
        # JIT did not create the whitelist entry, so it must not end up
        # tracking or scheduling a removal for it: the reservation is released
        # and never promoted.
        Should -Invoke -CommandName Update-JITTableRow -Exactly -Times 0 -Scope It
        Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 1 -Scope It
    }

    # ── SkippedOpen (resource open/unrestricted) ───────────────────────────────

    It "records a SkippedOpen audit and no row on Status='SkippedOpen'" {
        Mock Add-JITSqlFirewallRule { return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'SkippedOpen' } }
        . $script:RunScript -Request $script:Req
        Get-RespStatus | Should -Be 'SkippedOpen'
        Should -Invoke -CommandName Add-JITAuditRow -Times 1 -Scope It -ParameterFilter { $Action -eq 'SkippedOpen' }
        # Nothing to revoke, so the reservation must be released and never
        # promoted to Active.
        Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 1 -Scope It
        Should -Invoke -CommandName Update-JITTableRow -Exactly -Times 0 -Scope It
    }

    # ── Idempotency / cooldown (2.8) ──────────────────────────────────────────
    #
    # The host retries the grant POST and the plugin cannot disable it, so the
    # same request can arrive twice. The second arrival must not be reported as
    # a failure for a grant that already succeeded.

    It 'returns the existing rule as success when the same caller IP already has one' {
        $global:__ActiveRow = [PSCustomObject]@{
            RowKey         = 'jit-alice-11112222'
            PartitionKey   = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            ResourceName   = 'res1'
            ResourceRg     = 'rg1'
            SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            TargetType     = 'sqlServer'
            RuleIdentifier = 'jit-alice-11112222'
            CallerIp       = '10.1.2.3'
            RequestedBy    = 'alice@contoso.com'
            ExpiryUtc      = ([DateTime]::UtcNow.AddHours(3)).ToString('o')
        }

        . $script:RunScript -Request $script:Req

        $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        Get-RespStatus            | Should -Be 'AlreadyActive'
        ($global:__Resp.Body | ConvertFrom-Json).ruleId | Should -Be 'jit-alice-11112222'
    }

    It 'does not create a second rule or extend the expiry on the idempotent path' {
        $existingExpiry = ([DateTime]::UtcNow.AddHours(3)).ToString('o')
        $global:__ActiveRow = [PSCustomObject]@{
            RowKey         = 'jit-alice-11112222'
            PartitionKey   = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            ResourceName   = 'res1'
            ResourceRg     = 'rg1'
            SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            TargetType     = 'sqlServer'
            RuleIdentifier = 'jit-alice-11112222'
            CallerIp       = '10.1.2.3'
            RequestedBy    = 'alice@contoso.com'
            ExpiryUtc      = $existingExpiry
        }

        . $script:RunScript -Request $script:Req

        Should -Invoke -CommandName Add-JITSqlFirewallRule -Times 0 -Scope It
        Should -Invoke -CommandName Add-JITTableRow        -Times 0 -Scope It
        Should -Invoke -CommandName Update-JITTableRow     -Times 0 -Scope It
        # ConvertFrom-Json rehydrates an ISO-8601 string as [DateTime], so compare
        # normalised values rather than raw text.
        $returned = ([DateTime](($global:__Resp.Body | ConvertFrom-Json).expiresUtc)).ToUniversalTime().ToString('o')
        $returned | Should -Be ([DateTime]$existingExpiry).ToUniversalTime().ToString('o')
    }

    It 'still returns 409 when the active rule belongs to a different caller IP' {
        $global:__ActiveRow = [PSCustomObject]@{
            RowKey         = 'jit-alice-33334444'
            PartitionKey   = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            ResourceName   = 'res1'
            ResourceRg     = 'rg1'
            SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            TargetType     = 'sqlServer'
            RuleIdentifier = 'jit-alice-33334444'
            CallerIp       = '198.51.100.9'
            RequestedBy    = 'alice@contoso.com'
            ExpiryUtc      = ([DateTime]::UtcNow.AddHours(3)).ToString('o')
        }

        . $script:RunScript -Request $script:Req

        $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
        Should -Invoke -CommandName Add-JITSqlFirewallRule -Times 0 -Scope It
    }

    # ── Caller IP trust boundary (1.2) ────────────────────────────────────────

    It 'rejects a request whose client supplied its own X-Forwarded-For chain' {
        Mock Resolve-JITCallerIp {
            return @{ IpAddress = '10.1.2.3'; ClaimedIp = '203.0.113.50'; Spoofed = $true; EntryCount = 2 }
        }

        . $script:RunScript -Request $script:Req

        $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        Should -Invoke -CommandName Add-JITSqlFirewallRule -Times 0 -Scope It
        Should -Invoke -CommandName Add-JITTableRow        -Times 0 -Scope It
    }

    # ── Compensating remove when the tracking row cannot be written ───────────
    #
    # The worst failure this system can have: the firewall hole is open on the
    # resource and nothing records it, so the expiry timer will never revoke
    # it. Before the fix this logged a warning and returned 200 Created.
    Context 'when the reservation cannot be finalised after a successful grant' {

        BeforeEach {
            # The Functions worker leaves $ErrorActionPreference at Continue, so
            # run.ps1's Write-Error paths below are non-terminating there.
            # test.ps1 sets Stop for its own logic; match the worker.
            $ErrorActionPreference = 'Continue'
            # The row is now INSERTED before the grant (the reservation) and
            # UPDATED after it (the finalise), so the failure that strands a
            # live rule is the update.
            Mock Update-JITTableRow { throw 'table storage unavailable' }
            Mock Invoke-JITTargetRemove { return @{ Status = 'Removed'; Details = @{} } }
        }

        It 'removes the rule it just created rather than leaving it untracked' {
            . $script:RunScript -Request $script:Req 2>$null 3>$null
            Should -Invoke -CommandName Invoke-JITTargetRemove -Exactly -Times 1 -Scope It -ParameterFilter {
                $Row.TargetType -eq 'sqlServer' -and $Row.ResourceName -eq 'res1'
            }
        }

        It 'reports 500, never a success, when the grant could not be recorded' {
            . $script:RunScript -Request $script:Req 2>$null 3>$null
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        }

        It 'audits JITGrantRolledBack when the compensating remove succeeds' {
            . $script:RunScript -Request $script:Req 2>$null 3>$null
            Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
                $EventType -eq 'JITGrantRolledBack'
            }
        }

        It 'returns a correlation id and no exception detail to the caller' {
            . $script:RunScript -Request $script:Req 2>$null 3>$null
            $body = $global:__Resp.Body | ConvertFrom-Json
            $body.correlationId | Should -Match '^[0-9a-f]{12}$'
            ($body | ConvertTo-Json) | Should -Not -Match 'table storage unavailable'
        }

        It 'escalates to JITOrphanedGrant when the compensating remove also fails' {
            Mock Invoke-JITTargetRemove { throw 'ARM delete failed too' }
            . $script:RunScript -Request $script:Req 2>$null 3>$null
            Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
                $EventType -eq 'JITOrphanedGrant'
            }
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        }

        It 'escalates to JITOrphanedGrant when the rollback is refused rather than done' {
            # AKS refuses to remove the last authorized range, so the rule stays
            # live and untracked. That is an orphan, not a clean rollback.
            Mock Invoke-JITTargetRemove { return @{ Status = 'Refused'; Details = @{} } }
            . $script:RunScript -Request $script:Req 2>$null 3>$null
            Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
                $EventType -eq 'JITOrphanedGrant'
            }
            Should -Invoke -CommandName Write-JITAuditEvent -Exactly -Times 0 -Scope It -ParameterFilter {
                $EventType -eq 'JITGrantRolledBack'
            }
        }
    }

    # ── Serialised abuse limits: the reservation (2.5) ────────────────────────
    #
    # The race: the limits used to be read here and the row written after an
    # ARM call that can take minutes, so two concurrent requests from one
    # caller both passed the check and both inserted. The fix makes "check"
    # and "claim a slot" one atomic step under a caller-scoped lock, with the
    # ARM call deliberately OUTSIDE it (a 60s lease with no renewal cannot
    # safely span an LRO).
    Context 'reservation' {

        BeforeEach {
            $global:__Order = @()
            Mock Add-JITTableRow        { $global:__Order += 'reserve' }
            Mock Update-JITTableRow     { $global:__Order += 'finalise' }
            Mock Remove-JITTableRow     { $global:__Order += 'release' }
            Mock Add-JITSqlFirewallRule {
                $global:__Order += 'grant'
                return @{ RuleIdentifier = 'jit-alice-abcd1234'; Status = 'Created' }
            }
        }

        AfterEach {
            Remove-Variable -Name __Order -Scope Global -ErrorAction SilentlyContinue
        }

        It 'claims the slot BEFORE calling ARM, and finalises it after' {
            # This ordering IS the fix. A reservation written after the grant
            # would leave the same window open that the bug lived in.
            . $script:RunScript -Request $script:Req
            ($global:__Order -join ',') | Should -Be 'reserve,grant,finalise'
        }

        It 'evaluates the limits inside a lock keyed on the caller' {
            . $script:RunScript -Request $script:Req
            Should -Invoke -CommandName Invoke-WithBlobLock -Exactly -Times 1 -Scope It -ParameterFilter {
                $LockName -eq 'caller-oid-1'
            }
        }

        It 'writes the reservation with NO RuleIdentifier' {
            # It must stay blank until the grant reports what it actually
            # used, so each Remove handler falls back to the right per-type
            # key. Writing $ruleId here makes the twelve IP-identified types
            # (storage, keyVault, cosmosDb, aks, ...) hunt for an ipRule whose
            # VALUE is the rule id, find nothing, and report NotFound -- after
            # which the timer deletes the row and the live rule is orphaned.
            . $script:RunScript -Request $script:Req
            Should -Invoke -CommandName Add-JITTableRow -Exactly -Times 1 -Scope It -ParameterFilter {
                [string]::IsNullOrEmpty($Properties.RuleIdentifier)
            }
        }

        It 'writes the reservation as Pending with a short expiry, not the requested one' {
            . $script:RunScript -Request $script:Req
            Should -Invoke -CommandName Add-JITTableRow -Exactly -Times 1 -Scope It -ParameterFilter {
                $Properties.State -eq 'Pending' -and
                $Properties.CallerIp -eq '10.1.2.3' -and
                # 4h was requested; the reservation must expire far sooner so
                # an abandoned one clears itself.
                ([DateTime]::Parse($Properties.ExpiryUtc)).ToUniversalTime() -lt [DateTime]::UtcNow.AddHours(1)
            }
        }

        It 'promotes the reservation to Active with the real expiry and the handler identifier' {
            . $script:RunScript -Request $script:Req
            Should -Invoke -CommandName Update-JITTableRow -Exactly -Times 1 -Scope It -ParameterFilter {
                $Properties.State -eq 'Active' -and
                $Properties.RuleIdentifier -eq 'jit-alice-abcd1234' -and
                ([DateTime]::Parse($Properties.ExpiryUtc)).ToUniversalTime() -gt [DateTime]::UtcNow.AddHours(3)
            }
        }

        It 'releases the slot when the grant fails' {
            # Otherwise a failed request would cost the caller one of their
            # five slots until the reservation expired.
            $ErrorActionPreference = 'Continue'
            Mock Add-JITSqlFirewallRule { $global:__Order += 'grant'; throw 'ARM rejected the write' }
            . $script:RunScript -Request $script:Req 2>$null
            ($global:__Order -join ',') | Should -Be 'reserve,grant,release'
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        }

        It 'counts a reservation toward the per-caller limit' {
            # The whole point: an in-flight request from the same caller
            # occupies a slot even though its rule does not exist yet.
            $global:__ActiveRow = @(1..5 | ForEach-Object {
                [PSCustomObject]@{
                    RowKey       = "jit-alice-pending$_"
                    ResourceName = "other$_"
                    SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                    CallerIp     = '10.1.2.3'
                    State        = 'Pending'
                    ExpiryUtc    = ([DateTime]::UtcNow.AddMinutes(15)).ToString('o')
                }
            })
            . $script:RunScript -Request $script:Req
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::TooManyRequests)
            # Denied means no slot taken and no ARM call made.
            ($global:__Order -join ',') | Should -Be ''
        }

        It 'refuses a duplicate while the first request for the resource is still in flight' {
            $global:__ActiveRow = @([PSCustomObject]@{
                RowKey         = 'jit-alice-inflight'
                ResourceName   = 'res1'
                SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                CallerIp       = '10.1.2.3'
                State          = 'Pending'
                ExpiryUtc      = ([DateTime]::UtcNow.AddMinutes(15)).ToString('o')
            })
            . $script:RunScript -Request $script:Req
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
            # Not reported as "you already have access" - the rule may not exist.
            Get-RespStatus | Should -Not -Be 'AlreadyActive'
            ($global:__Order -join ',') | Should -Be ''
        }

        It 'denies without reserving when the table cannot be read (fails closed)' {
            $ErrorActionPreference = 'Continue'
            Mock Get-JITTableRows { throw 'storage unavailable' }
            . $script:RunScript -Request $script:Req 2>$null
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::ServiceUnavailable)
            ($global:__Order -join ',') | Should -Be ''
        }
    }
}
