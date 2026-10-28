# Tests for Revoke-JITAccess/run.ps1 — previously the only HTTP endpoint with
# no test file at all, despite carrying three separate authorization decisions.
#
# Covered:
#   • ruleId path validation (the value is interpolated into an OData filter)
#   • token / oid gates
#   • ownership — a caller may only revoke rules they themselves requested
#   • RBAC — the JIT-Requester check runs against the RULE's subscription, not
#     the function app's own
#   • Refused (AKS) — the row is KEPT and 409 returned, so a refusal can never
#     read as a successful revoke
#   • Removed / NotFound — the row is deleted and the revoke audited
#   • a failed resource removal leaves the tracking row in place
#
# run.ps1 is dot-sourced with its own -Request parameter, matching the
# Request-JITAccess tests. Every dependency is mocked, so nothing touches AAD,
# ARM or Table Storage.
#
# Run:  ./test.ps1 -Target Revoke-JITAccess

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

$script:RunScript = "$PSScriptRoot/../Revoke-JITAccess/run.ps1"

function script:Get-RespBody { $global:__Resp.Body | ConvertFrom-Json }

function script:New-Request {
    param([string]$RuleId = 'jit-alice-abcd1234', [string]$Auth = 'Bearer token')
    $headers = @{}
    if ($Auth) { $headers['Authorization'] = $Auth }
    return [PSCustomObject]@{
        Headers = $headers
        Params  = @{ ruleId = $RuleId }
    }
}

function script:New-Row {
    param([string]$TargetType = 'sqlServer', [string]$RequestedBy = 'alice@contoso.com')
    [PSCustomObject]@{
        PartitionKey   = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        RowKey         = 'jit-alice-abcd1234'
        TargetType     = $TargetType
        RuleIdentifier = 'jit-alice-abcd1234'
        ResourceName   = 'res1'
        ResourceRg     = 'rg1'
        SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        CallerIp       = '10.1.2.3'
        RequestedBy    = $RequestedBy
        ExpiryUtc      = ([DateTime]::UtcNow.AddHours(2)).ToString('o')
        Justification  = 'incident 42'
        Port           = $null
        State          = 'Active'
    }
}

}   # end BeforeAll

Describe 'Revoke-JITAccess' {

    BeforeEach {
        $global:__Resp = $null

        Mock Import-Module { }

        Mock Get-JitTenantId                { return 'test-tenant' }
        Mock Invoke-JwtValidation           { return @{ oid = 'oid-1'; upn = 'alice@contoso.com' } }
        Mock Test-CallerHasJitRequesterRole { return $true }

        Mock Get-JITTableName   { return 'JITRules' }
        Mock Get-JITTableRows   { return @($global:__Row) }
        Mock Remove-JITTableRow { }
        Mock Add-JITAuditRow    { }
        Mock Write-JITAuditEvent { }

        Mock Remove-JITSqlFirewallRule { return @{ Status = 'Removed'; Details = @{} } }
        Mock Remove-JITAksRule         { return @{ Status = 'Removed'; Details = @{} } }

        $global:__Row = New-Row
    }

    AfterEach {
        Remove-Variable -Name __Resp -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name __Row  -Scope Global -ErrorAction SilentlyContinue
    }

    # ── ruleId validation ─────────────────────────────────────────────────────

    Context 'ruleId path validation' {

        It 'accepts the username-tagged rule id shape' {
            . $script:RunScript -Request (New-Request -RuleId 'jit-alice-abcd1234')
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        }

        It 'accepts the legacy rule id shape' {
            $global:__Row.RowKey = 'jit-abcd1234'
            . $script:RunScript -Request (New-Request -RuleId 'jit-abcd1234')
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        }

        It 'rejects a rule id carrying an OData quote-break attempt' {
            # $ruleId is interpolated straight into "RowKey eq '<id>'", so the
            # charset restriction is what keeps that filter injection-free.
            . $script:RunScript -Request (New-Request -RuleId "jit-x' or RowKey ne '")
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
            Should -Invoke -CommandName Get-JITTableRows -Exactly -Times 0 -Scope It
        }

        It 'rejects a missing rule id' {
            . $script:RunScript -Request (New-Request -RuleId '')
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }

        It 'rejects a rule id with the wrong suffix length' {
            . $script:RunScript -Request (New-Request -RuleId 'jit-abc123')
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }
    }

    # ── Authentication ────────────────────────────────────────────────────────

    Context 'authentication' {

        It 'returns 401 when the Authorization header is absent' {
            . $script:RunScript -Request (New-Request -Auth '')
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Unauthorized)
        }

        It 'returns 401 when the Authorization header is not a Bearer token' {
            . $script:RunScript -Request (New-Request -Auth 'Basic dXNlcjpwYXNz')
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Unauthorized)
        }

        It 'returns 403 when token validation fails' {
            Mock Invoke-JwtValidation { return $null }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
        }

        It 'returns 403 when the token carries no oid claim' {
            Mock Invoke-JwtValidation { return @{ upn = 'alice@contoso.com' } }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
        }
    }

    # ── Ownership and RBAC ────────────────────────────────────────────────────

    Context 'ownership and authorization' {

        It 'refuses to revoke a reservation that is still being granted' {
            # State='Pending' means Request-JITAccess has claimed the slot and
            # is mid-flight against ARM. Removing the row now would race that
            # request and could delete the tracking row while the rule is
            # still being created - the untracked-rule case reservations exist
            # to prevent.
            $global:__Row.State = 'Pending'
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
            (Get-RespBody).status | Should -Be 'InProgress'
            Should -Invoke -CommandName Remove-JITSqlFirewallRule -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Remove-JITTableRow        -Exactly -Times 0 -Scope It
        }

        It 'returns 404 when no rule matches the id' {
            Mock Get-JITTableRows { return @() }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::NotFound)
        }

        It "refuses to revoke another caller's rule" {
            $global:__Row = New-Row -RequestedBy 'bob@contoso.com'
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
            Should -Invoke -CommandName Remove-JITSqlFirewallRule -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Remove-JITTableRow        -Exactly -Times 0 -Scope It
        }

        It 'checks the RBAC role against the subscription the RULE targets' {
            # Not the function app's own subscription: a caller holding
            # JIT-Requester somewhere else must not be able to revoke here.
            . $script:RunScript -Request (New-Request)
            Should -Invoke -CommandName Test-CallerHasJitRequesterRole -Exactly -Times 1 -Scope It -ParameterFilter {
                $SubscriptionId -eq 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -and $CallerObjectId -eq 'oid-1'
            }
        }

        It 'returns 403 and touches nothing when the caller lacks the role' {
            Mock Test-CallerHasJitRequesterRole { return $false }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
            Should -Invoke -CommandName Remove-JITSqlFirewallRule -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Remove-JITTableRow        -Exactly -Times 0 -Scope It
        }
    }

    # ── Remove-status branching ───────────────────────────────────────────────

    Context 'remove-status branching' {

        It 'deletes the tracking row and audits a JITRevoked on Status=Removed' {
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
            Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
                $EventType -eq 'JITRevoked'
            }
        }

        It 'still cleans up the row when the rule was already gone (Status=NotFound)' {
            Mock Remove-JITSqlFirewallRule { return @{ Status = 'NotFound'; Details = @{} } }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
            Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
                $EventType -eq 'JITRevoked' -and $Extra.notFound -eq $true
            }
        }

        It 'returns 409 and KEEPS the row when an AKS removal is refused' {
            # Refusing means the IP is still allowlisted. Deleting the row here
            # would leave the cluster open with nothing tracking it.
            $global:__Row = New-Row -TargetType 'aks'
            Mock Remove-JITAksRule { return @{ Status = 'Refused'; Details = @{} } }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
            (Get-RespBody).status | Should -Be 'Refused'
            Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 0 -Scope It
        }

        It 'audits a refused revoke as JITRemoveFailed, never as revoked' {
            $global:__Row = New-Row -TargetType 'aks'
            Mock Remove-JITAksRule { return @{ Status = 'Refused'; Details = @{} } }
            . $script:RunScript -Request (New-Request)
            Should -Invoke -CommandName Write-JITAuditEvent -Times 1 -Scope It -ParameterFilter {
                $EventType -eq 'JITRemoveFailed'
            }
            Should -Invoke -CommandName Write-JITAuditEvent -Exactly -Times 0 -Scope It -ParameterFilter {
                $EventType -eq 'JITRevoked'
            }
        }
    }

    # ── Failure handling ──────────────────────────────────────────────────────

    Context 'failure handling' {

        It 'keeps the tracking row when the resource removal throws' {
            # The Functions PowerShell worker leaves $ErrorActionPreference at
            # its default of Continue, so run.ps1's Write-Error in the catch is
            # non-terminating and the 500 response below it is still written.
            # test.ps1 sets Stop for its own logic; match the worker here or
            # this asserts against behaviour production never has.
            $ErrorActionPreference = 'Continue'
            Mock Remove-JITSqlFirewallRule { throw 'ARM rejected the delete' }
            . $script:RunScript -Request (New-Request) 2>$null
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
            Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 0 -Scope It
        }

        It 'returns a correlation id instead of the exception text' {
            # The exception can carry ARM URLs, resource ids and raw RP error
            # bodies; none of that belongs in a client response.
            $ErrorActionPreference = 'Continue'
            Mock Remove-JITSqlFirewallRule { throw 'ARM said: /subscriptions/secret-sub/resourceGroups/secret-rg failed' }
            . $script:RunScript -Request (New-Request) 2>$null
            $body = Get-RespBody
            $body.correlationId | Should -Match '^[0-9a-f]{12}$'
            ($body | ConvertTo-Json) | Should -Not -Match 'secret-sub'
        }

        It 'still reports success when only the table-row deletion fails' {
            # The rule IS off the resource at this point; failing the response
            # would make the caller retry a revoke that already worked.
            Mock Remove-JITTableRow { throw 'table unavailable' }
            . $script:RunScript -Request (New-Request) 3>$null
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        }

        It 'does not fail the revoke when the audit-history write fails' {
            Mock Add-JITAuditRow { throw 'audit table unavailable' }
            . $script:RunScript -Request (New-Request) 3>$null
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
            Should -Invoke -CommandName Remove-JITTableRow -Exactly -Times 1 -Scope It
        }
    }
}
