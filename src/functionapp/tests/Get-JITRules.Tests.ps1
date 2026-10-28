# Tests for Get-JITRules/run.ps1 — the second endpoint that had no test file.
#
# It is read-only, but two things here are load-bearing:
#   • the owner filter is applied SERVER-side, so a poll no longer pulls every
#     other caller's UPN, IP and justification across the wire;
#   • the X-JIT-Caller-IP header reports the IP a grant WOULD use, so it has to
#     be the trusted address, not one the client put in X-Forwarded-For. This
#     endpoint is where the spoof was first observed in production.
#
# Run:  ./test.ps1 -Target Get-JITRules

BeforeAll {

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force

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

$script:RunScript = "$PSScriptRoot/../Get-JITRules/run.ps1"

function script:New-Request {
    param([string]$Auth = 'Bearer token', [string]$ForwardedFor)
    $headers = @{}
    if ($Auth) { $headers['Authorization'] = $Auth }
    if ($PSBoundParameters.ContainsKey('ForwardedFor')) { $headers['X-Forwarded-For'] = $ForwardedFor }
    return [PSCustomObject]@{
        Headers     = $headers
        HttpContext = [PSCustomObject]@{ Connection = [PSCustomObject]@{ RemoteIpAddress = '198.51.100.1' } }
    }
}

function script:New-Row {
    param(
        [string]$RuleId      = 'jit-alice-abcd1234',
        [string]$RequestedBy = 'alice@contoso.com',
        [double]$ExpiresInHours = 2,
        [string]$Port        = $null
    )
    [PSCustomObject]@{
        PartitionKey   = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        RowKey         = $RuleId
        TargetType     = 'sqlServer'
        RuleIdentifier = $RuleId
        ResourceName   = 'res1'
        ResourceRg     = 'rg1'
        SubscriptionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        CallerIp       = '10.1.2.3'
        Port           = $Port
        RequestedBy    = $RequestedBy
        ExpiryUtc      = ([DateTime]::UtcNow.AddHours($ExpiresInHours)).ToString('o')
        Justification  = 'incident 42'
    }
}

}   # end BeforeAll

Describe 'Get-JITRules' {

    BeforeEach {
        $global:__Resp = $null

        Mock Import-Module { }
        Mock Get-JitTenantId      { return 'test-tenant' }
        Mock Invoke-JwtValidation { return @{ oid = 'oid-1'; upn = 'alice@contoso.com' } }
        Mock Get-JITTableName     { return 'JITRules' }
        Mock Get-JITTableRows     { return @($global:__Rows) }

        $global:__Rows = @(New-Row)
    }

    AfterEach {
        Remove-Variable -Name __Resp -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name __Rows -Scope Global -ErrorAction SilentlyContinue
    }

    Context 'authentication' {

        It 'returns 401 without an Authorization header' {
            . $script:RunScript -Request (New-Request -Auth '')
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Unauthorized)
        }

        It 'returns 403 when token validation fails' {
            Mock Invoke-JwtValidation { return $null }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
        }

        It 'returns 403 when the token has no oid claim' {
            Mock Invoke-JwtValidation { return @{ upn = 'alice@contoso.com' } }
            . $script:RunScript -Request (New-Request)
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
        }
    }

    Context 'owner scoping' {

        It 'filters by RequestedBy server-side rather than downloading every row' {
            . $script:RunScript -Request (New-Request)
            Should -Invoke -CommandName Get-JITTableRows -Exactly -Times 1 -Scope It -ParameterFilter {
                $Filter -eq "RequestedBy eq 'alice@contoso.com'"
            }
        }

        It 'escapes an apostrophe in the UPN by doubling it' {
            # o'brien@contoso.com would otherwise terminate the OData string.
            Mock Invoke-JwtValidation { return @{ oid = 'oid-1'; upn = "o'brien@contoso.com" } }
            . $script:RunScript -Request (New-Request)
            Should -Invoke -CommandName Get-JITTableRows -Exactly -Times 1 -Scope It -ParameterFilter {
                $Filter -eq "RequestedBy eq 'o''brien@contoso.com'"
            }
        }

        It 'falls back to unique_name then sub when upn is absent' {
            Mock Invoke-JwtValidation { return @{ oid = 'oid-1'; unique_name = 'alice-un@contoso.com' } }
            . $script:RunScript -Request (New-Request)
            Should -Invoke -CommandName Get-JITTableRows -Exactly -Times 1 -Scope It -ParameterFilter {
                $Filter -eq "RequestedBy eq 'alice-un@contoso.com'"
            }
        }
    }

    Context 'expiry filtering' {

        It 'returns an active rule' {
            . $script:RunScript -Request (New-Request)
            $body = $global:__Resp.Body | ConvertFrom-Json
            @($body).Count | Should -Be 1
            @($body)[0].ruleId | Should -Be 'jit-alice-abcd1234'
        }

        It 'omits a rule whose expiry has passed' {
            $global:__Rows = @(New-Row -ExpiresInHours -1)
            . $script:RunScript -Request (New-Request)
            $global:__Resp.Body | Should -Be '[]'
        }

        It 'returns an empty JSON array, not an empty string, when nothing is active' {
            # `@() | ConvertTo-Json` yields '' — a client parsing that gets a
            # parse error instead of "you have no rules".
            $global:__Rows = @()
            . $script:RunScript -Request (New-Request)
            $global:__Resp.Body | Should -Be '[]'
        }

        It 'keeps only the active rule when active and expired are mixed' {
            $global:__Rows = @(
                (New-Row -RuleId 'jit-alice-expired1' -ExpiresInHours -3),
                (New-Row -RuleId 'jit-alice-active01' -ExpiresInHours 5)
            )
            . $script:RunScript -Request (New-Request)
            $body = @($global:__Resp.Body | ConvertFrom-Json)
            $body.Count    | Should -Be 1
            $body[0].ruleId | Should -Be 'jit-alice-active01'
        }

        It 'omits a reservation that has not been granted yet' {
            # State='Pending' is a slot claimed by an in-flight request. The
            # rule may not exist on the resource, and may never, so listing it
            # would tell the caller they hold access they do not have.
            $row = New-Row
            $row | Add-Member -NotePropertyName State -NotePropertyValue 'Pending'
            $global:__Rows = @($row)
            . $script:RunScript -Request (New-Request)
            $global:__Resp.Body | Should -Be '[]'
        }

        It 'still lists rows written before the State column existed' {
            # Pre-reservation rows carry no State at all; absent must read as
            # active, not as pending.
            $global:__Rows = @(New-Row)
            . $script:RunScript -Request (New-Request)
            @($global:__Resp.Body | ConvertFrom-Json).Count | Should -Be 1
        }

        It 'drops a row whose expiry cannot be parsed rather than reporting it active' {
            $row = New-Row
            $row.ExpiryUtc = 'not-a-date'
            $global:__Rows = @($row)
            . $script:RunScript -Request (New-Request)
            $global:__Resp.Body | Should -Be '[]'
        }
    }

    Context 'caller IP header' {

        It 'reports the platform-observed IP' {
            . $script:RunScript -Request (New-Request -ForwardedFor '192.0.2.10:65221')
            $global:__Resp.Headers['X-JIT-Caller-IP'] | Should -Be '192.0.2.10'
        }

        It 'does NOT report a client-supplied X-Forwarded-For entry' {
            # This endpoint is how the spoof was confirmed against production:
            # it echoed back whatever the client claimed, which is the same IP
            # a grant would have allowlisted.
            . $script:RunScript -Request (New-Request -ForwardedFor '203.0.113.50, 192.0.2.10:65224')
            $global:__Resp.Headers['X-JIT-Caller-IP'] | Should -Be '192.0.2.10'
            $global:__Resp.Headers['X-JIT-Caller-IP'] | Should -Not -Be '203.0.113.50'
        }

        It 'falls back to the socket address with no X-Forwarded-For' {
            . $script:RunScript -Request (New-Request)
            $global:__Resp.Headers['X-JIT-Caller-IP'] | Should -Be '198.51.100.1'
        }
    }

    Context 'failure handling' {

        It 'returns 500 when the table query throws' {
            $ErrorActionPreference = 'Continue'
            Mock Get-JITTableRows { throw 'table unavailable' }
            . $script:RunScript -Request (New-Request) 2>$null
            $global:__Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        }
    }
}
