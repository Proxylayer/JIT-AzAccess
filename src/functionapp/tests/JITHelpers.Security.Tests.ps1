# Tests for the three JITHelpers behaviours that decide whether JIT fails open.
#
#   • Resolve-JITCallerIp  — WHICH IP gets a firewall hole punched for it, and
#                            whether the client supplied part of the chain.
#   • Get-JITTableRows     — continuation paging. A dropped page means the
#                            expiry timer never sees a rule and it is never
#                            revoked.
#   • ConvertTo-JITUtc     — one UTC reading of ExpiryUtc, so the grant path
#                            and the timer cannot disagree about "expired".
#
# These are pure/mocked unit tests: nothing touches the network.
#
# The X-Forwarded-For cases below are the strings MEASURED against a real Azure
# App Service (Linux, westus2, 2026-10-27, throwaway echo app since deleted) —
# see the Resolve-JITCallerIp doc comment. 192.0.2.10 stands in for the probe
# machine's real public IP. They are reproduced verbatim so this suite fails if
# anyone reverts to reading the leftmost entry.
#
# Run:  ./test.ps1 -Target JITHelpers.Security

BeforeAll {

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force

# A request shaped like the Functions worker's $Request: a Headers map plus the
# HttpContext chain Resolve-JITCallerIp falls back to.
function script:New-Request {
    param([string]$ForwardedFor, [string]$SocketIp = '198.51.100.1')

    $headers = @{}
    if ($PSBoundParameters.ContainsKey('ForwardedFor')) {
        $headers['X-Forwarded-For'] = $ForwardedFor
    }

    $connection = if ($SocketIp) {
        [PSCustomObject]@{ RemoteIpAddress = $SocketIp }
    } else { $null }

    return [PSCustomObject]@{
        Headers     = $headers
        HttpContext = [PSCustomObject]@{ Connection = $connection }
    }
}

# One Table Storage page: rows plus the continuation headers that say whether
# another page follows.
function script:New-TablePage {
    param([object[]]$Rows = @(), [string]$NextPartitionKey, [string]$NextRowKey)

    $headers = @{}
    if ($NextPartitionKey) { $headers['x-ms-continuation-NextPartitionKey'] = $NextPartitionKey }
    if ($NextRowKey)       { $headers['x-ms-continuation-NextRowKey']       = $NextRowKey }

    return @{
        StatusCode = 200
        Headers    = $headers
        Content    = (@{ value = $Rows } | ConvertTo-Json -Depth 6)
    }
}

}   # end BeforeAll

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Resolve-JITCallerIp' {

    BeforeEach {
        Remove-Item Env:\JIT_TRUSTED_XFF_DEPTH -ErrorAction SilentlyContinue
    }
    AfterEach {
        Remove-Item Env:\JIT_TRUSTED_XFF_DEPTH -ErrorAction SilentlyContinue
    }

    Context 'measured App Service chains' {

        It 'takes the platform-appended entry and strips its port when the client sent nothing' {
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '192.0.2.10:65221')
            $r.IpAddress  | Should -Be '192.0.2.10'
            $r.Spoofed    | Should -BeFalse
            $r.EntryCount | Should -Be 1
        }

        It 'ignores a client-supplied leftmost entry and reads the rightmost' {
            # THE VULNERABILITY: reading entries[0] here returns 203.0.113.50,
            # the attacker's chosen address, and that is what gets allowlisted.
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '203.0.113.50, 192.0.2.10:65224')
            $r.IpAddress | Should -Be '192.0.2.10'
            $r.ClaimedIp | Should -Be '203.0.113.50'
            $r.Spoofed   | Should -BeTrue
        }

        It 'still reads the rightmost entry when the client sent two of its own' {
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '203.0.113.50, 198.51.100.77, 192.0.2.10:65227')
            $r.IpAddress  | Should -Be '192.0.2.10'
            $r.ClaimedIp  | Should -Be '203.0.113.50'
            $r.Spoofed    | Should -BeTrue
            $r.EntryCount | Should -Be 3
        }

        It 'survives the empty element a trailing comma produces' {
            # App Service appends after the client's trailing comma, giving
            # "203.0.113.50,, 192.0.2.10:57877". The empty element must be
            # dropped rather than counted or returned.
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '203.0.113.50,, 192.0.2.10:57877')
            $r.IpAddress  | Should -Be '192.0.2.10'
            $r.Spoofed    | Should -BeTrue
            $r.EntryCount | Should -Be 2
        }
    }

    Context 'trusted proxy depth' {

        It 'skips one extra hop when JIT_TRUSTED_XFF_DEPTH is 1' {
            $env:JIT_TRUSTED_XFF_DEPTH = '1'
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '203.0.113.50, 192.0.2.10:443')
            $r.IpAddress | Should -Be '203.0.113.50'
            $r.Spoofed   | Should -BeFalse
        }

        It 'flags a chain longer than the configured depth allows' {
            $env:JIT_TRUSTED_XFF_DEPTH = '1'
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '10.9.9.9, 203.0.113.50, 192.0.2.10:443')
            $r.IpAddress | Should -Be '203.0.113.50'
            $r.Spoofed   | Should -BeTrue
        }

        It 'treats a negative depth as 0 rather than indexing off the end' {
            $env:JIT_TRUSTED_XFF_DEPTH = '-5'
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '192.0.2.10:65221')
            $r.IpAddress | Should -Be '192.0.2.10'
        }
    }

    Context 'fallbacks' {

        It 'uses the socket remote address when no X-Forwarded-For is present' {
            $r = Resolve-JITCallerIp -Request (New-Request)
            $r.IpAddress  | Should -Be '198.51.100.1'
            $r.Spoofed    | Should -BeFalse
            $r.EntryCount | Should -Be 0
        }

        It 'falls back to the socket address when the header is present but empty' {
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor ' , ')
            $r.IpAddress | Should -Be '198.51.100.1'
            $r.Spoofed   | Should -BeFalse
        }

        It 'returns a null IP rather than throwing when nothing identifies the caller' {
            $r = Resolve-JITCallerIp -Request (New-Request -SocketIp '')
            $r.IpAddress | Should -BeNullOrEmpty
        }

        It 'unwraps an [ipv6]:port entry' {
            $r = Resolve-JITCallerIp -Request (New-Request -ForwardedFor '[2001:db8::1]:51234')
            $r.IpAddress | Should -Be '2001:db8::1'
        }
    }

    It 'Get-CallerIp returns the same trusted address, not the claimed one' {
        $request = New-Request -ForwardedFor '203.0.113.50, 192.0.2.10:65224'
        Get-CallerIp -Request $request | Should -Be '192.0.2.10'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-JITTableRows continuation paging' {

    It 'returns rows from a single page when no continuation token is sent' {
        Mock -ModuleName JITHelpers Invoke-TableRestRaw {
            New-TablePage -Rows @(@{ RowKey = 'a' }, @{ RowKey = 'b' })
        }
        $rows = Get-JITTableRows -TableName 'JITRules'
        $rows.Count | Should -Be 2
    }

    It 'follows the continuation token across two pages and returns every row' {
        # THE BUG: Invoke-RestMethod discards response headers, so the caller
        # only ever saw page one and the timer never revoked anything past it.
        $script:Calls = 0
        Mock -ModuleName JITHelpers Invoke-TableRestRaw {
            $script:Calls++
            if ($script:Calls -eq 1) {
                New-TablePage -Rows @(@{ RowKey = 'page1-a' }, @{ RowKey = 'page1-b' }) `
                              -NextPartitionKey 'pk2' -NextRowKey 'rk2'
            } else {
                New-TablePage -Rows @(@{ RowKey = 'page2-a' })
            }
        }

        $rows = Get-JITTableRows -TableName 'JITRules'

        $script:Calls | Should -Be 2
        $rows.Count   | Should -Be 3
        @($rows.RowKey) | Should -Contain 'page2-a'
    }

    It 'passes the continuation keys back on the follow-up request' {
        $script:Queries = @()
        Mock -ModuleName JITHelpers Invoke-TableRestRaw {
            $script:Queries += $Query
            if ($script:Queries.Count -eq 1) {
                New-TablePage -Rows @(@{ RowKey = 'a' }) -NextPartitionKey 'pk 2' -NextRowKey 'rk/2'
            } else {
                New-TablePage -Rows @()
            }
        }

        Get-JITTableRows -TableName 'JITRules' | Out-Null

        # Opaque tokens can contain characters that are not URL-safe.
        $script:Queries[1] | Should -Match 'NextPartitionKey=pk%202'
        $script:Queries[1] | Should -Match 'NextRowKey=rk%2F2'
    }

    It 'keeps paging when a FILTERED page comes back empty but carries a token' {
        # A filtered scan can return an empty page with a continuation token
        # when the match lives further on. Stopping here is how Revoke-JITAccess
        # used to 404 on a rule that exists.
        $script:Calls = 0
        Mock -ModuleName JITHelpers Invoke-TableRestRaw {
            $script:Calls++
            if ($script:Calls -eq 1) {
                New-TablePage -Rows @() -NextPartitionKey 'pk2' -NextRowKey 'rk2'
            } else {
                New-TablePage -Rows @(@{ RowKey = 'found-on-page-2' })
            }
        }

        $rows = Get-JITTableRows -TableName 'JITRules' -Filter "RowKey eq 'found-on-page-2'"

        $script:Calls   | Should -Be 2
        $rows.Count     | Should -Be 1
        $rows[0].RowKey | Should -Be 'found-on-page-2'
    }

    It 'stops at the MaxPages cap and warns loudly that the result is incomplete' {
        Mock -ModuleName JITHelpers Invoke-TableRestRaw {
            # Never stops offering another page.
            New-TablePage -Rows @(@{ RowKey = 'x' }) -NextPartitionKey 'pk' -NextRowKey 'rk'
        }

        $warnings = @()
        $rows = Get-JITTableRows -TableName 'JITRules' -MaxPages 3 -WarningVariable warnings -WarningAction SilentlyContinue

        $rows.Count | Should -Be 3
        Should -Invoke -CommandName Invoke-TableRestRaw -ModuleName JITHelpers -Exactly -Times 3 -Scope It
        ($warnings -join ' ') | Should -Match 'RESULTS ARE INCOMPLETE'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-JITUtc' {

    It 'reads a Z-suffixed timestamp as UTC' {
        $v = ConvertTo-JITUtc '2026-01-02T03:04:05Z'
        $v.Kind | Should -Be ([DateTimeKind]::Utc)
        $v.Hour | Should -Be 3
    }

    It 'assumes UTC for an offset-less timestamp rather than local time' {
        # The column is ExpiryUtc. [DateTime]::Parse would have produced a
        # LOCAL-kind value here, which is what made the grant path and the
        # timer disagree about what had expired on any non-UTC host.
        $v = ConvertTo-JITUtc '2026-01-02T03:04:05'
        $v.Kind | Should -Be ([DateTimeKind]::Utc)
        $v.Hour | Should -Be 3
    }

    It 'converts an offset-bearing timestamp to the same instant in UTC' {
        $v = ConvertTo-JITUtc '2026-01-02T08:04:05+05:00'
        $v.Kind | Should -Be ([DateTimeKind]::Utc)
        $v.Hour | Should -Be 3
    }

    It 'agrees with the timer on a round-tripped ExpiryUtc value' {
        # The exact round trip the rows take: written with .ToString('o'),
        # read back by both the timer and the grant path.
        $written = ([DateTime]::UtcNow).ToString('o')
        $a = ConvertTo-JITUtc $written
        $b = [DateTimeOffset]::Parse($written).UtcDateTime
        $a.ToString('o') | Should -Be $b.ToString('o')
    }

    It 'returns $null for an unparseable value instead of throwing' {
        ConvertTo-JITUtc 'not-a-date' | Should -BeNullOrEmpty
    }

    It 'returns $null for empty and whitespace input' {
        ConvertTo-JITUtc ''    | Should -BeNullOrEmpty
        ConvertTo-JITUtc '   ' | Should -BeNullOrEmpty
    }
}
