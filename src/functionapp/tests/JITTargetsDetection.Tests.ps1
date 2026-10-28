# Tests for the pure IP-detection helpers in JITTargets\Targets\_Shared.ps1
# (FEAT-0003, item 4):
#   • ConvertTo-JITIpv4Number       — dotted-quad IPv4 -> comparable [int64]
#   • Test-JITFirewallRuleCoversIp  — "is this IP already inside an existing
#                                     firewall rule's [start,end] range?"
#
# Both are module-INTERNAL (script:-scoped in _Shared.ps1, NOT exported by
# JITTargets.psm1), so tests reach them via `InModuleScope JITTargets { ... }`,
# which runs the call inside the module's session state. These are pure functions
# — no ARM, no network, no Az.* — so nothing is mocked here.
#
# Pester 3.4.0 compatible (no BeforeAll at top level, no Should -Verb syntax).
#
# Run:  Invoke-Pester ./src/functionapp/tests/JITTargetsDetection.Tests.ps1

Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1" -Force

# ─────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-JITIpv4Number' {

    It 'orders addresses so numeric compare == address compare' {
        InModuleScope JITTargets {
            (ConvertTo-JITIpv4Number '10.0.0.1') -lt (ConvertTo-JITIpv4Number '10.0.0.2') | Should -Be $true
            (ConvertTo-JITIpv4Number '10.0.1.0') -gt (ConvertTo-JITIpv4Number '10.0.0.255') | Should -Be $true
        }
    }

    It 'computes the big-endian value of a low-octet address' {
        InModuleScope JITTargets {
            # 1.2.3.4 = (1<<24)+(2<<16)+(3<<8)+4 = 16909060
            ConvertTo-JITIpv4Number '1.2.3.4' | Should -Be 16909060
        }
    }

    It 'handles first octets above 127 without int32 sign overflow (int64 correctness)' {
        InModuleScope JITTargets {
            # 200.0.0.0 = 200<<24 = 3355443200, which overflows a signed int32 —
            # the helper must use int64 so the value stays positive and comparable.
            ConvertTo-JITIpv4Number '200.0.0.0' | Should -Be 3355443200
            (ConvertTo-JITIpv4Number '200.0.0.0') -gt (ConvertTo-JITIpv4Number '127.255.255.255') | Should -Be $true
        }
    }

    It 'computes the maximum address value (255.255.255.255)' {
        InModuleScope JITTargets {
            ConvertTo-JITIpv4Number '255.255.255.255' | Should -Be 4294967295
        }
    }

    It 'returns $null for a null/empty input' {
        InModuleScope JITTargets {
            ConvertTo-JITIpv4Number $null | Should -BeNullOrEmpty
            ConvertTo-JITIpv4Number ''    | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for a non-IPv4 (IPv6) address' {
        InModuleScope JITTargets {
            ConvertTo-JITIpv4Number '2001:db8::1' | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for garbage / non-address strings' {
        InModuleScope JITTargets {
            ConvertTo-JITIpv4Number 'not-an-ip'   | Should -BeNullOrEmpty
            ConvertTo-JITIpv4Number '10.0.0.1/24' | Should -BeNullOrEmpty
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Rule objects are built INSIDE the InModuleScope block (PSCustomObject
# construction works fine there), avoiding any cross-scope hand-off — Pester
# 3.4's InModuleScope has no -Parameters, so this is the clean way to feed data
# to a module-internal function under test. A local New-SqlRule helper (SQL-style
# .properties.startIpAddress/.endIpAddress shape) is defined per block.
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Test-JITFirewallRuleCoversIp' {

    It 'returns $true when the IP is inside an existing [start,end] range' {
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @(New-SqlRule '10.0.0.1' '10.0.0.100')
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '10.0.0.50' | Should -Be $true
        }
    }

    It 'returns $true when the IP equals the range start boundary' {
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @(New-SqlRule '10.0.0.1' '10.0.0.100')
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '10.0.0.1' | Should -Be $true
        }
    }

    It 'returns $true when the IP equals the range end boundary' {
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @(New-SqlRule '10.0.0.1' '10.0.0.100')
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '10.0.0.100' | Should -Be $true
        }
    }

    It 'returns $true for an exact single-IP rule (start == end == ip)' {
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @(New-SqlRule '203.0.113.7' '203.0.113.7')
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '203.0.113.7' | Should -Be $true
        }
    }

    It 'returns $false when the IP is outside every range' {
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @(New-SqlRule '10.0.0.1' '10.0.0.100')
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '10.0.0.200' | Should -Be $false
        }
    }

    It 'returns $false against an empty rule collection' {
        InModuleScope JITTargets {
            Test-JITFirewallRuleCoversIp -Rules @() -CallerIp '10.0.0.1' | Should -Be $false
        }
    }

    It 'matches correctly across high-octet ranges (int64 correctness)' {
        # 200.0.0.0 – 200.0.0.255 overflows int32; the helper must still contain 200.0.0.50.
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @(New-SqlRule '200.0.0.0' '200.0.0.255')
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '200.0.0.50'  | Should -Be $true
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '201.0.0.0'   | Should -Be $false
        }
    }

    It 'returns $false for a non-IPv4 caller IP (falls back to create a rule)' {
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @(New-SqlRule '10.0.0.1' '10.0.0.100')
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '2001:db8::1' | Should -Be $false
        }
    }

    It 'skips rules whose bounds are unparseable and keeps checking the rest' {
        InModuleScope JITTargets {
            function New-SqlRule ($s, $e) { [PSCustomObject]@{ properties = [PSCustomObject]@{ startIpAddress = $s; endIpAddress = $e } } }
            $rules = @((New-SqlRule 'garbage' 'also-garbage'), (New-SqlRule '10.0.0.1' '10.0.0.100'))
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '10.0.0.50' | Should -Be $true
        }
    }

    # ── Redis field-name variant (startIP / endIP) ─────────────────────────────

    It 'honors custom StartField/EndField names (Redis startIP/endIP)' {
        InModuleScope JITTargets {
            $rules = @([PSCustomObject]@{ properties = [PSCustomObject]@{ startIP = '10.0.0.1'; endIP = '10.0.0.100' } })
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '10.0.0.50' `
                -StartField 'startIP' -EndField 'endIP' | Should -Be $true
        }
    }

    It 'reads bounds off the item directly when it has no .properties wrapper' {
        # The helper falls back to the item itself when $r.properties is absent.
        InModuleScope JITTargets {
            $rules = @([PSCustomObject]@{ startIpAddress = '10.0.0.1'; endIpAddress = '10.0.0.100' })
            Test-JITFirewallRuleCoversIp -Rules $rules -CallerIp '10.0.0.50' | Should -Be $true
        }
    }
}
