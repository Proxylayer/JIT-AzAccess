# Tests for Invoke-JITArmReadModifyWrite — the shared ETag optimistic-concurrency
# read-modify-write helper in JITTargets\Targets\_Shared.ps1 (FEAT-0002).
#
# The helper is module-INTERNAL (defined in _Shared.ps1, NOT exported by
# JITTargets.psm1), so tests reach it via `InModuleScope JITTargets { ... }`,
# which runs the call inside the module's session state. The ARM layer it drives
# (Invoke-ArmRestRaw, the LRO poller Wait-JITArmAsyncOperation, and the status
# extractor Get-StatusFromError) is mocked with `-ModuleName JITTargets` so the
# mocks intercept the calls the helper makes from inside the module.
#
# HttpHelpers is imported (globally) so Invoke-ArmRestRaw / Get-StatusFromError
# exist and are therefore mockable in the JITTargets scope; JITTargets is imported
# so the helper and Wait-JITArmAsyncOperation exist. No network / Az.* is touched.
#
# Pester 3.4.0 compatible — Assert-MockCalled uses -Scope It. Cross-scope mutable
# state (call counters, the served ETag) is held in $global:* so mock scriptblocks
# running in the module scope can share it with the test; reset in BeforeEach.
#
# Run:  Invoke-Pester ./src/functionapp/tests/JITArmReadModifyWrite.Tests.ps1

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

Describe 'Invoke-JITArmReadModifyWrite' {

    BeforeEach {
        $global:RmwEtag       = '"etag-v1"'
        $global:RmwGetCount   = 0
        $global:RmwWriteCount = 0

        # Default: never actually poll (each LRO test asserts the delegation instead).
        Mock -ModuleName JITTargets Wait-JITArmAsyncOperation { }

        # Default happy ARM layer: GET returns a resource + ETag; write is a
        # synchronous 200 with no async header. Individual tests override this.
        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            if ($Method -eq 'GET') {
                $global:RmwGetCount++
                return @{
                    StatusCode = 200
                    Headers    = @{ ETag = $global:RmwEtag }
                    Content    = '{"properties":{"ipRules":[{"ipAddressOrRange":"1.1.1.1"}]}}'
                }
            }
            $global:RmwWriteCount++
            return @{ StatusCode = 200; Headers = @{}; Content = '' }
        }
    }

    # ── (a) Happy path: GET -> write, If-Match carries the ETag, no LRO poll ────

    It 'GETs, writes back with If-Match set to the GET ETag, and reports Changed' {
        InModuleScope JITTargets {
            $r = Invoke-JITArmReadModifyWrite `
                -Path '/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/acct' `
                -ApiVersion '2024-11-15' -WriteMethod PATCH -Modify {
                    param($resource)
                    return @{ properties = @{ ipRules = @(@{ ipAddressOrRange = '2.2.2.2' }) } }
                }
            $r.Changed | Should -Be $true
        }
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter {
            $Method -eq 'GET'
        }
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter {
            $Method -eq 'PATCH' -and $ExtraHeaders['If-Match'] -eq '"etag-v1"'
        }
    }

    It 'does not poll an async operation for a synchronous 200 write' {
        InModuleScope JITTargets {
            Invoke-JITArmReadModifyWrite -Path '/x' -ApiVersion '2024-11-15' -Modify {
                param($resource) return @{ properties = @{ ipRules = @(@{ ipAddressOrRange = '2.2.2.2' }) } }
            } | Out-Null
        }
        Should -Invoke -CommandName Wait-JITArmAsyncOperation -ModuleName JITTargets -Exactly -Times 0 -Scope It
    }

    # ── (b) 412 on first write -> re-GET -> second write succeeds ───────────────

    It 'retries after a 412 (re-GET then write) and converges within MaxAttempts' {
        Mock -ModuleName JITTargets Get-StatusFromError { return 412 }
        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            if ($Method -eq 'GET') {
                $global:RmwGetCount++
                return @{
                    StatusCode = 200
                    Headers    = @{ ETag = "`"etag-$($global:RmwGetCount)`"" }
                    Content    = '{"properties":{"ipRules":[]}}'
                }
            }
            $global:RmwWriteCount++
            if ($global:RmwWriteCount -eq 1) { throw 'ARM precondition failed (412)' }
            return @{ StatusCode = 200; Headers = @{}; Content = '' }
        }

        InModuleScope JITTargets {
            $r = Invoke-JITArmReadModifyWrite -Path '/x' -ApiVersion '2024-11-15' -Modify {
                param($resource) return @{ properties = @{ ipRules = @(@{ ipAddressOrRange = '9.9.9.9' }) } }
            }
            $r.Changed | Should -Be $true
        }

        # Re-GET happened (GET twice) and it converged in exactly 2 write attempts (<=5).
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 2 -Scope It -ParameterFilter { $Method -eq 'GET' }
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 2 -Scope It -ParameterFilter { $Method -eq 'PATCH' }
    }

    It 'sends the re-read ETag on the retry write after a 412' {
        Mock -ModuleName JITTargets Get-StatusFromError { return 412 }
        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            if ($Method -eq 'GET') {
                $global:RmwGetCount++
                return @{
                    StatusCode = 200
                    Headers    = @{ ETag = "`"etag-$($global:RmwGetCount)`"" }
                    Content    = '{"properties":{"ipRules":[]}}'
                }
            }
            $global:RmwWriteCount++
            if ($global:RmwWriteCount -eq 1) { throw 'ARM precondition failed (412)' }
            return @{ StatusCode = 200; Headers = @{}; Content = '' }
        }

        InModuleScope JITTargets {
            Invoke-JITArmReadModifyWrite -Path '/x' -ApiVersion '2024-11-15' -Modify {
                param($resource) return @{ properties = @{ ipRules = @(@{ ipAddressOrRange = '9.9.9.9' }) } }
            } | Out-Null
        }
        # First write carried etag-1, the surviving (retry) write carried etag-2.
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter {
            $Method -eq 'PATCH' -and $ExtraHeaders['If-Match'] -eq '"etag-2"'
        }
    }

    # ── (c) -Modify returns $false => skip: no write attempted ─────────────────

    It 'does not write when -Modify returns $false (skip-when-open)' {
        InModuleScope JITTargets {
            $r = Invoke-JITArmReadModifyWrite -Path '/x' -ApiVersion '2024-11-15' -Modify {
                param($resource) return $false
            }
            $r.Changed | Should -Be $false
        }
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 1 -Scope It -ParameterFilter { $Method -eq 'GET' }
        Should -Invoke -CommandName Invoke-ArmRestRaw -ModuleName JITTargets -Exactly -Times 0 -Scope It -ParameterFilter { $Method -ne 'GET' }
        Should -Invoke -CommandName Wait-JITArmAsyncOperation -ModuleName JITTargets -Exactly -Times 0 -Scope It
    }

    # ── (d) LRO: 202 Accepted -> poll to completion ────────────────────────────

    It 'polls to completion when the write returns 202 Accepted' {
        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            if ($Method -eq 'GET') {
                return @{ StatusCode = 200; Headers = @{ ETag = $global:RmwEtag }; Content = '{"properties":{"ipRules":[]}}' }
            }
            return @{ StatusCode = 202; Headers = @{ 'Azure-AsyncOperation' = 'https://management.azure.com/poll' }; Content = '' }
        }
        InModuleScope JITTargets {
            Invoke-JITArmReadModifyWrite -Path '/x' -ApiVersion '2024-11-15' -Modify {
                param($resource) return @{ properties = @{ ipRules = @(@{ ipAddressOrRange = '3.3.3.3' }) } }
            } | Out-Null
        }
        Should -Invoke -CommandName Wait-JITArmAsyncOperation -ModuleName JITTargets -Exactly -Times 1 -Scope It
    }

    # ── (d) LRO: 200 that still carries an Azure-AsyncOperation header -> poll ──

    It 'polls to completion when a 200 write carries an Azure-AsyncOperation header' {
        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            if ($Method -eq 'GET') {
                return @{ StatusCode = 200; Headers = @{ ETag = $global:RmwEtag }; Content = '{"properties":{"ipRules":[]}}' }
            }
            return @{ StatusCode = 200; Headers = @{ 'Azure-AsyncOperation' = 'https://management.azure.com/poll' }; Content = '' }
        }
        InModuleScope JITTargets {
            Invoke-JITArmReadModifyWrite -Path '/x' -ApiVersion '2024-11-15' -Modify {
                param($resource) return @{ properties = @{ ipRules = @(@{ ipAddressOrRange = '3.3.3.3' }) } }
            } | Out-Null
        }
        Should -Invoke -CommandName Wait-JITArmAsyncOperation -ModuleName JITTargets -Exactly -Times 1 -Scope It
    }
}
