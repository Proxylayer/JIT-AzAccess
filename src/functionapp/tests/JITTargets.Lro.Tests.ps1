# Tests for Wait-JITArmAsyncOperation — the shared long-running-operation
# poller in JITTargets\Targets\_Shared.ps1.
#
# Why this matters more than it looks: every Add handler that writes through a
# 202 (the four child-rule types directly, the twelve array types via
# Invoke-JITArmReadModifyWrite) decides "did the grant land?" on what this
# poller returns. A poller that reports a SUCCESSFUL operation as a failure
# makes Request-JITAccess roll back a rule that exists — and before the
# reservation retention added alongside these tests, that left the rule live
# with nothing tracking it.
#
# The poller is module-internal, so tests reach it with InModuleScope and mock
# the ARM layer with -ModuleName JITTargets. Start-Sleep is mocked too, or each
# case would take its poll interval in real seconds.
#
# Run:  ./test.ps1 -Target JITTargets.Lro

BeforeAll {

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

}   # end BeforeAll

Describe 'Wait-JITArmAsyncOperation' {

    BeforeEach {
        $global:LroPolls     = 0
        $global:LroResponses = @()
        Mock -ModuleName JITTargets Start-Sleep { }
        Mock -ModuleName JITTargets Invoke-ArmRestRaw {
            $i = $global:LroPolls
            $global:LroPolls++
            # Repeat the last scripted response once the list runs out, so a
            # test can model "never finishes" with a single entry.
            $idx = [Math]::Min($i, $global:LroResponses.Count - 1)
            return $global:LroResponses[$idx]
        }
    }

    AfterEach {
        Remove-Variable -Name LroPolls     -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name LroResponses -Scope Global -ErrorAction SilentlyContinue
    }

    Context 'Azure-AsyncOperation shape (a JSON status field)' {

        It 'returns once the operation reports Succeeded' {
            $global:LroResponses = @(
                @{ StatusCode = 200; Headers = @{}; Content = '{"status":"InProgress"}' },
                @{ StatusCode = 200; Headers = @{}; Content = '{"status":"Succeeded"}' }
            )
            InModuleScope JITTargets {
                { Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Azure-AsyncOperation' = 'https://arm/op/1' } `
                    -TimeoutSeconds 60 -DefaultPollSeconds 1 } | Should -Not -Throw
            }
            $global:LroPolls | Should -Be 2
        }

        It 'throws when the operation reports Failed' {
            $global:LroResponses = @(@{ StatusCode = 200; Headers = @{}; Content = '{"status":"Failed","error":{"code":"Boom"}}' })
            InModuleScope JITTargets {
                { Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Azure-AsyncOperation' = 'https://arm/op/1' } `
                    -TimeoutSeconds 60 -DefaultPollSeconds 1 } | Should -Throw -ExpectedMessage '*failed*'
            }
        }

        It 'throws when the operation reports Canceled' {
            $global:LroResponses = @(@{ StatusCode = 200; Headers = @{}; Content = '{"status":"Canceled"}' })
            InModuleScope JITTargets {
                { Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Azure-AsyncOperation' = 'https://arm/op/1' } `
                    -TimeoutSeconds 60 -DefaultPollSeconds 1 } | Should -Throw -ExpectedMessage '*canceled*'
            }
        }

        It 'does not mistake a 200 carrying InProgress for completion' {
            # The status field wins over the HTTP code when both are present.
            $global:LroResponses = @(
                @{ StatusCode = 200; Headers = @{}; Content = '{"status":"InProgress"}' },
                @{ StatusCode = 200; Headers = @{}; Content = '{"status":"InProgress"}' },
                @{ StatusCode = 200; Headers = @{}; Content = '{"status":"Succeeded"}' }
            )
            InModuleScope JITTargets {
                Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Azure-AsyncOperation' = 'https://arm/op/1' } `
                    -TimeoutSeconds 60 -DefaultPollSeconds 1
            }
            $global:LroPolls | Should -Be 3
        }
    }

    Context 'Location shape (no JSON status, the HTTP code is the signal)' {

        It 'treats a 200 with no status field as completion' {
            # THE BUG: reading only the JSON meant this never looked finished,
            # so a successful operation polled until the timeout and was
            # reported as a failure.
            $global:LroResponses = @(
                @{ StatusCode = 202; Headers = @{}; Content = '' },
                @{ StatusCode = 200; Headers = @{}; Content = '{"id":"/subscriptions/x/..."}' }
            )
            InModuleScope JITTargets {
                { Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Location' = 'https://arm/loc/1' } `
                    -TimeoutSeconds 60 -DefaultPollSeconds 1 } | Should -Not -Throw
            }
            $global:LroPolls | Should -Be 2
        }

        It 'treats a 204 with an empty body as completion' {
            $global:LroResponses = @(@{ StatusCode = 204; Headers = @{}; Content = '' })
            InModuleScope JITTargets {
                { Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Location' = 'https://arm/loc/1' } `
                    -TimeoutSeconds 60 -DefaultPollSeconds 1 } | Should -Not -Throw
            }
            $global:LroPolls | Should -Be 1
        }

        It 'keeps polling while the poll URL answers 202' {
            $global:LroResponses = @(
                @{ StatusCode = 202; Headers = @{}; Content = '' },
                @{ StatusCode = 202; Headers = @{}; Content = '' },
                @{ StatusCode = 201; Headers = @{}; Content = '' }
            )
            InModuleScope JITTargets {
                Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Location' = 'https://arm/loc/1' } `
                    -TimeoutSeconds 60 -DefaultPollSeconds 1
            }
            $global:LroPolls | Should -Be 3
        }
    }

    Context 'unresolved outcome' {

        It 'marks a timeout as UNRESOLVED, not as a failure' {
            # The distinction is load-bearing: Request-JITAccess keeps its
            # reservation row on this sentinel so the cleanup timer reconciles
            # a rule that may have been created after we stopped looking.
            # Without it the slot is released and the rule is orphaned.
            $global:LroResponses = @(@{ StatusCode = 202; Headers = @{}; Content = '' })
            InModuleScope JITTargets {
                { Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Location' = 'https://arm/loc/1' } `
                    -TimeoutSeconds 2 -DefaultPollSeconds 1 } |
                    Should -Throw -ExpectedMessage 'ARM_LRO_UNRESOLVED:*'
            }
        }

        It 'does NOT mark a definite failure as unresolved' {
            # A Failed operation created nothing, so the caller is free to
            # release its reservation.
            $global:LroResponses = @(@{ StatusCode = 200; Headers = @{}; Content = '{"status":"Failed"}' })
            $message = InModuleScope JITTargets {
                try {
                    Wait-JITArmAsyncOperation -ResponseHeaders @{ 'Azure-AsyncOperation' = 'https://arm/op/1' } `
                        -TimeoutSeconds 60 -DefaultPollSeconds 1
                    return ''
                }
                catch { return $_.Exception.Message }
            }
            $message | Should -Not -BeNullOrEmpty
            $message | Should -Not -BeLike 'ARM_LRO_UNRESOLVED:*'
        }

        It 'throws when a 202 carries neither header to poll' {
            InModuleScope JITTargets {
                { Wait-JITArmAsyncOperation -ResponseHeaders @{} -TimeoutSeconds 60 } |
                    Should -Throw -ExpectedMessage '*no Azure-AsyncOperation or Location header*'
            }
        }
    }
}
