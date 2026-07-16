# Tests for the "Runtime Configuration Derivation" helpers in JITHelpers.psm1
#
# Covers the mostly-pure "env var wins, else derive" helpers:
#   • Get-JitSubscriptionId  — env / WEBSITE_OWNER_NAME parse / IMDS fallback
#   • Get-JitResourceGroup   — env / WEBSITE_RESOURCE_GROUP fallback
#   • Get-JitSiteName        — env / WEBSITE_SITE_NAME fallback
#   • Get-JitSiteResourceId  — env / assembled from sub+rg+site
#   • Get-JitTenantId        — env / MI token 'tid' claim decode
#   • Test-CallerHasJitRequesterRole — denies when the role GUID won't resolve
#
# These are unit tests: IMDS and the MI token fetch are mocked so nothing
# touches the network. Private Get-JitInstanceMetadata and the imported
# Get-ManagedIdentityToken are mocked inside the module scope.
#
# Pester 3.4.0 compatible (no BeforeAll at top level, no Should -Verb syntax).
#
# Run:  Invoke-Pester ./src/functionapp/tests/JITHelpers.Derivation.Tests.ps1

# HttpHelpers exports Get-ManagedIdentityToken, which Get-JitTenantId calls and
# expects to be present in the global scope at runtime. Load it first so the
# command exists and can be mocked inside the JITHelpers module scope.
Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1" -Force

# Distinct dummy GUIDs so it is unambiguous which source a value came from.
$script:EnvSub    = '11111111-1111-1111-1111-111111111111'
$script:OwnerSub  = '22222222-2222-2222-2222-222222222222'
$script:ImdsSub   = '33333333-3333-3333-3333-333333333333'
$script:EnvTenant = '44444444-4444-4444-4444-444444444444'
$script:TidTenant = '55555555-5555-5555-5555-555555555555'

function script:ConvertTo-Base64Url ([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes) -replace '\+', '-' -replace '/', '_' -replace '=+$', ''
}

# Build an unsigned-style JWT "header.payload.sig" whose payload carries the
# given claims. Only the payload segment is consumed by Get-JitTenantId.
function script:New-TidJwt ([hashtable]$Claims) {
    $headerJson  = @{ alg = 'RS256'; typ = 'JWT' } | ConvertTo-Json -Compress
    $payloadJson = $Claims | ConvertTo-Json -Compress
    $h = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($headerJson))
    $p = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payloadJson))
    return "$h.$p.signature"
}

# Clear the env vars these helpers consult, plus the per-worker derived caches,
# so each test runs from a known-empty baseline.
function script:Reset-DerivationState {
    foreach ($v in @(
        'JIT_SUBSCRIPTION_ID', 'JIT_RESOURCE_GROUP', 'JIT_SITE_NAME',
        'JIT_SITE_RESOURCE_ID', 'AZURE_TENANT_ID',
        'WEBSITE_OWNER_NAME', 'WEBSITE_RESOURCE_GROUP', 'WEBSITE_SITE_NAME'
    )) {
        Remove-Item "Env:\$v" -ErrorAction SilentlyContinue
    }
    InModuleScope JITHelpers {
        $script:DerivedSubscriptionId = $null
        $script:DerivedTenantId       = $null
        $script:JitRoleDefIdCache     = @{}
        $script:RoleCheckCache        = @{}
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-JitSubscriptionId' {

    BeforeEach { Reset-DerivationState }
    AfterEach  { Reset-DerivationState }

    It 'returns JIT_SUBSCRIPTION_ID when the env var is set (env wins)' {
        $env:JIT_SUBSCRIPTION_ID = $script:EnvSub
        # A parseable WEBSITE_OWNER_NAME must NOT override the explicit env var.
        $env:WEBSITE_OWNER_NAME  = "$script:OwnerSub+my-rg-eastuswebspace"
        Get-JitSubscriptionId | Should Be $script:EnvSub
    }

    It 'parses the subscription GUID before the + from WEBSITE_OWNER_NAME' {
        $env:WEBSITE_OWNER_NAME = "$script:OwnerSub+my-rg-eastuswebspace"
        Get-JitSubscriptionId | Should Be $script:OwnerSub
    }

    It 'falls through to IMDS when WEBSITE_OWNER_NAME is not a GUID' {
        $env:WEBSITE_OWNER_NAME = 'not-a-guid+my-rg-eastuswebspace'
        Mock -ModuleName JITHelpers Get-JitInstanceMetadata {
            [PSCustomObject]@{ subscriptionId = '33333333-3333-3333-3333-333333333333' }
        }
        # Returning the IMDS value proves the IMDS fallback path was taken.
        Get-JitSubscriptionId | Should Be $script:ImdsSub
    }

    It 'falls through to IMDS when WEBSITE_OWNER_NAME is empty' {
        Mock -ModuleName JITHelpers Get-JitInstanceMetadata {
            [PSCustomObject]@{ subscriptionId = '33333333-3333-3333-3333-333333333333' }
        }
        Get-JitSubscriptionId | Should Be $script:ImdsSub
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-JitResourceGroup' {

    BeforeEach { Reset-DerivationState }
    AfterEach  { Reset-DerivationState }

    It 'returns JIT_RESOURCE_GROUP when set (env wins)' {
        $env:JIT_RESOURCE_GROUP     = 'rg-override'
        $env:WEBSITE_RESOURCE_GROUP = 'rg-platform'
        Get-JitResourceGroup | Should Be 'rg-override'
    }

    It 'falls back to WEBSITE_RESOURCE_GROUP when JIT_RESOURCE_GROUP is unset' {
        $env:WEBSITE_RESOURCE_GROUP = 'rg-platform'
        Get-JitResourceGroup | Should Be 'rg-platform'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-JitSiteName' {

    BeforeEach { Reset-DerivationState }
    AfterEach  { Reset-DerivationState }

    It 'returns JIT_SITE_NAME when set (env wins)' {
        $env:JIT_SITE_NAME     = 'site-override'
        $env:WEBSITE_SITE_NAME = 'site-platform'
        Get-JitSiteName | Should Be 'site-override'
    }

    It 'falls back to WEBSITE_SITE_NAME when JIT_SITE_NAME is unset' {
        $env:WEBSITE_SITE_NAME = 'site-platform'
        Get-JitSiteName | Should Be 'site-platform'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-JitSiteResourceId' {

    BeforeEach { Reset-DerivationState }
    AfterEach  { Reset-DerivationState }

    It 'returns JIT_SITE_RESOURCE_ID when set (env wins)' {
        $env:JIT_SITE_RESOURCE_ID = '/subscriptions/x/resourceGroups/y/providers/Microsoft.Web/sites/z'
        # These would otherwise be assembled, but the explicit id must win.
        $env:JIT_SUBSCRIPTION_ID  = $script:EnvSub
        $env:JIT_RESOURCE_GROUP   = 'rg-platform'
        $env:JIT_SITE_NAME        = 'site-platform'
        Get-JitSiteResourceId | Should Be '/subscriptions/x/resourceGroups/y/providers/Microsoft.Web/sites/z'
    }

    It 'assembles the resource id from the derived subscription, resource group, and site' {
        # Drive the three inputs via their own env-wins vars (no mocking needed).
        $env:JIT_SUBSCRIPTION_ID = $script:EnvSub
        $env:JIT_RESOURCE_GROUP  = 'rg-platform'
        $env:JIT_SITE_NAME       = 'site-platform'
        $expected = "/subscriptions/$script:EnvSub/resourceGroups/rg-platform/providers/Microsoft.Web/sites/site-platform"
        Get-JitSiteResourceId | Should Be $expected
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-JitTenantId' {

    BeforeEach { Reset-DerivationState }
    AfterEach  { Reset-DerivationState }

    It 'returns AZURE_TENANT_ID when set (env wins)' {
        $env:AZURE_TENANT_ID = $script:EnvTenant
        Get-JitTenantId | Should Be $script:EnvTenant
    }

    It 'decodes the tid claim from the MI ARM token when AZURE_TENANT_ID is unset' {
        $global:__JitTidJwt = New-TidJwt -Claims @{ tid = $script:TidTenant; oid = 'someone' }
        Mock -ModuleName JITHelpers Get-ManagedIdentityToken {
            return $global:__JitTidJwt
        }
        Get-JitTenantId | Should Be $script:TidTenant
        Remove-Variable -Name __JitTidJwt -Scope Global -ErrorAction SilentlyContinue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Test-CallerHasJitRequesterRole' {

    BeforeEach { Reset-DerivationState }
    AfterEach  { Reset-DerivationState }

    # Full authorization against live ARM is covered by integration testing; here
    # we only assert the cheap fail-closed path: if the 'JIT Requester' role
    # definition GUID cannot be resolved in the target subscription, access is
    # denied without ever querying role assignments.
    It 'denies when the JIT Requester role GUID cannot be resolved in the subscription' {
        Mock -ModuleName JITHelpers Get-JitRequesterRoleDefinitionGuid { $null }
        Test-CallerHasJitRequesterRole `
            -CallerObjectId '00000000-0000-0000-0000-0000000000aa' `
            -SubscriptionId $script:EnvSub | Should Be $false
    }
}
