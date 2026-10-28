# Tests for JITHelpers.psm1
#
# Covers:
#   • Invoke-JwtValidation — all claim checks + RS256 signature verification
#   • Get-AvailableNsgPriority — priority selection logic (pure function, no Azure calls)
#
# Test-CallerHasJitRequesterRole is integration-tested live (it hits ARM); not
# unit-tested here because mocking Get-AzAccessToken across module scopes is
# brittle.
#
# Pester 5+ (setup in BeforeAll, `Should -Verb` syntax). Everything below the
# BeforeAll runs at RUN time: a Describe body runs at DISCOVERY time in Pester
# 5, where none of this state would exist yet.
#
# Run:  Invoke-Pester ./src/functionapp/tests/JITHelpers.Tests.ps1

BeforeAll {

Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1" -Force

# ── In-memory RSA key pair used to sign and verify test JWTs ─────────────────
$script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
$script:Kid = 'test-key-1'

function script:ConvertTo-Base64Url ([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes) -replace '\+', '-' -replace '/', '_' -replace '=+$', ''
}

$pub = $script:Rsa.ExportParameters($false)
$script:Jwk = [PSCustomObject]@{
    kid = $script:Kid
    n   = ConvertTo-Base64Url $pub.Modulus
    e   = ConvertTo-Base64Url $pub.Exponent
}

function script:New-TestJwt {
    param(
        [hashtable] $Claims,
        [string]    $Alg = 'RS256',
        [string]    $Kid = $script:Kid
    )
    $headerJson  = @{ alg = $Alg; typ = 'JWT'; kid = $Kid } | ConvertTo-Json -Compress
    $payloadJson = $Claims | ConvertTo-Json -Compress
    $h = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($headerJson))
    $p = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payloadJson))
    $sigBytes = $script:Rsa.SignData(
        [Text.Encoding]::ASCII.GetBytes("$h.$p"),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    return "$h.$p.$(ConvertTo-Base64Url $sigBytes)"
}

function script:New-ValidClaims {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    return @{
        iss = 'https://sts.windows.net/test-tenant/'
        aud = 'https://management.azure.com/'
        tid = 'test-tenant'
        oid = '00000000-0000-0000-0000-000000000001'
        exp = $now + 3600
        nbf = $now - 10
    }
}

$script:VP = @{
    TenantId = 'test-tenant'
}

# Populate the JITHelpers module's JWKS cache with our test key so
# Invoke-JwtValidation never hits the network during tests.
function script:Set-TestJwksCache {
    param(
        [object[]]$Keys     = @($script:Jwk),
        [string]  $TenantId = 'test-tenant'
    )
    # The module's JWKS cache is keyed by tenant id:
    #   @{ <tenantId> = @{ Keys = [...]; FetchedAt = [DateTime] } }
    # Use $global: to bridge the test script scope -> module scope boundary.
    $global:__JITTestKeys   = $Keys
    $global:__JITTestTenant = $TenantId
    InModuleScope JITHelpers {
        $script:JwksCache = @{
            $global:__JITTestTenant = @{
                Keys      = $global:__JITTestKeys
                FetchedAt = [DateTime]::UtcNow
            }
        }
        # Clear the kid-miss force-refresh throttle so a rotation test is never
        # blocked by a forced refresh an earlier test already spent.
        $script:JwksForcedRefreshAt = @{}
    }
    Remove-Variable -Name __JITTestKeys   -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name __JITTestTenant -Scope Global -ErrorAction SilentlyContinue
}

}   # end BeforeAll

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Invoke-JwtValidation' {

    BeforeEach {
        Set-TestJwksCache
    }

    # ── Happy path ────────────────────────────────────────────────────────────

    It 'returns the decoded payload for a fully valid RS256 token' {
        $token  = New-TestJwt -Claims (New-ValidClaims)
        $result = Invoke-JwtValidation -Token $token @script:VP
        $result       | Should -Not -BeNullOrEmpty
        $result.oid   | Should -Be '00000000-0000-0000-0000-000000000001'
    }

    It 'accepts the v2.0 issuer URL format' {
        $claims       = New-ValidClaims
        $claims['iss'] = 'https://login.microsoftonline.com/test-tenant/v2.0'
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims $claims) @script:VP
        $result | Should -Not -BeNullOrEmpty
    }

    It 'accepts the trailing-slash variant of the ARM audience' {
        $claims        = New-ValidClaims
        $claims['aud'] = 'https://management.azure.com'
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims $claims) @script:VP
        $result | Should -Not -BeNullOrEmpty
    }

    It 'accepts an explicit AllowedAudiences override' {
        $claims        = New-ValidClaims
        $claims['aud'] = 'https://custom.example.com/'
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims $claims) `
            -TenantId 'test-tenant' `
            -AllowedAudiences @('https://custom.example.com/')
        $result | Should -Not -BeNullOrEmpty
    }

    # ── Algorithm ─────────────────────────────────────────────────────────────

    It 'rejects a token whose alg header is not RS256' {
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims (New-ValidClaims) -Alg 'HS256') @script:VP
        $result | Should -BeNullOrEmpty
    }

    It 'rejects a token with alg: none' {
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims (New-ValidClaims) -Alg 'none') @script:VP
        $result | Should -BeNullOrEmpty
    }

    # ── Time claims ───────────────────────────────────────────────────────────

    It 'rejects an expired token' {
        $claims        = New-ValidClaims
        $claims['exp'] = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims $claims) @script:VP
        $result | Should -BeNullOrEmpty
    }

    It 'rejects a token whose nbf is in the future' {
        $claims        = New-ValidClaims
        $claims['nbf'] = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims $claims) @script:VP
        $result | Should -BeNullOrEmpty
    }

    # ── Tenant / issuer ───────────────────────────────────────────────────────

    It 'rejects a token issued for a different tenant' {
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims (New-ValidClaims)) `
            -TenantId 'other-tenant'
        $result | Should -BeNullOrEmpty
    }

    It 'rejects a token with an untrusted issuer' {
        $claims        = New-ValidClaims
        $claims['iss'] = 'https://evil.example.com/'
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims $claims) @script:VP
        $result | Should -BeNullOrEmpty
    }

    # ── Audience ──────────────────────────────────────────────────────────────

    It 'rejects a token for a non-ARM audience' {
        $claims        = New-ValidClaims
        $claims['aud'] = 'api://some-other-app'
        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims $claims) @script:VP
        $result | Should -BeNullOrEmpty
    }

    # ── Signature ─────────────────────────────────────────────────────────────

    It 'rejects a token with a tampered signature' {
        $parts    = (New-TestJwt -Claims (New-ValidClaims)).Split('.')
        $tampered = "$($parts[0]).$($parts[1]).dGFtcGVyZWQ"
        $result   = Invoke-JwtValidation -Token $tampered @script:VP
        $result | Should -BeNullOrEmpty
    }

    It 'rejects a token signed by a different key' {
        $otherKey    = [System.Security.Cryptography.RSA]::Create(2048)
        $headerJson  = @{ alg = 'RS256'; typ = 'JWT'; kid = $script:Kid } | ConvertTo-Json -Compress
        $payloadJson = (New-ValidClaims) | ConvertTo-Json -Compress
        $h   = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($headerJson))
        $p   = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payloadJson))
        $sig = ConvertTo-Base64Url ($otherKey.SignData(
            [Text.Encoding]::ASCII.GetBytes("$h.$p"),
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1))
        $result = Invoke-JwtValidation -Token "$h.$p.$sig" @script:VP
        $result | Should -BeNullOrEmpty
    }

    # ── Malformed tokens ──────────────────────────────────────────────────────

    It 'rejects a token with wrong part count' {
        $result = Invoke-JwtValidation -Token 'not.valid.jwt.structure' @script:VP
        $result | Should -BeNullOrEmpty
    }

    It 'rejects an empty string token (parameter binding rejects it)' {
        # [Parameter(Mandatory)][string] without [AllowEmptyString()] rejects ''
        { Invoke-JwtValidation -Token '' @script:VP } | Should -Throw
    }

    # ── Key rotation retry ────────────────────────────────────────────────────

    It 'retries JWKS fetch on cache miss and succeeds after key rotation' {
        Set-TestJwksCache -Keys @([PSCustomObject]@{ kid = 'old-key'; n = 'x'; e = 'x' })

        $global:__JITRetryJwk = $script:Jwk
        Mock -ModuleName JITHelpers Invoke-RestMethod {
            return [PSCustomObject]@{ keys = @($global:__JITRetryJwk) }
        }

        $result = Invoke-JwtValidation -Token (New-TestJwt -Claims (New-ValidClaims)) @script:VP

        $result | Should -Not -BeNullOrEmpty
        Remove-Variable -Name __JITRetryJwk -Scope Global -ErrorAction SilentlyContinue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-AvailableNsgPriority' {

    BeforeAll {
        function New-MockNsg {
            param([int[]]$InboundPriorities = @())
            $rules = $InboundPriorities | ForEach-Object {
                [PSCustomObject]@{ Direction = 'Inbound'; Priority = $_ }
            }
            return [PSCustomObject]@{ SecurityRules = $rules }
        }
    }

    It 'returns the minimum priority when no rules exist' {
        Get-AvailableNsgPriority -Nsg (New-MockNsg) -Min 1000 -Max 3900 | Should -Be 1000
    }

    It 'returns the next available slot when the minimum is occupied' {
        Get-AvailableNsgPriority -Nsg (New-MockNsg 1000) -Min 1000 -Max 3900 | Should -Be 1010
    }

    It 'skips a run of consecutive occupied priorities' {
        Get-AvailableNsgPriority -Nsg (New-MockNsg 1000, 1010, 1020) -Min 1000 -Max 3900 | Should -Be 1030
    }

    It 'ignores outbound rules when selecting priority' {
        $nsg = [PSCustomObject]@{
            SecurityRules = @([PSCustomObject]@{ Direction = 'Outbound'; Priority = 1000 })
        }
        Get-AvailableNsgPriority -Nsg $nsg -Min 1000 -Max 3900 | Should -Be 1000
    }

    It 'respects a custom Min/Max range' {
        Get-AvailableNsgPriority -Nsg (New-MockNsg) -Min 2000 -Max 2100 | Should -Be 2000
    }

    It 'throws when every priority in the range is occupied' {
        $allUsed = 1000..1090 | Where-Object { ($_ - 1000) % 10 -eq 0 }
        { Get-AvailableNsgPriority -Nsg (New-MockNsg $allUsed) -Min 1000 -Max 1090 } | Should -Throw
    }
}
