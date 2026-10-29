# The function app and the plugin ship together off one git tag, so they must
# declare the same version — and they declare it in two different languages, in
# two different files, which is exactly the shape of every drift bug this repo
# has already been bitten by (the app name defaulting to `jitazaccess` in one
# script and `pgjitazaccess` in another; five hand-maintained target-type lists
# that had to agree).
#
# A version that lies is worse than no version: the cold-start log line and the
# alerts that quote it would point at the wrong build.
#
# Run:  ./test.ps1 -Target JITVersion

BeforeAll {
    Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
    Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force

    $script:CsprojPath = Join-Path $PSScriptRoot '../../plugin/AzureTray.Plugin.JITAzAccess/AzureTray.Plugin.JITAzAccess.csproj'
}

Describe 'Version parity' {

    It 'the function app reports a version' {
        Get-JITAppVersion | Should -Not -BeNullOrEmpty
    }

    It 'the function app version is a three-part semver' {
        Get-JITAppVersion | Should -Match '^\d+\.\d+\.\d+$'
    }

    It 'the plugin csproj declares exactly one <Version>' {
        $matches = @(Select-String -Path $script:CsprojPath -Pattern '<Version>([^<]+)</Version>' -AllMatches)
        $matches.Count | Should -Be 1
    }

    It 'the function app and the plugin declare the SAME version' {
        $csproj = Get-Content $script:CsprojPath -Raw
        $csproj -match '<Version>([^<]+)</Version>' | Should -BeTrue
        $pluginVersion = $Matches[1].Trim()

        Get-JITAppVersion | Should -Be $pluginVersion `
            -Because "the function app and the plugin ship from one tag; bump both or neither (csproj says '$pluginVersion')"
    }
}
