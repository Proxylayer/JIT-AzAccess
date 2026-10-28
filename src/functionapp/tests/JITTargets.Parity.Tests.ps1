# Parity guards for the supported target-type set.
#
# The failure these exist to prevent: a type accepted by Request-JITAccess but
# missing from the Remove-ExpiredRules dispatch switch. The grant succeeds, and
# at expiry the timer's unknown-type branch deletes the tracking row WITHOUT
# touching Azure - the firewall stays open forever and nothing records it.
#
# These are AST/metadata assertions, so they need no Azure and no mocks.
#
# Pester 5+ (setup in BeforeAll, `Should -Verb` syntax). The type list MUST be
# built at run time: with it built in the script body, $script:Types was empty
# inside every It and five of these six guards passed by comparing '' to ''.
# They are mutation-tested after any change here for exactly that reason.

BeforeAll {

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

$script:Types   = @(Get-JITSupportedTargetTypes)
$script:Exports = (Get-Module JITTargets).ExportedFunctions.Keys

# Pulls the literal switch labels out of a run.ps1's target-type switch, so the
# test reads the real dispatch table rather than a copy of it.
function script:Get-SwitchTokens {
    param([string]$RelPath, [string]$MustContain)

    $full = Join-Path $PSScriptRoot $RelPath
    $ast  = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$null, [ref]$null)

    $switches = $ast.FindAll({
        param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst]
    }, $true)

    foreach ($sw in $switches) {
        $tokens = @()
        foreach ($clause in $sw.Clauses) {
            $cond = $clause.Item1
            if ($cond -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $tokens += $cond.Value
            }
        }
        if ($tokens -contains $MustContain) { return $tokens }
    }
    return @()
}

}   # end BeforeAll

Describe 'Supported target-type parity' {

    It 'maps every supported type to an exported Add handler' {
        # Reads the real Request-JITAccess dispatch switch and checks the
        # command each arm names is actually exported by JITTargets. NSG is
        # granted before the switch (it needs the blob lock), so it is checked
        # separately below.
        $full = Join-Path $PSScriptRoot '../Request-JITAccess/run.ps1'
        $text = Get-Content $full -Raw
        $bad  = @()
        foreach ($t in @($script:Types | Where-Object { $_ -ne 'nsg' })) {
            if ($text -match "(?m)^\s*'$([regex]::Escape($t))'\s+\{\s*(Add-JIT\w+)\s") {
                $fn = $matches[1]
                if ($script:Exports -notcontains $fn) { $bad += "$t -> $fn (not exported)" }
            }
            else { $bad += "$t -> no Add dispatch arm" }
        }
        if ($script:Exports -notcontains 'Add-JITNsgRule') { $bad += 'nsg -> Add-JITNsgRule (not exported)' }
        ($bad -join '; ') | Should -Be ''
    }

    It 'dispatches every supported type in Request-JITAccess' {
        $tokens  = Get-SwitchTokens -RelPath '../Request-JITAccess/run.ps1' -MustContain 'sqlServer'
        $tokens.Count | Should -BeGreaterThan 0
        # NSG is handled before the switch (it needs the blob lock), so it is
        # legitimately absent from the dispatch switch itself.
        $expected = @($script:Types | Where-Object { $_ -ne 'nsg' })
        $missing  = @($expected | Where-Object { $tokens -notcontains $_ })
        ($missing -join ',') | Should -Be ''
    }

    It 'dispatches every supported type in Remove-ExpiredRules' {
        $tokens  = Get-SwitchTokens -RelPath '../Remove-ExpiredRules/run.ps1' -MustContain 'nsg'
        $tokens.Count | Should -BeGreaterThan 0
        $missing = @($script:Types | Where-Object { $tokens -notcontains $_ })
        ($missing -join ',') | Should -Be ''
    }

    It 'dispatches every supported type in Revoke-JITAccess' {
        $tokens  = Get-SwitchTokens -RelPath '../Revoke-JITAccess/run.ps1' -MustContain 'nsg'
        $tokens.Count | Should -BeGreaterThan 0
        $missing = @($script:Types | Where-Object { $tokens -notcontains $_ })
        ($missing -join ',') | Should -Be ''
    }

    It 'dispatches every supported type in the shared Invoke-JITTargetRemove' {
        $full   = Join-Path $PSScriptRoot '../Modules/JITTargets/JITTargets.psm1'
        $ast    = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$null, [ref]$null)
        $sw     = @($ast.FindAll({
            param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst]
        }, $true))[0]
        $tokens = @()
        foreach ($clause in $sw.Clauses) {
            $cond = $clause.Item1
            if ($cond -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $tokens += $cond.Value
            }
        }
        $missing = @($script:Types | Where-Object { $tokens -notcontains $_ })
        ($missing -join ',') | Should -Be ''
    }

    It 'every Remove handler falls back to a usable identifier when RuleIdentifier is blank' {
        # Request-JITAccess writes its reservation row with an EMPTY
        # RuleIdentifier, because only the grant knows what the handler
        # actually used. Cleanup of an abandoned reservation therefore depends
        # on every handler resolving a per-type key from the rest of the row:
        # RowKey for a named rule, CallerIp for an IP-identified entry. A
        # handler added without that fallback silently cannot clean up its own
        # abandoned reservations.
        $dir = Join-Path $PSScriptRoot '../Modules/JITTargets/Targets'
        $bad = @()
        foreach ($f in Get-ChildItem -Path $dir -Filter '*.ps1' -File) {
            if ($f.BaseName -eq '_Shared') { continue }
            $text = Get-Content $f.FullName -Raw
            if ($text -notmatch 'function\s+Remove-JIT\w+') { continue }
            if ($text -notmatch 'if \(\$Row\.RuleIdentifier\) \{ \$Row\.RuleIdentifier \} else \{ \$Row\.(RowKey|CallerIp) \}') {
                $bad += $f.BaseName
            }
        }
        ($bad -join ', ') | Should -Be ''
    }

    It 'exports a Remove handler reachable for every supported type' {
        # Every type must resolve through the shared dispatcher to a command
        # that actually exists in the module.
        $full = Join-Path $PSScriptRoot '../Modules/JITTargets/JITTargets.psm1'
        $text = Get-Content $full -Raw
        $bad  = @()
        foreach ($t in $script:Types) {
            if ($text -match "(?m)^\s*'$([regex]::Escape($t))'\s*\{\s*return\s+(Remove-JIT\w+)\s") {
                $fn = $matches[1]
                if ($script:Exports -notcontains $fn) { $bad += "$t -> $fn (not exported)" }
            }
            else { $bad += "$t -> no dispatcher arm" }
        }
        ($bad -join '; ') | Should -Be ''
    }
}
