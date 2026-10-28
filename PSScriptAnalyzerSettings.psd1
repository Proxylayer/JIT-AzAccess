@{
    # PSScriptAnalyzer settings for the JIT-AzAccess function app.
    #
    # Everything is enabled except the rules below, each excluded for a reason
    # specific to this codebase rather than to quiet a number down. Severity is
    # not filtered: an Information-level finding still fails the build, because
    # the point of running this in CI is that nothing new slips in.

    Severity = @('Error', 'Warning', 'Information')

    ExcludeRules = @(
        # Write-Host IS the output channel for an Azure Functions PowerShell
        # worker: it is what reaches the function invocation log that operators
        # read. ~219 uses, all deliberate.
        'PSAvoidUsingWriteHost'

        # The Functions worker passes $Request/$Timer as globals, and the tests
        # hand fixtures across the module-scope boundary the same way (there is
        # no other way to reach into InModuleScope). ~218 uses.
        'PSAvoidGlobalVars'

        # The function app ships no .psd1 manifests; modules are dot-sourced by
        # path from the worker, so there is nothing for this rule to check and
        # it fires on every module file.
        'PSUseToExportFieldsInManifest'

        # Plural nouns appear in exported names that are already part of the
        # deployed contract (Get-JITTableRows, Get-JITSupportedTargetTypes).
        # Renaming them is a breaking change for no benefit.
        'PSUseSingularNouns'

        # The Remove-JIT*Rule handlers are internal dispatch targets called by
        # a timer and by two HTTP endpoints, never interactively. -WhatIf on
        # all 19 would be ceremony nothing can reach; the safety that matters
        # (the AKS "would open the API server" refusal) is in the handlers.
        'PSUseShouldProcessForStateChangingFunctions'

        # The worker binds $Request / $Timer / $TriggerMetadata by NAME from
        # function.json, so an endpoint must declare them whether or not it
        # reads them. The same applies to -RuleId on the array-type Add
        # handlers, which share one signature with the named-rule handlers so
        # the dispatch switch can call them uniformly.
        'PSReviewUnusedParameter'

        # Several files carry box-drawing characters in their comment banners.
        # The app runs on PowerShell 7 on Linux App Service, where UTF-8
        # WITHOUT a BOM is correct; adding one would be the actual defect.
        'PSUseBOMForUnicodeEncodedFile'
    )

    Rules = @{
        # The repo targets PowerShell 7.4 on Linux App Service (see
        # azuredeploy.json powerShellVersion). Flag anything that would not run
        # there rather than discovering it after a deploy.
        PSUseCompatibleSyntax = @{
            Enable        = $true
            TargetVersions = @('7.0')
        }
    }
}
