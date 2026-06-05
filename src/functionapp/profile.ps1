# profile.ps1 — runs once per worker process at cold start.
#
# This function app uses ZERO Az PowerShell modules. Tokens come from the
# IDENTITY_ENDPOINT REST API; ARM/Graph calls go through Invoke-RestMethod.
# See Modules/HttpHelpers/HttpHelpers.psm1.
#
# Self-registers the function app's base URL on the AzureTray host app
# registration so the AzureTray plugin can discover it without manual config.
# Writes a single tag of the form:
#   jit-baseurl:<subscriptionId>=<https-url>
# The notes field is left untouched (humans use it for descriptions).

Import-Module "$PSScriptRoot/Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking

if ($env:WEBSITE_HOSTNAME -and $env:AZURETRAY_APP_REGISTRATION_OBJECT_ID -and $env:JIT_SUBSCRIPTION_ID) {
    try {
        $appObjId   = $env:AZURETRAY_APP_REGISTRATION_OBJECT_ID
        $subId      = $env:JIT_SUBSCRIPTION_ID
        $graphToken = Get-ManagedIdentityToken -Resource 'https://graph.microsoft.com/'
        $headers    = @{ Authorization = "Bearer $graphToken"; 'Content-Type' = 'application/json' }
        $baseUrl    = "https://$($env:WEBSITE_HOSTNAME)"

        $tagPrefix = "jit-baseurl:${subId}="
        $newTag    = "${tagPrefix}${baseUrl}"

        # Read existing tags.
        $existingTags = @()
        try {
            $app = Invoke-RestMethod -Method Get `
                       -Uri "https://graph.microsoft.com/v1.0/applications/$appObjId`?`$select=tags" `
                       -Headers $headers
            if ($app.tags) { $existingTags = @($app.tags) }
        }
        catch {
            Write-Warning "JIT: could not read existing tags on app reg $appObjId (continuing with empty): $_"
        }

        # Drop any previous version of our own tag (URL may have changed),
        # keep everything else (other JIT deployments + tags the host or
        # other plugins may have set).
        $otherTags  = @($existingTags | Where-Object { $_ -notlike "${tagPrefix}*" })
        $mergedTags = @($otherTags + $newTag) | Sort-Object -Unique

        if (($existingTags | Sort-Object) -join "`n" -eq ($mergedTags | Sort-Object) -join "`n") {
            Write-Host "JIT: tag already up to date — $newTag"
        }
        else {
            # ConvertTo-Json unwraps single-element arrays. Force the array
            # shape via List<string> so Graph doesn't 400 on count == 1.
            $tagList = [System.Collections.Generic.List[string]]::new()
            foreach ($t in $mergedTags) { $tagList.Add([string]$t) }

            Invoke-RestMethod `
                -Method  PATCH `
                -Uri     "https://graph.microsoft.com/v1.0/applications/$appObjId" `
                -Headers $headers `
                -Body    (@{ tags = $tagList } | ConvertTo-Json -Depth 3) | Out-Null

            Write-Host "JIT: app reg $appObjId tag set — $newTag"
        }
    }
    catch {
        Write-Warning "Could not update AzureTray app registration tags: $_"
    }
}
elseif ($env:WEBSITE_HOSTNAME) {
    if (-not $env:AZURETRAY_APP_REGISTRATION_OBJECT_ID) {
        Write-Warning "JIT: AZURETRAY_APP_REGISTRATION_OBJECT_ID not set — skipping URL self-register. Re-run Deploy.ps1."
    }
    elseif (-not $env:JIT_SUBSCRIPTION_ID) {
        Write-Warning "JIT: JIT_SUBSCRIPTION_ID not set — skipping URL self-register. Re-deploy with the latest azuredeploy.json."
    }
}
