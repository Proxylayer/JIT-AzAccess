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
Import-Module "$PSScriptRoot/Modules/JITHelpers/JITHelpers.psm1"   -Force

# Subscription id is derived at runtime (env JIT_SUBSCRIPTION_ID wins, else the
# platform's WEBSITE_OWNER_NAME / IMDS) so no config app-setting is required.
# One line per cold start, so every App Insights trace can be tied to a build.
Write-Host "JIT-AzAccess function app $(Get-JITAppVersion) starting (PowerShell $($PSVersionTable.PSVersion))."

$subId = Get-JitSubscriptionId

if ($env:WEBSITE_HOSTNAME -and $env:AZURETRAY_APP_REGISTRATION_OBJECT_ID -and $subId) {
    try {
        $appObjId   = $env:AZURETRAY_APP_REGISTRATION_OBJECT_ID
        $graphToken = Get-ManagedIdentityToken -Resource 'https://graph.microsoft.com/'
        $headers    = @{ Authorization = "Bearer $graphToken"; 'Content-Type' = 'application/json' }
        $baseUrl    = "https://$($env:WEBSITE_HOSTNAME)"

        $tagPrefix = "jit-baseurl:${subId}="
        $newTag    = "${tagPrefix}${baseUrl}"

        # Read -> merge -> write, retried, because several JIT deployments
        # share ONE app registration's tags array and each writes its own
        # entry. There is no ETag/If-Match on this PATCH, so two function apps
        # cold-starting together can both read the same array and the second
        # write silently drops the first one's tag. Re-reading afterwards and
        # retrying turns that from a permanent loss into a brief one.
        $maxAttempts = 3
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {

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

            # NOTE the parentheses. Written without them --
            #   ($a | Sort-Object) -join "`n" -eq ($b | Sort-Object) -join "`n"
            # -- PowerShell binds -eq tighter than the second -join, so the
            # whole expression evaluates to the STRING "False", which is
            # non-empty and therefore truthy. This branch always won and the
            # PATCH below was dead code: the app never self-registered its URL
            # at cold start, and only Deploy.ps1 Step 3c ever wrote the tag.
            # Deploy.ps1 has the same comparison WITH the parentheses, which is
            # why only this copy was broken.
            $existingJoined = (($existingTags | Sort-Object) -join "`n")
            $mergedJoined   = (($mergedTags   | Sort-Object) -join "`n")

            if ($existingJoined -eq $mergedJoined) {
                Write-Host "JIT: tag already up to date — $newTag"
                break
            }

            # ConvertTo-Json unwraps single-element arrays. Force the array
            # shape via List<string> so Graph doesn't 400 on count == 1.
            $tagList = [System.Collections.Generic.List[string]]::new()
            foreach ($t in $mergedTags) { $tagList.Add([string]$t) }

            Invoke-RestMethod `
                -Method  PATCH `
                -Uri     "https://graph.microsoft.com/v1.0/applications/$appObjId" `
                -Headers $headers `
                -Body    (@{ tags = $tagList } | ConvertTo-Json -Depth 3) | Out-Null

            Write-Host "JIT: app reg $appObjId tag set — $newTag (attempt $attempt)"

            # Confirm it survived. A concurrent deployment's write between our
            # read and ours lands here as a missing tag.
            Start-Sleep -Milliseconds (200 * $attempt)
            $verified = $false
            try {
                $after = Invoke-RestMethod -Method Get `
                             -Uri "https://graph.microsoft.com/v1.0/applications/$appObjId`?`$select=tags" `
                             -Headers $headers
                $verified = @($after.tags) -contains $newTag
            }
            catch {
                Write-Warning "JIT: could not verify the tag write (assuming it landed): $_"
                $verified = $true
            }

            if ($verified) { break }

            if ($attempt -eq $maxAttempts) {
                Write-Warning ("JIT: tag '$newTag' did not survive $maxAttempts attempts — another deployment " +
                               "is probably writing the same app registration. The plugin will not discover " +
                               "this subscription until the next cold start or a Deploy.ps1 re-run.")
            }
            else {
                Write-Warning "JIT: tag '$newTag' was overwritten by a concurrent write — retrying."
            }
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
    elseif (-not $subId) {
        Write-Warning "JIT: could not determine the function app's subscription id (WEBSITE_OWNER_NAME/IMDS unavailable and JIT_SUBSCRIPTION_ID unset) — skipping URL self-register."
    }
}
