# profile.ps1 — runs once per worker process at cold start.
# Authenticates the function app's system-assigned managed identity with Az modules,
# then self-registers the function endpoint URL on the app registration.

if ($env:MSI_ENDPOINT -or $env:IDENTITY_ENDPOINT) {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    Write-Host "Authenticated via system-assigned managed identity."
}

# Self-register the endpoint URL on the app registration so calling apps can discover it.
# Requires Application.ReadWrite.OwnedBy on the managed identity and ownership of the app reg.
if ($env:JIT_APP_REGISTRATION_OBJECT_ID -and $env:WEBSITE_HOSTNAME) {
    try {
        $graphToken = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token
        $endpoint   = "https://$($env:WEBSITE_HOSTNAME)/api/Request-jitazaccess"

        Invoke-RestMethod `
            -Method  PATCH `
            -Uri     "https://graph.microsoft.com/v1.0/applications/$($env:JIT_APP_REGISTRATION_OBJECT_ID)" `
            -Headers @{ Authorization = "Bearer $graphToken"; 'Content-Type' = 'application/json' } `
            -Body    (@{ web = @{ homePageUrl = $endpoint } } | ConvertTo-Json) | Out-Null

        Write-Host "App registration homePageUrl updated to: $endpoint"
    }
    catch {
        # Non-fatal — log and continue. The function still starts normally.
        Write-Warning "Could not update app registration homePageUrl: $_"
    }
}
