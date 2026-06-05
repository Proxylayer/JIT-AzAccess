# Get-JITTargets/run.ps1
#
# HTTP GET — Returns the pre-approved JIT target manifest so the plugin can
# present a curated, server-controlled browse list rather than letting callers
# type arbitrary subscription/resource combinations.
#
# Access control: Bearer token must carry the JIT.Requester app role.
#
# The target manifest lives at blob  jit-config/targets.json  in the
# AzureWebJobsStorage account.  An empty array is returned if the blob does
# not yet exist.  Use the az CLI or Storage Explorer to seed the file:
#
#   [
#     {
#       "id":                    "nsg-dev-eastus",
#       "displayName":           "Dev NSG (East US)",
#       "targetType":            "nsg",
#       "subscriptionId":        "<guid>",
#       "resourceGroup":         "rg-dev-eastus",
#       "resourceName":          "nsg-dev-eastus",
#       "environment":           "dev",
#       "defaultPort":           "3389",
#       "allowedPorts":          ["22","3389","443","*"],
#       "allowedDurations":      [1,2,4],
#       "enabled":               true,
#       "requiresJustification": false
#     }
#   ]

using namespace System.Net

param($Request, $TriggerMetadata)

Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1" -Force

$tenantId         = $env:AZURE_TENANT_ID
$audience         = $env:JWT_AUDIENCE
$allowedClientIds = ($env:APPROVED_CLIENT_IDS -split ',') |
                        ForEach-Object { $_.Trim() } | Where-Object { $_ }

function Write-JsonResponse {
    param([HttpStatusCode]$Status, [object]$Body)
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $Status
        Body       = ($Body | ConvertTo-Json -Depth 10 -Compress)
        Headers    = @{ 'Content-Type' = 'application/json' }
    })
}

#region ── 1. Validate token ──────────────────────────────────────────────────

$authHeader = $Request.Headers['Authorization']
if (-not $authHeader -or -not $authHeader.ToString().StartsWith('Bearer ')) {
    Write-JsonResponse -Status Unauthorized -Body @{ error = 'Missing or invalid Authorization header.' }
    return
}

$token  = $authHeader.ToString().Substring(7)
$claims = Invoke-JwtValidation -Token $token `
                               -TenantId $tenantId `
                               -Audience $audience `
                               -AllowedClientIds $allowedClientIds

if (-not $claims) {
    Write-JsonResponse -Status Forbidden -Body @{ error = 'Token validation failed.' }
    return
}

$callerRoles = @()
if ($claims.roles) { $callerRoles = @($claims.roles) }

if ('JIT.Requester' -notin $callerRoles) {
    Write-JsonResponse -Status Forbidden -Body @{
        error        = 'Caller does not have the JIT.Requester role. Activate it via PIM before using JIT.'
        requiredRole = 'JIT.Requester'
    }
    return
}

#endregion

#region ── 2. Load and return enabled targets ─────────────────────────────────

try {
    $manifest = Get-JITTargetManifest
    $enabled  = @($manifest | Where-Object { $_.enabled -ne $false })
    Write-Host "Get-JITTargets: returning $($enabled.Count) enabled target(s)."
    Write-JsonResponse -Status OK -Body $enabled
}
catch {
    Write-Error "Get-JITTargets: failed to load target manifest — $_"
    Write-JsonResponse -Status InternalServerError -Body @{
        error = 'Failed to load the target manifest from storage. ' +
                'Ensure the blob jit-config/targets.json exists in the AzureWebJobsStorage account.'
    }
}

#endregion
