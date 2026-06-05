# Managed dependencies — downloaded and cached by the Functions runtime.
# https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell#dependency-management
#
# Intentionally empty. The function app uses Invoke-RestMethod against
# Azure REST APIs directly (see Modules/HttpHelpers/HttpHelpers.psm1)
# instead of Az PowerShell modules. This:
#   • Drops ~400 MB of resident memory
#   • Removes ~5s of cold-start time
#   • Avoids dependency-install flakiness (modules sometimes failed to load,
#     leaving "Get-AzAccessToken not recognized" errors in the worker)
@{
}
