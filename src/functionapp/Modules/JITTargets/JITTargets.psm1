# JITTargets.psm1
# Per-resource-type Add/Remove handlers for JIT IP whitelisting.
#
# 100% REST via Invoke-ArmRest — no Az.* PowerShell modules. Each Add-*
# returns a hashtable with RuleIdentifier and Details. Each Remove-*
# accepts the row from Table Storage and cleans up.
#
# This module is now split across per-type files under .\Targets\. This .psm1 is
# a thin loader: it dot-sources the shared helpers FIRST, then each per-type
# file. Dot-sourcing from the .psm1 loads every definition into THIS module's
# scope. Each per-type file owns its own $script:-scoped constants (ARM API
# version, and for PostgreSQL the LRO bounds and private-server sentinel),
# co-located with the handlers that use them; _Shared.ps1 keeps only the
# genuinely cross-type helpers (ConvertTo-Hashtable, Get-HeaderValue, and the
# generic Wait-JITArmAsyncOperation poller).
#
# IMPORTANT: HttpHelpers and JITHelpers must already be loaded in global
# scope before any JITTargets function is invoked. Each endpoint's run.ps1
# imports them in the right order. We do NOT Import-Module them here, since
# nested Import-Module -Force wipes the inner module's ExportedCommands.

# Shared helpers + script-scope constants MUST load first (deterministic order):
# the per-type files below reference the constants and helpers it defines.
. "$PSScriptRoot\Targets\_Shared.ps1"

# Per-type handler files (order among these does not matter — no cross-refs).
. "$PSScriptRoot\Targets\Nsg.ps1"
. "$PSScriptRoot\Targets\SqlServer.ps1"
. "$PSScriptRoot\Targets\PostgresqlFlexibleServer.ps1"
. "$PSScriptRoot\Targets\StorageAccount.ps1"
. "$PSScriptRoot\Targets\KeyVault.ps1"
# CHILD firewall-rule types (clone SQL/PostgreSQL template).
. "$PSScriptRoot\Targets\MysqlFlexibleServer.ps1"
. "$PSScriptRoot\Targets\Redis.ps1"
. "$PSScriptRoot\Targets\Synapse.ps1"
# ARRAY-on-resource types (use the shared ETag read-modify-write helper).
. "$PSScriptRoot\Targets\CosmosDb.ps1"
. "$PSScriptRoot\Targets\ContainerRegistry.ps1"
. "$PSScriptRoot\Targets\AiSearch.ps1"
. "$PSScriptRoot\Targets\CognitiveServices.ps1"
. "$PSScriptRoot\Targets\Kusto.ps1"
. "$PSScriptRoot\Targets\IotHub.ps1"
. "$PSScriptRoot\Targets\SignalR.ps1"
# CHILD-SINGLETON array types (PUT the networkRuleSets/default child).
. "$PSScriptRoot\Targets\EventHub.ps1"
. "$PSScriptRoot\Targets\ServiceBus.ps1"
# CONFIG-CHILD array-of-objects (PATCH the sites/config/web child).
. "$PSScriptRoot\Targets\AppService.ps1"
# FULL-BODY-PUT string-array types (no PATCH for cluster properties).
. "$PSScriptRoot\Targets\Aks.ps1"

Export-ModuleMember -Function @(
    'Add-JITNsgRule';           'Remove-JITNsgRule'
    'Add-JITSqlFirewallRule';   'Remove-JITSqlFirewallRule'
    'Add-JITPostgresFirewallRule'; 'Remove-JITPostgresFirewallRule'
    'Add-JITStorageNetworkRule';'Remove-JITStorageNetworkRule'
    'Add-JITKeyVaultNetworkRule';'Remove-JITKeyVaultNetworkRule'
    'Add-JITMysqlFlexibleServerRule'; 'Remove-JITMysqlFlexibleServerRule'
    'Add-JITRedisRule';            'Remove-JITRedisRule'
    'Add-JITSynapseRule';          'Remove-JITSynapseRule'
    'Add-JITCosmosDbRule';         'Remove-JITCosmosDbRule'
    'Add-JITContainerRegistryRule';'Remove-JITContainerRegistryRule'
    'Add-JITAiSearchRule';         'Remove-JITAiSearchRule'
    'Add-JITCognitiveServicesRule';'Remove-JITCognitiveServicesRule'
    'Add-JITKustoRule';            'Remove-JITKustoRule'
    'Add-JITIotHubRule';           'Remove-JITIotHubRule'
    'Add-JITSignalRRule';          'Remove-JITSignalRRule'
    'Add-JITEventHubRule';         'Remove-JITEventHubRule'
    'Add-JITServiceBusRule';       'Remove-JITServiceBusRule'
    'Add-JITAppServiceRule';       'Remove-JITAppServiceRule'
    'Add-JITAksRule';              'Remove-JITAksRule'
)
