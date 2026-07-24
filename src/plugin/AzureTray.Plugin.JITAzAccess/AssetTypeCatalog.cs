using System;
using System.Collections.Generic;
using System.Linq;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// One JIT-eligible Azure asset type. Single record shared by resource
/// discovery, ARM verification, the config selector, and menu labels so the
/// supported-type set is defined exactly once.
/// </summary>
/// <param name="Token">
/// Internal target token (e.g. <c>nsg</c>). Carried on <c>JitTarget.TargetType</c>
/// and in the grant request body; also the config-option suffix (<c>include.&lt;token&gt;</c>).
/// </param>
/// <param name="ArmType">
/// Canonical ARM type with provider casing (e.g. <c>Microsoft.Network/networkSecurityGroups</c>).
/// Used to build ARM verifier URLs.
/// </param>
/// <param name="ArgType">
/// Lowercase ARM type (e.g. <c>microsoft.network/networksecuritygroups</c>). Used for the
/// Resource Graph <c>type in~</c> list and to map an ARM row back to its token.
/// </param>
/// <param name="DisplayLabel">Short human label shown in the menu and config (e.g. <c>NSG</c>).</param>
internal sealed record AssetType(string Token, string ArmType, string ArgType, string DisplayLabel);

/// <summary>
/// Canonical table of every asset type the plugin can discover and grant JIT
/// access to. This is the ONE source of truth: the KQL type filter, the
/// ARM→token mapping, the config selector, and the menu labels are all derived
/// from it, so adding a type is a single edit here.
/// </summary>
internal static class AssetTypeCatalog
{
    public static IReadOnlyList<AssetType> All { get; } = new[]
    {
        // Original five.
        new AssetType("nsg",                      "Microsoft.Network/networkSecurityGroups", "microsoft.network/networksecuritygroups",   "NSG"),
        new AssetType("sqlServer",                "Microsoft.Sql/servers",                   "microsoft.sql/servers",                     "SQL"),
        new AssetType("storageAccount",           "Microsoft.Storage/storageAccounts",       "microsoft.storage/storageaccounts",         "Storage"),
        new AssetType("keyVault",                 "Microsoft.KeyVault/vaults",               "microsoft.keyvault/vaults",                 "Key Vault"),
        new AssetType("postgresqlFlexibleServer", "Microsoft.DBforPostgreSQL/flexibleServers","microsoft.dbforpostgresql/flexibleservers","PostgreSQL"),

        // Twelve new.
        new AssetType("mysqlFlexibleServer",      "Microsoft.DBforMySQL/flexibleServers",    "microsoft.dbformysql/flexibleservers",      "MySQL"),
        new AssetType("redis",                    "Microsoft.Cache/Redis",                   "microsoft.cache/redis",                     "Redis"),
        new AssetType("synapse",                  "Microsoft.Synapse/workspaces",            "microsoft.synapse/workspaces",              "Synapse"),
        new AssetType("cosmosDb",                 "Microsoft.DocumentDB/databaseAccounts",   "microsoft.documentdb/databaseaccounts",     "Cosmos DB"),
        new AssetType("containerRegistry",        "Microsoft.ContainerRegistry/registries",  "microsoft.containerregistry/registries",    "Container Registry"),
        new AssetType("aiSearch",                 "Microsoft.Search/searchServices",         "microsoft.search/searchservices",           "AI Search"),
        new AssetType("cognitiveServices",        "Microsoft.CognitiveServices/accounts",    "microsoft.cognitiveservices/accounts",      "Cognitive / OpenAI"),
        new AssetType("kusto",                    "Microsoft.Kusto/clusters",                "microsoft.kusto/clusters",                  "Data Explorer"),
        new AssetType("iotHub",                   "Microsoft.Devices/IotHubs",               "microsoft.devices/iothubs",                 "IoT Hub"),
        new AssetType("signalR",                  "Microsoft.SignalRService/signalR",        "microsoft.signalrservice/signalr",          "SignalR"),
        new AssetType("eventHub",                 "Microsoft.EventHub/namespaces",           "microsoft.eventhub/namespaces",             "Event Hubs"),
        new AssetType("serviceBus",               "Microsoft.ServiceBus/namespaces",         "microsoft.servicebus/namespaces",           "Service Bus"),

        // Compute / hosting.
        new AssetType("appService",               "Microsoft.Web/sites",                     "microsoft.web/sites",                       "App Service"),
        new AssetType("aks",                      "Microsoft.ContainerService/managedClusters","microsoft.containerservice/managedclusters","AKS"),
    };

    private static readonly IReadOnlyDictionary<string, AssetType> ByArgType =
        All.ToDictionary(t => t.ArgType, StringComparer.OrdinalIgnoreCase);

    private static readonly IReadOnlyDictionary<string, AssetType> ByToken =
        All.ToDictionary(t => t.Token, StringComparer.Ordinal);

    /// <summary>Internal token for a lowercase ARM type, or null if unsupported.</summary>
    public static string? TokenForArgType(string argType) =>
        ByArgType.TryGetValue(argType, out var t) ? t.Token : null;

    /// <summary>Short display label for a token, falling back to the token itself.</summary>
    public static string LabelForToken(string token) =>
        ByToken.TryGetValue(token, out var t) ? t.DisplayLabel : token;

    /// <summary>Canonical ARM type (provider casing) for a token, or null if unknown.</summary>
    public static string? ArmTypeForToken(string token) =>
        ByToken.TryGetValue(token, out var t) ? t.ArmType : null;
}
