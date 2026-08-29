# JIT-AzAccess — Azure Function App

Grants callers temporary (JIT) IP-based access to Azure resources by dynamically adding and auto-expiring firewall/network rules. Supports:

- **NSG** inbound security rules
- **Azure SQL Server** firewall rules
- **Storage Account** network ACLs
- **Key Vault** network ACLs

Rules are automatically removed by a timer trigger when they expire (every 5 minutes).

---

## Design

The function app accepts **plain ARM-audience tokens** (`https://management.azure.com/`) issued
by the calling user's tenant — no dedicated JIT app registration, no custom OAuth scope.

Authorization is gated on Azure RBAC for the actions that change access: to
**request** access the caller must hold the custom **"JIT-Requester"** role
**within the subscription they are requesting access into** (evaluated against the
`subscriptionId` in the request body), and to **revoke** a rule the caller must
hold it in that rule's own subscription. Listing your own rules (`Get-JITRules`)
requires only authentication — no role assignment — because callers only ever see
the rules they personally requested. The role name is hardcoded in the app. The
deployment scripts make this role assignable in each target subscription; admins
assign it to end users.

The function app is **zero-config**: it deploys with no operational App Settings.
Its own subscription id, resource group, site name, and tenant id are derived at
runtime from platform-injected environment variables (`WEBSITE_OWNER_NAME`,
`WEBSITE_RESOURCE_GROUP`, `WEBSITE_SITE_NAME`) and the managed identity token, with
IMDS as a fallback. Every derived value can still be overridden by setting the
corresponding App Setting (`JIT_SUBSCRIPTION_ID`, `JIT_RESOURCE_GROUP`,
`JIT_SITE_NAME`, `JIT_SITE_RESOURCE_ID`, `AZURE_TENANT_ID`) — env wins when set.

The AzureTray plugin auto-discovers the function app URL by reading the
**AzureTray host's** app-registration `tags` via Microsoft Graph. The
function app's managed identity self-registers its URL as a tag of the form
`jit-baseurl:<subscriptionId>=<https-url>` on every cold start (`profile.ps1`).
The `notes` field is left untouched for human-authored descriptions. No
plugin-side configuration needed.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Azure CLI (`az`) | `az login` before deploying |
| Azure subscription | You need **Owner** or **User Access Administrator** to deploy the ARM template and create custom RBAC roles |
| Entra ID role | Caller must be **Application Administrator** (or Global Admin) to grant Graph app role assignments to the function app MI |
| AzureTray app registration | Must already exist in the tenant — its `notes` field is where the function app writes `jitBaseUrl` |

---

## Quick Start

### 1. Deploy the infrastructure

```powershell
./scripts/Deploy.ps1 `
    -SubscriptionId "<your-subscription-id>" `
    -Location       "eastus"
```

`Deploy.ps1` will:

1. Run the ARM template (resource group + function app + dependencies)
2. Zip-deploy the function app code
3. Grant the function app's MI, and make the requester role assignable, on the target subscriptions:
   - `JIT-AzAccess Manager` custom RBAC role assigned to the MI (so it can write firewall rules)
   - `JIT-Requester` custom RBAC role definition made assignable in each target subscription
   - Microsoft Graph `Application.ReadWrite.OwnedBy` + ownership of the AzureTray app reg (so it can self-register its URL on cold start)
4. Register this deployment's URL as a `jit-baseurl:<sub>=<url>` tag on the AzureTray app reg
5. Restart the function app so `profile.ps1` self-registers its URL tag

### 2. Assign the JIT-Requester role to your users

The function app rejects callers who don't hold the `JIT-Requester` role **in the
subscription they are requesting access into**. Assign it (via the portal, az CLI,
or PIM) at the target subscription scope:

```powershell
az role assignment create `
    --assignee-object-id <user-or-group-objectId> `
    --assignee-principal-type User `
    --role "JIT-Requester" `
    --scope "/subscriptions/<targetSubscriptionId>"
```

You can scope the assignment narrower (resource group within the subscription) — ARM
inheritance applies. Listing your own rules via `Get-JITRules` needs no role
assignment — it requires only authentication, and callers only ever see the rules
they personally requested.

### 3. Use it from AzureTray

No plugin settings — sign in to the tenant in AzureTray. The JIT Access plugin auto-discovers
the function app URL via the AzureTray app reg tags and starts polling.

---

## Folder Structure

```
jit-azaccess/
  azuredeploy.json                    # Subscription-scoped ARM template
  azuredeploy.parameters.example.json # Parameter file template
  functionapp/                        # PowerShell Azure Functions code
    host.json
    requirements.psd1
    profile.ps1                       # Writes jitBaseUrl to AzureTray app reg on cold start
    Request-JITAccess/
      function.json                   # HTTP POST
      run.ps1
    Get-JITRules/, Revoke-JITAccess/  # HTTP endpoints
    Remove-ExpiredRules/              # Timer trigger (every 5 min)
    Modules/
      HttpHelpers/HttpHelpers.psm1    # REST helpers (ARM/Graph/Blob/Table), MI token
      JITHelpers/JITHelpers.psm1      # JWT validation, RBAC role check, audit logging
      JITTargets/JITTargets.psm1      # Per-resource-type Add/Remove handlers
    tests/                            # Pester tests
  scripts/
    Deploy.ps1                        # End-to-end deployment orchestration
    Grant-JITPermissions.ps1          # Create JIT-AzAccess Manager role + assign to MI
    Remove-JITDeployment.ps1          # Tear down a deployment
    Test-JITAccess.ps1                # Smoke-test the deployed function app
  plugin/AzureTray.Plugin.JITAzAccess/ # The AzureTray plugin (client-side resource discovery)
```

---

## ARM Template Parameters

| Parameter | Default | Description |
|---|---|---|
| `location` | _(required)_ | Azure region for all resources |
| `appName` | `jitazaccess` | Short lowercase alphanumeric name (3-15 chars) used to derive resource names |
| `resourceGroupName` | `rg-jit-azaccess` | Resource group to create |
| `azureTrayAppRegistrationName` | `AzureTray` | Display name of the host app reg the function app writes `jitBaseUrl` to |
| `allowedDurationsHours` | `1,4,8` | Comma-separated list of valid JIT durations in hours |
| `nsgPriorityMin` | `1000` | Lowest NSG rule priority the JIT app may assign |
| `nsgPriorityMax` | `3900` | Highest NSG rule priority the JIT app may assign |
| `maxRulesPerCaller` | `5` | Max simultaneously active rules per caller identity |
| `maxRulesPerResource` | `20` | Max simultaneously active rules per target resource |

Resource names are derived from `appName`:

| Resource | Name |
|---|---|
| Storage account | `st{appName}` |
| Consumption plan | `asp-{appName}` |
| Function app | `func-{appName}` |

---

## API Usage

**Endpoint:** `POST https://func-{appName}.azurewebsites.net/api/Request-JITAccess`

**Authorization:** `Bearer <ARM token>`. Token must:
- be issued by the function app's tenant (`tid` claim matches the app's derived/overridden tenant id)
- carry an ARM audience (`https://management.azure.com/`)

**Authorization check:** the caller's AAD object ID (`oid` claim) must hold the
`JIT-Requester` RBAC role within the target subscription named in the request body
(`subscriptionId`) — at the subscription scope, inherited from a parent management
group, or on a resource group / resource inside it.

**Request body:**

```json
{
  "targetType":    "nsg",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "resourceGroup":  "my-rg",
  "resourceName":   "my-nsg",
  "durationHours":  4,
  "port":           "443"
}
```

Supported `targetType` values:

| `targetType` | Azure resource | Model |
|---|---|---|
| `nsg` | Network security group | Per-IP inbound security rule |
| `sqlServer` | Azure SQL server | Firewall rule (child) |
| `postgresqlFlexibleServer` | PostgreSQL flexible server | Firewall rule (child, async) |
| `mysqlFlexibleServer` | MySQL flexible server | Firewall rule (child, async) |
| `redis` | Azure Cache for Redis | Firewall rule (child) |
| `synapse` | Synapse workspace | Firewall rule (child, async) |
| `storageAccount` | Storage account | `networkAcls.ipRules[]` entry |
| `keyVault` | Key vault | `networkAcls.ipRules[]` entry |
| `cosmosDb` | Cosmos DB account | `ipRules[]` entry (async) |
| `containerRegistry` | Container registry | `networkRuleSet.ipRules[]` entry (async) |
| `aiSearch` | AI Search service | `networkRuleSet.ipRules[]` entry |
| `cognitiveServices` | Cognitive Services / Azure OpenAI | `networkAcls.ipRules[]` entry (async) |
| `kusto` | Data Explorer (Kusto) cluster | `allowedIpRangeList[]` entry (async) |
| `iotHub` | IoT hub | `networkRuleSets.ipRules[]` entry (async) |
| `signalR` | SignalR service | `networkACLs.ipRules[]` entry (async) |
| `eventHub` | Event Hubs namespace | `networkRuleSets/default` `ipRules[]` entry |
| `serviceBus` | Service Bus namespace | `networkRuleSets/default` `ipRules[]` entry |
| `appService` | App Service site (**and all of its deployment slots**) | `config/web` `ipSecurityRestrictions[]` + `scmIpSecurityRestrictions[]` entry |
| `aks` | AKS managed cluster | `apiServerAccessProfile.authorizedIPRanges[]` entry (full-body PUT, async) |

`port` is NSG-only (omit for any-port; supports ranges like `8080-8090`).

> **PostgreSQL / MySQL / Synapse** firewall-rule create and delete are **asynchronous**
> (long-running) operations — JIT polls the operation to completion before confirming the
> grant, and the expiry timer preserves the record for retry if a delete has not yet
> completed.
>
> **PostgreSQL flexible servers** must additionally be **public-access**: a private/VNet-
> integrated server (public network access disabled, or delegated to a subnet) has no
> firewall to write to, so such a request is rejected with `409 Conflict`.
>
> **AKS managed clusters** must be **public** clusters: a private cluster
> (`apiServerAccessProfile.enablePrivateCluster = true`) does not use API-server authorized
> IP ranges, so such a request is rejected with `409 Conflict`. JIT edits only
> `authorizedIPRanges` and **never writes an empty array** — it will not create the first
> range on an unrestricted (open) cluster, and on cleanup it refuses to remove the last
> range (which would open the API server to the internet), leaving that entry in place.
>
> **App Service sites** are whitelisted on **both** the main site and the SCM/Kudu site
> (`ipSecurityRestrictions[]` and `scmIpSecurityRestrictions[]`; when
> `scmIpSecurityRestrictionsUseMain = true` the SCM site inherits the main rules and only
> the main list is touched). Because an App Service with an empty restriction list is
> *unrestricted*, JIT only adds a rule when the site is **already restricted** (a concrete
> rule exists, or the list's default action is `Deny`) — a currently-open site is a no-op.
>
> A grant against an App Service also covers **every deployment slot** of that site. Slots
> are separate ARM children with their own independent allowlists
> (`.../sites/{name}/slots/{slot}/config/web`), so JIT enumerates them and applies the *same*
> rule to each — and revoking removes it from all of them again. The already-restricted guard
> is re-evaluated **independently per slot**, so an open slot stays open even when the site is
> restricted. **Consequence:** a grant on a production site also whitelists that site's
> staging/QA slots. If a slot cannot be enumerated or written, the site (and the remaining
> slots) still succeed and the shortfall is recorded on the audit record rather than failing
> the request.
>
> **Array-on-resource types** (`storageAccount`, `keyVault`, `cosmosDb`, `containerRegistry`,
> `aiSearch`, `cognitiveServices`, `kusto`, `iotHub`, `signalR`, `eventHub`, `serviceBus`,
> `appService`, `aks`)
> add or remove a single entry in an IP-allowlist array on the resource. To avoid two
> concurrent grants clobbering each other's entry, these use an optimistic-concurrency
> read-modify-write (ETag `If-Match`, bounded retry on `412`). Several of these updates are
> **eventually consistent** — the grant is confirmed once ARM accepts (or the long-running
> operation completes), but the resource may take a short time to enforce the new rule.
>
> **Tier / configuration caveats** (JIT never *creates* a restriction — it only edits an
> already network-restricted resource, so if the target is currently open the grant is a
> no-op that reports "no change"):
> - **Redis / Event Hubs / Service Bus / SignalR** require the **Standard tier** (or higher);
>   a Basic-tier resource has no firewall to manage.
> - **Container Registry** requires the **Premium SKU** and `networkRuleSet.defaultAction = Deny`.
> - **Cognitive Services / Container Registry / Cosmos DB** require `publicNetworkAccess`
>   **enabled** and the relevant `defaultAction = Deny` for the allowlist to take effect.

**Success response (200):**

```json
{
  "ruleId":         "jit-a1b2c3d4",
  "ruleIdentifier": "jit-a1b2c3d4",
  "targetType":     "nsg",
  "resource":       "/subscriptions/.../resourceGroups/my-rg/my-nsg",
  "callerIp":       "203.0.113.42",
  "port":           "443",
  "expiresUtc":     "2026-05-18T20:00:00.0000000Z",
  "requestedBy":    "user@contoso.com"
}
```

---

## Security Notes

- JWT validation performs full RS256 signature verification against Azure AD's JWKS with a 1-hour in-process cache and automatic key rotation handling.
- RBAC role assignments are looked up against ARM on every request; results are cached per-caller-per-subscription for 60 seconds so assignments and revocations take effect within ~1 minute without a restart.
- NSG priority assignment is protected by a distributed blob lease to prevent concurrent requests from colliding.
- Audit events (`JITGranted`, `JITDenied`, `JITExpired`, `JITRemoveFailed`, `JITRevoked`) are emitted as structured JSON to stdout and surfaced in the function app's standard logs (Log stream, Kudu, `az functionapp log tail`).
- The function app runs with a system-assigned managed identity; no credentials are stored.
- TLS 1.2 minimum, FTPS disabled, HTTPS-only enforced.
