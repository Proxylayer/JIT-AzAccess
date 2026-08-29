# JIT-AzAccess — Technical Reference

Audience: an engineering agent modifying this codebase. Terse, dense, example-first.
All paths are repo-relative to `c:\Users\jbland\source\repos\JIT-AzAccess`. `file:line`
pointers are exact against the source as read.

---

## 1. System overview & architecture

Three independently-deployed parts:

| Part | Location | Runtime | Role |
|---|---|---|---|
| **JIT API / enforcement** | `src/functionapp/` | PowerShell 7.2 Azure Functions (Consumption Y1) | The authority. Validates JWTs, checks RBAC, mutates target-resource firewalls via ARM REST, tracks active rules in Table Storage, auto-expires them on a timer. |
| **AzureTray plugin (client UI)** | `src/plugin/AzureTray.Plugin.JITAzAccess/` | .NET 8 class library loaded into the AzureTray tray host | Discovers targets client-side via ARM Resource Graph, discovers the function-app URL via Graph app-reg tags, calls the API, verifies grants, renders the tray menu. |
| **Deploy / admin scripts** | `src/scripts/` | PowerShell 7 + Azure CLI (`az`) / Az PowerShell (PIM only) | Provision infra, create/assign the two custom RBAC roles, configure PIM, health-check, tear down. |

**The AzureTray host app is a SEPARATE repo (read-only from here).** The plugin
implements host-provided `AzureTray.Plugin.Contracts` interfaces (see §12) and is
loaded by the host. This repo only contains the plugin, not the host.

### Zero Az modules in the function app
The function app uses **no `Az.*` PowerShell modules** (`src/functionapp/profile.ps1:3`,
`host.json` `managedDependency.enabled=false` at `src/functionapp/host.json:3-5`). Every
Azure call is `Invoke-RestMethod` via `Modules/HttpHelpers/HttpHelpers.psm1`: MI bearer
tokens for ARM/Graph, Shared-Key signing for Blob/Table data-plane. This drops ~400 MB
resident + ~5 s cold start (`HttpHelpers.psm1:10`).

### Data flow — grant (POST Request-JITAccess)
```
client (ARM token)
  -> Invoke-JwtValidation (RS256 verify, tid/iss/aud/exp)         JITHelpers.psm1:102
  -> parse+validate body, justification policy                    Request-JITAccess/run.ps1:103-203
  -> Test-CallerHasJitRequesterRole (RBAC in TARGET sub)          Request-JITAccess/run.ps1:213 / JITHelpers.psm1:289
  -> Get-CallerIp (X-Forwarded-For leftmost)                      JITHelpers.psm1:957
  -> abuse checks (per-caller/per-resource/cooldown) fail-closed  Request-JITAccess/run.ps1:247-317
  -> Add-JIT<X>Rule dispatch (NSG under blob lock)                Request-JITAccess/run.ps1:341-370
  -> branch on Status: Created|AlreadyPresent|SkippedOpen         Request-JITAccess/run.ps1:419-588
  -> Add-JITTableRow (JITRules) + Add-JITAuditRow (JITRulesAudit) + Write-JITAuditEvent (stdout)
```

### Data flow — expiry (timer, every 5 min)
```
Remove-ExpiredRules/run.ps1  ->  Get-JITTableRows (all)  ->  filter ExpiryUtc < now
  -> Remove-JIT<X>Rule dispatch                                  Remove-ExpiredRules/run.ps1:67-87
  -> branch Removed|NotFound (delete row) vs Refused (keep row)  Remove-ExpiredRules/run.ps1:98-184
  -> JITExpired / JITRemoveFailed audit + Add-JITAuditRow(Expire|RemoveFailed)
```

### Data flow — plugin
```
host TenantReady -> JitUrlDiscovery.DiscoverAsync (Graph app-reg tags jit-baseurl:*)
  -> ResourceDiscovery.DiscoverAsync (ARM Resource Graph, user's own token)
  -> poll GetActiveRulesAsync per URL (90s)                      JitAzAccessPlugin.cs:611
  -> user clicks target -> duration prompt -> justification/prod confirms
  -> JitClient.RequestAccessAsync (POST)                         JitClient.cs:43
  -> ArmVerifier.VerifyAsync (read-only ARM confirm)             ArmVerifier.cs:47
  -> VerifyAndNotifyAsync raises exactly one toast               JitAzAccessPlugin.cs:1347
```

---

## 2. Repository map

```
build.ps1                          # (repo root) build orchestrator — .NET plugin build
test.ps1                           # (repo root) Pester/standalone test runner (§14)
src/
  azuredeploy.json                 # subscription-scoped ARM template (§10, §13)
  azuredeploy.parameters.example.json
  README.md                        # user-facing overview (accurate; predates some plugin detail)
  JIT-AzAccess-Manager.json        # UNREFERENCED exported role def, hardcoded subs (§15)
  JIT-AzAccess.json                # UNREFERENCED exported JIT-Requester def, hardcoded subs (§15)
  functionapp/
    host.json                      # v2, extensionBundle [4.*,5.0.0), managedDependency off
    profile.ps1                    # cold-start URL self-register (jit-baseurl tag) (§11)
    Request-JITAccess/{function.json,run.ps1}   # POST — grant
    Get-JITRules/{function.json,run.ps1}        # GET  — list own active rules
    Revoke-JITAccess/{function.json,run.ps1}    # DELETE /{ruleId} — revoke own rule
    Remove-ExpiredRules/{function.json,run.ps1} # timer 0 */5 * * * * — expire
    Modules/
      HttpHelpers/HttpHelpers.psm1   # MI token, ARM REST (+Raw), Blob/Table SharedKey
      JITHelpers/JITHelpers.psm1     # JWT, RBAC check, config derivation, audit, table CRUD, NSG priority, blob lock, justification
      JITTargets/
        JITTargets.psm1              # thin loader: dot-sources _Shared then per-type files; Export-ModuleMember
        Targets/_Shared.ps1          # ConvertTo-Hashtable, Get-HeaderValue, IPv4 compare, Wait-JITArmAsyncOperation, Invoke-JITArmReadModifyWrite
        Targets/Nsg.ps1 ... Aks.ps1  # 19 per-type Add/Remove handler files
    tests/                           # Pester 3.4 + one standalone (§14)
  scripts/
    Deploy.ps1                     # end-to-end deploy orchestration
    Grant-JITPermissions.ps1       # create JIT-AzAccess Manager + JIT-Requester roles; assign Manager to MI
    Set-JITPim.ps1                 # PIM for Azure resources (Az PowerShell) — permanent eligible+active
    Remove-JITDeployment.ps1       # idempotent teardown (-KeepFunctionApp soft mode)
    Test-JITAccess.ps1             # 8-check health probe
  plugin/AzureTray.Plugin.JITAzAccess/
    JitAzAccessPlugin.cs           # ITrayPlugin entry point (menu, poll, grant/revoke, verify)
    AssetTypeCatalog.cs            # single source of truth: 19 AssetType records
    ResourceDiscovery.cs           # ARM Resource Graph KQL -> JitTarget list
    JitUrlDiscovery.cs             # Graph app-reg tag scan -> per-sub URL map
    JitClient.cs                   # typed HTTP client for the 3 endpoints
    ArmVerifier.cs                 # post-grant read-only ARM confirmation
    JitHttpException.cs            # carries StatusCode/Operation/ServerError
    ActiveRulesStore.cs / FavoritesStore.cs   # local JSON persistence in DataDir
    Models/{JitTarget,JitRequest,JitServerRule,JitGrantResponse,ActiveRule}.cs
```

---

## 3. Authorization model

Two authN/authZ layers: (1) **authentication** = JWT validation; (2) **authorization**
= holding the hardcoded `JIT-Requester` custom RBAC role in the *target* subscription.

### JWT validation — `Invoke-JwtValidation` (`JITHelpers.psm1:102-249`)
Full RS256 verification; returns the decoded payload PSObject or `$null`.
Checks in order: 3-part token; `alg == RS256` (`:161`); `exp` not past (`:168`);
`nbf` not future (`:174`); `tid == TenantId` (`:180`); `iss ∈ {https://sts.windows.net/<tid>/,
https://login.microsoftonline.com/<tid>/v2.0}` (`:186-190`); `aud ∈` accepted ARM audiences
(`:196-204`); JWKS signature (`:206-241`, fetches `https://login.microsoftonline.com/<tid>/discovery/v2.0/keys`,
1 h cache `JwksCacheTtl` `:17`, one forced-refresh retry on kid miss `:211-215`).

Accepted audiences default (`$script:DefaultArmAudiences` `JITHelpers.psm1:44-49`):
`https://management.azure.com/`, `https://management.azure.com`,
`https://management.core.windows.net/`, `https://management.core.windows.net`.
Override via env `EXPECTED_AUDIENCES` (comma-separated) for sovereign clouds (`:138-147`).

**Claims consumed by handlers:**
| Claim | Use | Where |
|---|---|---|
| `oid` | caller AAD object id -> RBAC check (`$callerObjectId`) | Request `run.ps1:89`, Revoke `run.ps1:47`, Get `run.ps1:48` |
| `upn` (then `unique_name`, then `sub`) | `$requestedBy` audit identity + row ownership | Request `run.ps1:79-81`, Get `run.ps1:54-56`, Revoke `run.ps1:53-55` |
| `tid` | validated == expected tenant | `:180` |

### RBAC role check — `Test-CallerHasJitRequesterRole` (`JITHelpers.psm1:289-377`)
Role name literal: `$script:JitRequesterRoleName = 'JIT-Requester'` (`JITHelpers.psm1:21`) —
**hardcoded, deliberately NOT env-configurable.**

Flow: resolve the role-definition GUID in the subscription via
`GET /subscriptions/<sub>/providers/Microsoft.Authorization/roleDefinitions?$filter=roleName eq 'JIT-Requester'`
(`Get-JitRequesterRoleDefinitionGuid` `:255-287`, cached per-sub `JitRoleDefIdCache` `:26`).
Then list the caller's assignments at `/subscriptions/<sub>` scope with the ARM
`assignedTo('<oid>')` filter, following `nextLink` pagination (`:341-353`), and match the
role-def GUID (`:363-366`). `assignedTo()` includes assignments inherited from a parent
management group and on child RG/resource scopes.

**Evaluated against the TARGET subscription** (the request-body `subscriptionId` /
the rule's `SubscriptionId`), NOT the function app's own host subscription. Deferred until
after body parse in Request (`run.ps1:213`) and after rule lookup in Revoke (`run.ps1:103`).

Decision cache: `RoleCheckCache` keyed `"{oid}|{sub}"`, TTL 60 s for both allow and deny
(`JITHelpers.psm1:33-34`, `:314-320`, `:375`) — so grants/revocations of the role take
effect within ~1 min without a restart.

### Endpoint authorization summary
| Endpoint | AuthN | AuthZ |
|---|---|---|
| `Request-JITAccess` | JWT | must hold `JIT-Requester` in body `subscriptionId` |
| `Revoke-JITAccess` | JWT | own the row (`RequestedBy == upn`) **and** hold `JIT-Requester` in the rule's `SubscriptionId` |
| `Get-JITRules` | JWT only | **none** — returns only rows where `RequestedBy == caller` (`Get-JITRules/run.ps1:72`) |
| `Remove-ExpiredRules` | timer (no HTTP) | n/a — runs as MI |

### `JIT-AzAccess Manager` role (MI-only)
The function app's system-assigned MI holds this role on each target subscription so it
can read/write the resource firewalls. Name literal `'JIT-AzAccess Manager'`
(`Grant-JITPermissions.ps1:50`). Actions list: `Grant-JITPermissions.ps1:54-132` (includes
`Microsoft.Authorization/roleAssignments/read` + `roleDefinitions/read` for the RBAC check
at `:130-131`). Never assigned to end users.

---

## 4. The 19 asset types

Token order and dispatch match `$supportedTypes` (`Request-JITAccess/run.ps1:136-141`,
`Remove-ExpiredRules/run.ps1:45-50`) and `AssetTypeCatalog.All` (`AssetTypeCatalog.cs:35-61`).

| Token | ARM type (canonical) | ARG type (lowercase) | Mechanism | api-version | Write verb | LRO? | Key gotcha |
|---|---|---|---|---|---|---|---|
| `nsg` | `Microsoft.Network/networkSecurityGroups` | `microsoft.network/networksecuritygroups` | child `securityRules/{id}` | `2024-03-01` | PUT child | no | dup-detect exact single-IP only; opens ANY port/proto for the IP; requested port audit-only |
| `sqlServer` | `Microsoft.Sql/servers` | `microsoft.sql/servers` | child `firewallRules/{id}` | `2021-11-01` | PUT child | no | start==end single IP |
| `postgresqlFlexibleServer` | `Microsoft.DBforPostgreSQL/flexibleServers` | `microsoft.dbforpostgresql/flexibleservers` | child `firewallRules/{id}` | `2024-08-01` | PUT child (Raw) | **yes** 202 | rejects private/VNet server (sentinel -> 409) |
| `storageAccount` | `Microsoft.Storage/storageAccounts` | `microsoft.storage/storageaccounts` | prop `networkAcls.ipRules[]` `{value,action}` | `2023-01-01` | PATCH full networkAcls | no | no networkAcls => SkippedOpen |
| `keyVault` | `Microsoft.KeyVault/vaults` | `microsoft.keyvault/vaults` | prop `networkAcls.ipRules[]` `{value}` | `2023-07-01` | PATCH full networkAcls | no | stores `<ip>/32`; no networkAcls => SkippedOpen |
| `mysqlFlexibleServer` | `Microsoft.DBforMySQL/flexibleServers` | `microsoft.dbformysql/flexibleservers` | child `firewallRules/{id}` | `2023-12-30` | PUT child (Raw) | tolerated 202 | start==end |
| `redis` | `Microsoft.Cache/Redis` | `microsoft.cache/redis` | child `firewallRules/{id}` | `2024-11-01` | PUT child (Raw) | tolerated 202 | body uses `startIP`/`endIP` (not `...IpAddress`); Standard+ tier |
| `synapse` | `Microsoft.Synapse/workspaces` | `microsoft.synapse/workspaces` | child `firewallRules/{id}` | `2021-06-01` | PUT child (Raw) | **yes** 202 | start==end |
| `cosmosDb` | `Microsoft.DocumentDB/databaseAccounts` | `microsoft.documentdb/databaseaccounts` | prop `ipRules[]` `{ipAddressOrRange}` | `2024-11-15` | PATCH via RMW | yes (Async header) | empty ipRules => SkippedOpen; needs publicNetworkAccess+Deny |
| `containerRegistry` | `Microsoft.ContainerRegistry/registries` | `microsoft.containerregistry/registries` | prop `networkRuleSet.ipRules[]` `{action,value}` | `2023-07-01` | PATCH via RMW | yes | Premium SKU + defaultAction=Deny; no networkRuleSet => SkippedOpen |
| `aiSearch` | `Microsoft.Search/searchServices` | `microsoft.search/searchservices` | prop `networkRuleSet.ipRules[]` `{value}` | `2023-11-01` | **PUT** full resource via RMW | no (sync) | no PATCH exists; empty ipRules => SkippedOpen |
| `cognitiveServices` | `Microsoft.CognitiveServices/accounts` | `microsoft.cognitiveservices/accounts` | prop `networkAcls.ipRules[]` `{value}` | `2024-10-01` | PATCH via RMW | yes | covers Azure OpenAI; no networkAcls => SkippedOpen |
| `kusto` | `Microsoft.Kusto/clusters` | `microsoft.kusto/clusters` | prop `allowedIpRangeList[]` (bare strings) | `2024-04-13` | PATCH via RMW | yes | empty list => SkippedOpen |
| `iotHub` | `Microsoft.Devices/IotHubs` | `microsoft.devices/iothubs` | prop `networkRuleSets.ipRules[]` `{filterName,action,ipMask}` | `2023-06-30` | **PUT** full resource via RMW | yes | filterName=RuleId (unique); match/remove by ipMask |
| `signalR` | `Microsoft.SignalRService/signalR` | `microsoft.signalrservice/signalr` | prop `networkACLs.ipRules[]` `{value,action}` | `2024-03-01` | PATCH via RMW | yes | note `networkACLs` casing; Standard+ tier |
| `eventHub` | `Microsoft.EventHub/namespaces` | `microsoft.eventhub/namespaces` | singleton child `networkRuleSets/default` `properties.ipRules[]` `{action,ipMask}` | `2024-01-01` | **PUT** child via RMW | no (sync) | Standard+ tier; Basic 404s => modification failure; match by ipMask |
| `serviceBus` | `Microsoft.ServiceBus/namespaces` | `microsoft.servicebus/namespaces` | singleton child `networkRuleSets/default` `properties.ipRules[]` `{action,ipMask}` | `2024-01-01` | **PUT** child via RMW | no (sync) | same as EventHub |
| `appService` | `Microsoft.Web/sites` | `microsoft.web/sites` | config child `config/web` `ipSecurityRestrictions[]` + `scmIpSecurityRestrictions[]` `{ipAddress,action,priority,name,description}` — on the site **and every deployment slot** (`.../sites/{name}/slots/{slot}/config/web`) | `2024-04-01` | PATCH `config/web` via RMW, once per resource (site + N slots) | no (sync) | only whitelists an ALREADY-restricted resource, guard re-evaluated per slot; stores `<ip>/32`; priority band 3000-3900, computed per resource; slots enumerated via `GET .../sites/{name}/slots` (paged) |
| `aks` | `Microsoft.ContainerService/managedClusters` | `microsoft.containerservice/managedclusters` | prop `apiServerAccessProfile.authorizedIPRanges[]` (bare `<ip>/32`) | `2025-05-01` | **PUT** full resource via RMW | yes | rejects private cluster (sentinel->409); never empties array (ADD skips open, REMOVE refuses last) |

Per-type files (all under `src/functionapp/Modules/JITTargets/Targets/`): `Nsg.ps1`,
`SqlServer.ps1`, `PostgresqlFlexibleServer.ps1`, `StorageAccount.ps1`, `KeyVault.ps1`,
`MysqlFlexibleServer.ps1`, `Redis.ps1`, `Synapse.ps1`, `CosmosDb.ps1`,
`ContainerRegistry.ps1`, `AiSearch.ps1`, `CognitiveServices.ps1`, `Kusto.ps1`,
`IotHub.ps1`, `SignalR.ps1`, `EventHub.ps1`, `ServiceBus.ps1`, `AppService.ps1`, `Aks.ps1`.

Each per-type file owns its own `$script:<Type>Api` version constant (co-located with the
handler); `PostgresqlFlexibleServer.ps1` and `Aks.ps1` also own their LRO bounds and the
`PRIVATE_SERVER_REJECTED:` sentinel. Load order is fixed by the loader
(`JITTargets.psm1:22-50`): `_Shared.ps1` first, then the per-type files.

**Mechanism families:**
- *Child firewall rule* (independently addressable): nsg, sqlServer, postgres, mysql, redis, synapse — PUT/DELETE a `.../{id}` child.
- *Property array on the resource* (PATCH or PUT full container sub-object): storage, keyVault, cosmosDb, containerRegistry, aiSearch, cognitiveServices, kusto, iotHub, signalR, aks.
- *Singleton child array* (`networkRuleSets/default`): eventHub, serviceBus.
- *Config-child array-of-objects* (`config/web`): appService. This is the only family where **one JITRules row drives N ARM writes**: the handler applies the same rule name to the site's `config/web` and to each deployment slot's `slots/{slot}/config/web`, so a grant on a production site also whitelists that site's staging/QA slots. Slot enumeration and per-slot writes are best effort — failures are warned about and recorded in `Details` (`slotCount`, `slots`, `slotFailures`, `slotEnumerationFailed`) rather than aborting the operation. That `Details` payload is persisted to the JITRulesAudit `Details` column (section 8), so partial coverage is auditable and not merely logged.

---

## 5. Handler contracts (CRITICAL for extensibility)

### Add-JIT&lt;X&gt;Rule
**Signature (uniform):**
```powershell
function Add-JIT<X>Rule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )   # NSG also takes -Port, -PriorityMin, -PriorityMax
}
```
Called via splat `@addParams` (`Request-JITAccess/run.ps1:331-337`). NSG additionally
gets `-Port $portVal -PriorityMin $priorityMin -PriorityMax $priorityMax` (`run.ps1:346`).

**Return contract:** `@{ RuleIdentifier=<string>; Status='Created'|'AlreadyPresent'|'SkippedOpen'; Details=@{} }`

| Status | Meaning | How detected |
|---|---|---|
| `Created` | rule added for caller IP | write performed (RMW `Changed=$true`, or child PUT ran) |
| `AlreadyPresent` | caller IP already whitelisted | child types: `Test-JITFirewallRuleCoversIp` / exact-source match (NSG); array types: entry with matching value/ipMask/`<ip>/32` present |
| `SkippedOpen` | resource is open/unrestricted; adding would restrict it | no networkAcls/networkRuleSet, or empty ipRules/allowedIpRangeList/authorizedIPRanges array, or App Service site **and all of its slots** not restricted |

`RuleIdentifier` conventions: child-rule types store the rule name (`$RuleId`); array-value
types store the caller IP (`$CallerIp`); Key Vault stores `<ip>/32` (`KeyVault.ps1:47`);
App Service stores the rule name, shared by the site and **all** of its deployment slots — a
single identifier is what lets one row revoke every resource the grant touched.

The dispatcher treats a missing Status as `Created` (`Request-JITAccess/run.ps1:410`).

`Details` is **persisted**, not log-only: the dispatcher captures it as `$grantDetails`
(`run.ps1:417`) and passes it to every audit row it writes, where it is stored as compact JSON
in the JITRulesAudit `Details` column (section 8). An empty `Details` writes no column, so
handlers with nothing to report cost nothing.

### Remove-JIT&lt;X&gt;Rule
**Signature (uniform):** `param([Parameter(Mandatory)]$Row)` — receives the full JITRules table row.

**Return contract:** `@{ Status='Removed'|'NotFound'|'Refused'; Details=@{} }`

| Status | Meaning | Row disposition |
|---|---|---|
| `Removed` | rule deleted from resource | delete JITRules row |
| `NotFound` | rule already absent (manual delete / idempotent) | delete JITRules row |
| `Refused` | removing would open the resource | **KEEP** the row; do not report success |

`Refused` is **AKS-only** (`Aks.ps1:126-130`): if removing the caller's IP would empty
`authorizedIPRanges`, the handler refuses (writing an empty array opens the API server to
the internet). Revoke maps it to HTTP 409 + retains row (`Revoke-JITAccess/run.ps1:164-191`);
the timer keeps the row and retries next tick (`Remove-ExpiredRules/run.ps1:98-121`).
Both `NotFound` and `Removed` cause row deletion; missing Status is treated as `Removed`
(`Revoke run.ps1:157`, `Remove-ExpiredRules run.ps1:91`).

`Details` is **persisted** on the Remove path too — captured as `$removeDetails`
(`Revoke run.ps1:162`, `Remove-ExpiredRules run.ps1:96`) and written to the JITRulesAudit
`Details` column (section 8) on the `Revoke` / `Expire` / `RemoveFailed` rows. This is what
makes a partial removal (App Service slot failure or failed slot enumeration) auditable
rather than log-only.

Every Remove handler falls back `RuleIdentifier ?? RowKey` (child types) or
`RuleIdentifier ?? CallerIp` (array types) so an older row with a null column still cleans
up (rationale at `Nsg.ps1:76-82`). 404 on a child DELETE is swallowed as `NotFound`
(`Get-StatusFromError` == 404).

### Shared helpers — `Targets/_Shared.ps1`

**`Invoke-JITArmReadModifyWrite`** (`_Shared.ps1:157-274`) — optimistic-concurrency RMW for
array-on-resource types.
```powershell
Invoke-JITArmReadModifyWrite `
    -Path <armPath-no-apiversion> `
    -ApiVersion $script:<Type>Api `
    -WriteMethod PATCH|PUT `            # default PATCH
    -MaxAttempts 5 `                    # 412 retry bound
    -LroTimeoutSeconds 180 -LroDefaultPollSeconds 5 `
    -Modify { param($resource) <return body-to-write | $false> }
# returns @{ Changed = <bool> }
```
Steps: (1) `Invoke-ArmRestRaw GET` capturing `ETag` (`:229-231`); (2) run `-Modify`; block
returns `$false` for no-op (idempotent) or the body to write; last pipeline value is used
(`:236-240`); (3) write with `If-Match: <etag>` when present — 412 -> re-GET + retry, else
throw (`:263-270`); (4) poll if 202 **or** a 200/201 carrying `Azure-AsyncOperation`
(`:255-260`). The `-Modify` block must return the **whole container sub-object** (e.g.
`@{ properties=@{ networkAcls=$fullAcl } }` for PATCH, or the mutated `$resource` for PUT)
so sibling fields (defaultAction/bypass/privateEndpoints) are preserved — a partial write
would reset the resource's posture.

**`Wait-JITArmAsyncOperation`** (`_Shared.ps1:81-155`) — polls a 202's
`Azure-AsyncOperation` header (falls back to `Location`), honoring `Retry-After`
(clamped 1-30 s), until JSON `status` is `Succeeded` (return), `Failed`/`Canceled`/`Cancelled`
(throw), else keep polling until `-TimeoutSeconds` (throw timeout).

**`Test-JITFirewallRuleCoversIp`** (`_Shared.ps1:50-79`) — `$true` if the caller IPv4 falls in
any rule's `[start,end]`. Field names default `startIpAddress`/`endIpAddress`; Redis passes
`-StartField startIP -EndField endIP` (`Redis.ps1:35`). Non-IPv4 caller -> `$false`.
**`ConvertTo-JITIpv4Number`** (`_Shared.ps1:36-48`) — dotted-quad IPv4 -> big-endian `[int64]`
for comparison; `$null` for IPv6/CIDR/garbage.

**`Get-HeaderValue`** (`_Shared.ps1:25-34`) — case-insensitive lookup in the normalized header
hashtable from `Invoke-ArmRestRaw`.

**`ConvertTo-Hashtable`** (`_Shared.ps1:12-23`) — shallow-clone a PSCustomObject to a hashtable
so one property can be changed and the whole object PATCHed back (used by all networkAcls /
networkRuleSet / networkACLs types to preserve siblings).

Usage example (minimal array-type Add):
```powershell
$r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:FooApi -WriteMethod PATCH -Modify {
    param($resource)
    $acls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }
    if (-not $acls) { $outcome.Reason = 'SkippedOpen'; return $false }
    $ipRules = @(); if ($acls.ipRules) { $ipRules = @($acls.ipRules) }
    if ($ipRules | Where-Object { $_.value -eq $CallerIp }) { $outcome.Reason = 'AlreadyPresent'; return $false }
    $h = ConvertTo-Hashtable $acls
    $h.ipRules = @($ipRules) + @(@{ value = $CallerIp })
    return @{ properties = @{ networkAcls = $h } }
}
```

### Private-server rejection sentinel
`$script:PostgresPrivateRejectPrefix = 'PRIVATE_SERVER_REJECTED:'` (`PostgresqlFlexibleServer.ps1:24`);
AKS reuses the identical literal `$script:AksPrivateRejectPrefix` (`Aks.ps1:37`). Handlers
`throw "$prefix <message>"` when the target can't use IP firewalling (Postgres private/VNet
server `PostgresqlFlexibleServer.ps1:53-55`; AKS private cluster `Aks.ps1:70-72`).
`Request-JITAccess` catches, strips the prefix, and returns **409 Conflict** + a `JITDenied`
audit with `DenyReason='PrivateServerNotSupported'` (`Request-JITAccess/run.ps1:378-386`).
**Keep the literal identical in the handler and the run.ps1 match (`-like 'PRIVATE_SERVER_REJECTED:*'`).**

---

## 6. STEP-BY-STEP: add a new asset type

Worked checklist for a new token `foo` (`Microsoft.Foo/bars`):

1. **Create** `src/functionapp/Modules/JITTargets/Targets/Foo.ps1` with
   `$script:FooApi = '<api-version>'` and `Add-JITFooRule` / `Remove-JITFooRule` (skeletons below).
2. **Loader** — add `. "$PSScriptRoot\Targets\Foo.ps1"` in `JITTargets.psm1` (after `_Shared`,
   `:24-50`) and add both function names to `Export-ModuleMember` (`JITTargets.psm1:52-72`).
3. **Dispatch × 3 run.ps1 files:**
   - `Request-JITAccess/run.ps1`: add `'foo'` to `$supportedTypes` (`:136-141`) and a
     `'foo' { Add-JITFooRule @addParams }` arm in the switch (`:350-369`).
   - `Revoke-JITAccess/run.ps1`: add `'foo' { Remove-JITFooRule -Row $row }` (`:116-139`).
   - `Remove-ExpiredRules/run.ps1`: add `'foo'` to `$supportedTypes` (`:45-50`) and a
     `'foo' { Remove-JITFooRule -Row $row }` arm (`:67-87`).
4. **RBAC actions** — add the read/write (and firewallRules/delete for child types) actions to
   `$roleActions` in `Grant-JITPermissions.ps1` (`:54-132`) **and** to `$requiredManagerActions`
   in `Test-JITAccess.ps1` (`:193-250`, keep the two in sync). **Redeploy the Manager role**
   (`Grant-JITPermissions.ps1`) — it refreshes Actions; without this the MI 403s at runtime.
5. **Plugin catalog** — add one `AssetType` record to `AssetTypeCatalog.All`
   (`AssetTypeCatalog.cs:35-61`): `new AssetType("foo","Microsoft.Foo/bars","microsoft.foo/bars","Foo")`.
   This alone wires discovery (KQL `type in~`), the ARM->token map, the `include.foo` config
   checkbox, and the menu label.
6. **ArmVerifier** (`ArmVerifier.cs`) — child-rule type: add a `"foo" => VerifyChildFirewallRuleAsync(...)`
   arm (`:62-89`) + an api-version const (`:22-30`). Array type: leave it — the `_` arm returns
   `VerificationResult.Skipped` (`:88`).

**Minimal CHILD-type skeleton:**
```powershell
$script:FooApi = '2024-01-01'
function Add-JITFooRule {
    param([Parameter(Mandatory)][string]$SubscriptionId,[Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$ResourceName,[Parameter(Mandatory)][string]$CallerIp,
          [Parameter(Mandatory)][string]$RuleId)
    $base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Foo/bars/$ResourceName"
    $existing = Invoke-ArmRest -Path "$base/firewallRules" -ApiVersion $script:FooApi
    if (Test-JITFirewallRuleCoversIp -Rules $existing.value -CallerIp $CallerIp) {
        return @{ RuleIdentifier=$RuleId; Status='AlreadyPresent'; Details=@{} } }
    Invoke-ArmRest -Method PUT -Path "$base/firewallRules/$RuleId" -ApiVersion $script:FooApi -Body @{
        properties=@{ startIpAddress=$CallerIp; endIpAddress=$CallerIp } } | Out-Null
    return @{ RuleIdentifier=$RuleId; Status='Created'; Details=@{} }
}
function Remove-JITFooRule {
    param([Parameter(Mandatory)]$Row)
    $ruleName = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.RowKey }
    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)/providers/Microsoft.Foo/bars/$($Row.ResourceName)/firewallRules/$ruleName"
    try { Invoke-ArmRest -Method DELETE -Path $path -ApiVersion $script:FooApi | Out-Null; return @{ Status='Removed'; Details=@{} } }
    catch { if ((Get-StatusFromError $_) -eq 404) { return @{ Status='NotFound'; Details=@{} } } else { throw } }
}
```

**Minimal ARRAY-type skeleton:**
```powershell
$script:FooApi = '2024-01-01'
function Add-JITFooRule {
    param([Parameter(Mandatory)][string]$SubscriptionId,[Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$ResourceName,[Parameter(Mandatory)][string]$CallerIp,
          [Parameter(Mandatory)][string]$RuleId)
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Foo/bars/$ResourceName"
    $outcome = @{ Reason = 'SkippedOpen' }
    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:FooApi -WriteMethod PATCH -Modify {
        param($resource)
        $acls = if ($resource.properties) { $resource.properties.networkAcls } else { $null }
        if (-not $acls) { $outcome.Reason='SkippedOpen'; return $false }
        $ipRules = @(); if ($acls.ipRules) { $ipRules = @($acls.ipRules) }
        if ($ipRules | Where-Object { $_.value -eq $CallerIp }) { $outcome.Reason='AlreadyPresent'; return $false }
        $h = ConvertTo-Hashtable $acls
        $h.ipRules = @($ipRules) + @(@{ value = $CallerIp })
        return @{ properties = @{ networkAcls = $h } }
    }
    if (-not $r.Changed) { return @{ RuleIdentifier=$CallerIp; Status=$outcome.Reason; Details=@{} } }
    return @{ RuleIdentifier=$CallerIp; Status='Created'; Details=@{} }
}
```

---

## 7. Endpoints & request flow

`function.json` bindings — all `authLevel: anonymous` (auth is done in-code via JWT):

| Endpoint | Method | Route | Trigger |
|---|---|---|---|
| Request-JITAccess | POST | `/api/Request-JITAccess` | http (`Request-JITAccess/function.json`) |
| Get-JITRules | GET | `/api/Get-JITRules` | http |
| Revoke-JITAccess | DELETE | `/api/Revoke-JITAccess/{ruleId}` | http, `route: Revoke-JITAccess/{ruleId}` |
| Remove-ExpiredRules | — | — | timerTrigger `0 */5 * * * *`, `runOnStartup:false` |

### Request-JITAccess (`Request-JITAccess/run.ps1`)
Validation gate order: bearer present (401) -> JWT valid (403 `TokenValidationFailed`) ->
`oid` present (403 `MissingObjectIdClaim`) -> body parseable (400) -> `targetType` in
`$supportedTypes` (400) -> required fields present (400) -> `durationHours` in
`ALLOWED_DURATIONS_HOURS` (400) -> `subscriptionId` GUID regex (400) -> `resourceGroup`
`^[a-zA-Z0-9._\-()]{1,90}$` (400) -> `resourceName` `^[a-zA-Z0-9._\-]{1,90}$` (400) ->
`port` `^\d{1,5}(-\d{1,5})?$` (400) -> justification (400 if required+missing) -> justification
≤ 500 chars (400) -> **RBAC** (403 `MissingJitRequesterRole`) -> caller IP determinable +
not loopback + format (400) -> abuse checks.

Abuse checks (`run.ps1:247-317`, **fail-closed** -> 503 on Storage error):
`JIT_MAX_RULES_PER_CALLER` (default 5) -> 429; `JIT_MAX_RULES_PER_RESOURCE` (default 20) ->
429; cooldown (an active rule already exists for this caller+resource+sub) -> 409 with
`existingRuleId`/`expiresUtc`.

Rule id: `jit-<callerUser>-<8hex>` where `callerUser` = UPN local-part, alnum-only, lower,
≤20 chars (`run.ps1:322-326`). Port stored `'*'` when omitted.

Add-status branching (`run.ps1:419-588`):
| Add Status | Action | Response `status` / HTTP |
|---|---|---|
| `SkippedOpen` | audit `SkippedOpen`; no JITRules row, no scheduled removal | `SkippedOpen` / 200 |
| `AlreadyPresent` + JIT-managed row exists | `Update-JITTableRow` ExpiryUtc; audit `Extend` | `Extended` / 200 |
| `AlreadyPresent` + no JIT row (external) | audit `AlreadyExternal`; track nothing | `AlreadyWhitelisted` / 200 |
| `Created` (or missing) | `Add-JITTableRow`; `Write-JITAuditEvent JITGranted`; audit `Grant` | `Created` / 200 |

Error mapping: `PRIVATE_SERVER_REJECTED:*` -> 409 (`PrivateServerNotSupported`); any other
throw -> 500 with `detail` (`run.ps1:389-397`).

**Example request body** (`JitRequest`, `Models/JitRequest.cs`):
```json
{ "targetType":"nsg", "subscriptionId":"11111111-1111-1111-1111-111111111111",
  "resourceGroup":"my-rg", "resourceName":"my-nsg", "durationHours":4,
  "port":"443", "justification":"Investigating incident #12345" }
```
**Example 200 (Created)** (`run.ps1:571-584`):
```json
{ "status":"Created","ruleId":"jit-jbland-cc5d7ef8","ruleIdentifier":"jit-jbland-cc5d7ef8",
  "targetType":"nsg","resource":"/subscriptions/.../resourceGroups/my-rg/my-nsg",
  "subscriptionId":"...","resourceGroup":"my-rg","resourceName":"my-nsg",
  "callerIp":"203.0.113.42","port":"443","expiresUtc":"2026-07-24T20:00:00.0000000Z",
  "requestedBy":"user@contoso.com" }
```
**Errors:** 403 `{ "error":"Caller does not hold the 'JIT-Requester' RBAC role in subscription '...'.","requiredRole":"JIT-Requester" }`;
400 `{ "error":"Justification is required for JIT access requests." }`;
409 `{ "error":"An active JIT rule already exists for this resource. Wait for it to expire or revoke it first.","existingRuleId":"jit-...","expiresUtc":"..." }`.

### Get-JITRules (`Get-JITRules/run.ps1`)
JWT only. Returns a JSON **array** of the caller's active (non-expired, `RequestedBy==upn`)
rows projected to `{ruleId,targetType,subscriptionId,resourceGroup,resourceName,ruleIdentifier,
callerIp,port,requestedBy,expiresUtc,justification}` (`run.ps1:74-88`). Sets response header
`X-JIT-Caller-IP` = the caller's current public IP (`run.ps1:96`) so the plugin can flag
already-allowed resources.

### Revoke-JITAccess (`Revoke-JITAccess/run.ps1`)
`ruleId` regex `^jit-([a-z0-9]{1,20}-)?[0-9a-fA-F]{8}$` (`run.ps1:70`). Look up by
`RowKey eq '<ruleId>'` (scan; partition unknown) -> 404 if absent. Ownership check
`RequestedBy == upn` (403). RBAC check in the rule's sub (403). Remove-status branching:
`Refused` -> 409 + keep row + `RemoveFailed` audit (`run.ps1:159-186`); `Removed`/`NotFound`
-> `JITRevoked` audit + `Revoke` audit row + delete JITRules row -> 200
`{status,ruleId,revokedBy,targetType,resourceName}`.

### Remove-ExpiredRules (`Remove-ExpiredRules/run.ps1`)
No HTTP. Reads all rows, filters `ExpiryUtc < now`. Unknown targetType -> delete stale row,
no audit (`run.ps1:58-63`). Else dispatch Remove; `Refused` -> keep row + `JITRemoveFailed`/
`RemoveFailed` audit; `Removed`/`NotFound` -> `JITExpired`/`Expire` audit + delete row; a
thrown error -> `JITRemoveFailed`/`RemoveFailed` audit + **keep** row for next-tick retry.

---

## 8. Storage tables

Both tables live in `AzureWebJobsStorage` (Shared-Key via `Invoke-TableRest`,
`HttpHelpers.psm1:533`). Table names cannot contain hyphens (Azure constraint).

### JITRules — CURRENTLY-active rules (one row per active grant)
Name from env `JIT_TABLE_NAME`, default `JITRules`. Created on demand by `Get-JITTableName`
(`JITHelpers.psm1:778-794`).

| Column | Semantics |
|---|---|
| `PartitionKey` | subscriptionId |
| `RowKey` | ruleId (`jit-<user>-<8hex>`) |
| `TargetType` | asset token |
| `ResourceName` | resource name |
| `ResourceRg` | resource group (note column name `ResourceRg`, not `ResourceGroup`) |
| `SubscriptionId` | target subscription (== PartitionKey) |
| `RuleIdentifier` | per-type identifier (rule name / IP / `<ip>/32`) — key used by Remove |
| `CallerIp` | granted IP |
| `Port` | port or `*` |
| `RequestedBy` | UPN (ownership + Get filter) |
| `ExpiryUtc` | ISO-8601 `o` UTC — drives expiry + active filtering |
| `Justification` | free-text or `''` |

Written by `Add-JITTableRow` (`Request-JITAccess/run.ps1:538-551`); expiry refreshed by
`Update-JITTableRow` (MERGE, `If-Match:*`; `Request-JITAccess/run.ps1:470`); deleted by
`Remove-JITTableRow` (Revoke `run.ps1:227`, timer `run.ps1:178`); read by `Get-JITTableRows`
(Get, Revoke lookup, abuse checks, timer scan). Helpers: `JITHelpers.psm1:796-867`.

### JITRulesAudit — append-only lifecycle history (one row per event)
Name from env `JIT_AUDIT_TABLE_NAME`, default `JITRulesAudit`
(`Get-JITAuditTableName` `JITHelpers.psm1:873-894`). RowKey is a unique per-event id
`<ISO8601>-<guid8>` (`:930`) so multiple events for one rule coexist. PartitionKey =
subscriptionId. Columns: `PartitionKey,RowKey,Action,EventUtc,TargetType,ResourceName,
ResourceRg,SubscriptionId,RuleIdentifier,CallerIp,Port,RequestedBy,ExpiryUtc,Justification`
plus an optional `Details` column (below) plus any `-Extra` merge
(`Add-JITAuditRow` `JITHelpers.psm1:960-1030`).

**`Action` values** (audit row): `Grant`, `Extend`, `AlreadyExternal`, `SkippedOpen`
(all in `Request-JITAccess/run.ps1`), `Revoke` (`Revoke-JITAccess/run.ps1:213`), `Expire`
(`Remove-ExpiredRules/run.ps1:138`), `RemoveFailed` (Revoke `:175`, timer `:109`/`:162`).

#### `Details` column — persisted handler Details

The `Details` hashtable every target handler returns (section 5) is persisted here as
**compact JSON in a single `Details` string column**. Table properties are flat scalars and
`Details` is nested (`slots` / `slotFailures` are themselves maps), so it is serialized whole
rather than exploded into columns. Serialization: `ConvertTo-JITAuditDetails`
(`JITHelpers.psm1:909-958`), `ConvertTo-Json -Compress -Depth 6` — depth matters, the default
of 2 silently mangles the nested per-slot maps.

| Situation | Stored |
|---|---|
| `Details` empty or `$null` (most handlers) | **column omitted entirely** — no `{}` noise on every row |
| normal payload | the compact JSON, e.g. `{"site":"Removed","slotCount":2,"slots":{"staging":"Removed","qa":"Failed"},"slotFailures":{"qa":"403 Forbidden"}}` |
| payload > **8192 chars** | replaced by a still-valid JSON envelope `{"_truncated":true,"_originalLength":<n>,"_preview":"<first 1024 chars>"}` — truncation is never silent |
| serialization throws | column omitted, `Write-Warning` emitted; the audit row is still written |

The 8192-char cap is a deliberately conservative fraction of the Azure Table limits (64 KB per
string property, 1 MB per entity): the richest payload today is App Service's one short entry
per deployment slot, and the platform maximum is 20 slots. **Auditing never fails the
operation** — serialization and truncation problems degrade the row, they do not throw.

Populated from the dispatcher's handler result at every call site where one exists:
`$grantDetails` (`Request-JITAccess/run.ps1:417` -> `Grant` `:560`, `Extend` `:477`,
`AlreadyExternal` `:505`, `SkippedOpen` `:427`), `$removeDetails`
(`Revoke-JITAccess/run.ps1:162` -> `Revoke` `:213`, `RemoveFailed` `:175`;
`Remove-ExpiredRules/run.ps1:96` -> `Expire` `:138`, `RemoveFailed` `:109`). The timer's
outer-catch `RemoveFailed` (`:162`) writes no Details — the handler threw, so no result exists.

This is the compensating control for App Service's slot fan-out: a revoke whose slot
enumeration failed lands as `Status='Removed'` with
`{"slotEnumerationFailed":true,"slotEnumerationError":"..."}` in `Details`, so the incomplete
coverage is auditable instead of living only in a `Write-Warning` in the function logs.

### stdout audit — `Write-JITAuditEvent` (`JITHelpers.psm1:514-552`)
Separate from the table. Emits compact JSON to stdout (Log stream / Kudu). `EventType`
`ValidateSet`: `JITGranted`, `JITDenied`, `JITExpired`, `JITRemoveFailed`, `JITRevoked`
(`:523`). All grant/deny/expiry decisions flow through here.

---

## 9. Justification model

**Required by default.** Server-authoritative opt-out via an AzureTray app-reg tag.

Server (`Test-JustificationRequired` `JITHelpers.psm1:603-621`): reads the app-reg tags via
`Get-AzureTrayAppRegTags` (`:558-601`, Graph `GET /v1.0/applications/<objId>?$select=id,tags`
using the MI Graph token, 5-min cache `AppRegTagsCacheTtl` `:40`). Returns `$false` (not
required) **only** if a tag equals `justificationrequired:false` (case-insensitive, trimmed;
`:616`). Tag literal to write: `JustificationRequired:false`. Fail-safe: unknown/unreadable
tags (`$null`, e.g. object id unset or any Graph error) -> **required** (`:613`, `:596-600`
does not cache the failure).

Enforced in Request (`Request-JITAccess/run.ps1:191-198`): if required and trimmed
justification empty -> 400 `{ "error":"Justification is required for JIT access requests." }`
+ `JITDenied`/`JustificationRequired`. Also ≤ 500 chars (`run.ps1:200-203`).

Plugin UX (`JitAzAccessPlugin.cs:1122-1140`): prompts for justification unless
`state.Urls.JustificationOptional` is true, but a target's `RequiresJustification` still
forces the prompt. `JustificationOptional` comes from `JitUrlDiscovery` detecting the same
`JustificationRequired:false` tag (`JitUrlDiscovery.cs:33`, `:150-153`). Target-level
`RequiresJustification` is set from resource tags `environment=prod|production` or
`jit-requires-justification=true` (`ResourceDiscovery.cs:254-264`). The server is
authoritative; the plugin flag only relaxes the client prompt.

---

## 10. Configuration & zero-config

The app deploys with the App Settings the ARM template sets (`azuredeploy.json:163-178`);
everything else is derived at runtime. **Env var wins whenever set.**

| Env var | Default / derivation | Read at |
|---|---|---|
| `AZURE_TENANT_ID` | else MI ARM-token `tid` claim; else IMDS `tenantId` | `Get-JitTenantId` `JITHelpers.psm1:475-508` |
| `JIT_SUBSCRIPTION_ID` | else `WEBSITE_OWNER_NAME` split `+`[0] (GUID-validated); else IMDS `subscriptionId` | `Get-JitSubscriptionId` `JITHelpers.psm1:410-435` |
| `JIT_RESOURCE_GROUP` | else `WEBSITE_RESOURCE_GROUP` | `Get-JitResourceGroup` `:437-445` |
| `JIT_SITE_NAME` | else `WEBSITE_SITE_NAME` | `Get-JitSiteName` `:447-455` |
| `JIT_SITE_RESOURCE_ID` | else built `/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<site>` | `Get-JitSiteResourceId` `:457-473` |
| `EXPECTED_AUDIENCES` | else the 4 ARM audience defaults | `Invoke-JwtValidation` `:139-146` |
| `ALLOWED_DURATIONS_HOURS` | `'1,4,8'` (template default; run.ps1 fallback same) | `Request-JITAccess/run.ps1:37` |
| `JIT_TABLE_NAME` | `JITRules` (set by template) | Request `:40`, Get `:19`, Revoke `:20`, timer `:13` |
| `JIT_AUDIT_TABLE_NAME` | `JITRulesAudit` | `Get-JITAuditTableName` `:883` |
| `JIT_NSG_PRIORITY_MIN` | `1000` | Request `:41` |
| `JIT_NSG_PRIORITY_MAX` | `3900` | Request `:42` |
| `JIT_MAX_RULES_PER_CALLER` | `5` | Request `:43` |
| `JIT_MAX_RULES_PER_RESOURCE` | `20` | Request `:44` |
| `AZURETRAY_APP_REGISTRATION_OBJECT_ID` | (set by Deploy.ps1 Step 0) — object id of the AzureTray app reg | profile `:20-22`, `Get-AzureTrayAppRegTags` `:575` |
| `AZURETRAY_APP_REGISTRATION_NAME` | informational, template `:176` | (scripts only) |
| `AzureWebJobsStorage` | connection string (template `:165-166`) | `Get-StorageParts` `HttpHelpers.psm1:220-238` |
| `IDENTITY_ENDPOINT` / `IDENTITY_HEADER` | platform-injected (MI) | `Get-ManagedIdentityToken` `HttpHelpers.psm1:45-53` |
| `WEBSITE_HOSTNAME` / `WEBSITE_OWNER_NAME` / `WEBSITE_RESOURCE_GROUP` / `WEBSITE_SITE_NAME` | platform-injected | profile / derivation helpers |

Note: `Test-JITAccess.ps1` Check 6 also probes for `JIT_REQUESTER_ROLE_NAME`
(`Test-JITAccess.ps1:343`), but the function-app code does **not** read that env var (role
name is hardcoded `JITHelpers.psm1:21`) — that check is stale relative to the current code.

IMDS: `Get-JitInstanceMetadata` GETs `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
with `Metadata: true`, 5 s timeout, best-effort (`JITHelpers.psm1:391-408`).

Fixed constants (not env-configurable): `Invoke-ArmRest` default api-version `2022-04-01`
(`HttpHelpers.psm1:89`); Blob `x-ms-version 2021-12-02` (`:416`); Table `x-ms-version 2019-02-02`
(`:569`); JWKS cache 1 h; role-check cache 60 s; app-reg-tags cache 5 min; blob-lock container
`jit-locks` (`JITHelpers.psm1:672`).

---

## 11. URL discovery & the manifest tag

Tag format (exact): `jit-baseurl:<subscriptionId>=<https-url>` written to the AzureTray
app-reg `tags` array. One tag per deployment/subscription. The `notes` field is deliberately
left untouched for humans.

Example: `jit-baseurl:11111111-1111-1111-1111-111111111111=https://func-pgjitazaccess.azurewebsites.net`

**Server self-registration** (`profile.ps1`): on cold start, if `WEBSITE_HOSTNAME` +
`AZURETRAY_APP_REGISTRATION_OBJECT_ID` + derived subId all present, gets a Graph MI token,
reads existing tags, drops any prior `jit-baseurl:<thisSub>=*`, adds the current one, and
PATCHes `applications/<objId>` (`profile.ps1:20-69`). Forces a `List<string>` so a
single-element tags array doesn't get unwrapped by `ConvertTo-Json` (`:54-55`). Requires the
MI to hold Graph `Application.ReadWrite.OwnedBy` + be an owner of that app reg (granted by
`Deploy.ps1` Step 3b). Deploy.ps1 Step 3c also writes the tag immediately with the operator's
creds so it's present before the first cold start (`Deploy.ps1:322-378`).

**Plugin self-discovery** (`JitUrlDiscovery.cs:47-128`): pages `GET /v1.0/applications?
$select=id,appId,displayName,tags&$top=100` (max 20 pages `:37`) for the tenant, scans every
readable app reg's `tags` for `jit-baseurl:` (`TagPrefix` `:28`) and the
`JustificationRequired:false` opt-out (`:33`), building a `subId -> url` map. First URL per
sub wins (`:167-173`). No app-registration name is assumed. Returns `JitUrlDiscoveryResult`
(`:192`) with `PerSubscription`, `JustificationOptional`, `UrlForSubscription()`, `AllUrls`.

---

## 12. Plugin internals

**Contracts** (from the host repo `AzureTray.Plugin.Contracts`, `PluginApiVersion.Current`
reported via `ApiVersion` `JitAzAccessPlugin.cs:46`): `JitAzAccessPlugin` implements
`ITrayPlugin, IMenuChangeNotifier, IBadgeProvider, IPluginTestProvider, IPluginConfigurable,
IDisposable` (`JitAzAccessPlugin.cs:33`). Host renders only **Boolean / Text / Number**
option kinds — no Select/ComboBox/WPF (`BuildSettingsView()` returns null `:270`; comment
`:130-132`). Required permissions: ARM `user_impersonation` (JitClient + verify) and Graph
`Application.Read.All` (URL discovery) (`:71-85`).

**AssetTypeCatalog** (`AssetTypeCatalog.cs`) is the single source of truth: `record
AssetType(Token, ArmType, ArgType, DisplayLabel)`. Drives the KQL `type in~` list, the
ARM->token map (`TokenForArgType`), the `include.<token>` config checkboxes, and menu labels
(`LabelForToken`). Add a type by adding one record (§6).

**Config selector** (`JitAzAccessPlugin.cs:125-268`): `defaultDurationHours` (Number, default
4), `allowedDurations` (Text, default `"1,2,4,8"`), `include.all` master Boolean, plus one
`include.<token>` Boolean per catalog type (all default true). `include.all` toggles all
children; unchecking any child clears the master; re-checking the last one restores it
(`SetValue` `:203-234`). `SelectedAssetTypes` (`:243-259`) returns the full catalog when
`include.all` is on, when no keys are set, or when every child is cleared (preserves
"discover everything"); otherwise the checked subset. This set gates `ResourceDiscovery`
(`:647`) and hence the KQL query (`ResourceDiscovery.BuildKql` `:41-64`).

**Polling** (`JitAzAccessPlugin.cs:462-727`): one 90 s timer fans out over all tenants
(`PollAllAsync`). Per tenant: targets refreshed every `TargetsTtl=5 min` (`:429`), rules every
`RulesTtl=90 s` (`:430`). CAS guard `state.Polling` prevents overlapping runs (`:629`).
401/403 -> `NotifyAuthBlocked` one-shot toast (`:747-795`); `ArgumentException`("not enabled
for plugin") -> `SuspendForTenantMismatch` (`:732-740`).

**ArmVerifier** (`ArmVerifier.cs:47-109`): after a grant, a read-only ARM GET confirms the
rule landed. 8 s timeout (`:50`). Child/child-firewall types (nsg, sqlServer, postgres, mysql,
redis, synapse) do a **child GET** — 200 => `Confirmed`, else `NotFound`. storage/keyVault do
a parent GET + `ipRules` scan. **All array-on-resource types (cosmosDb, containerRegistry,
aiSearch, cognitiveServices, kusto, iotHub, signalR, eventHub, serviceBus, appService, aks)
hit the `_` arm and return `Skipped`** (`:88`) — no single-rule child to confirm. Verifier
api-version constants are a **separate copy** (`ArmVerifier.cs:22-29`) from the function-app
handlers; they currently match (nsg 2024-03-01, sql 2021-11-01, storage 2023-01-01, keyVault
2023-07-01, postgres 2024-08-01, mysql 2023-12-30, redis 2024-11-01, synapse 2021-06-01) but
must be kept in sync manually.

**Single post-grant notification** (`VerifyAndNotifyAsync` `JitAzAccessPlugin.cs:1347-1437`):
the **sole owner** of post-grant feedback — exactly one toast per grant. Green (`Success`)
**only** on `VerificationResult.Confirmed` (`:1373-1384`). `NotFound` -> Warning; `Timeout`/
`Skipped`/`Error`/default and the null-verifier fallback -> neutral Info. No success toast
fires in `GrantFromTargetAsync` (`:1216-1219`). A 400 from the server is surfaced as a Warning
with the server message (`:1221-1239`).

`JitClient` (`JitClient.cs`) posts camelCase JSON (`:26-30`), throws `JitHttpException`
(status/operation/serverError) on non-2xx, and reads `X-JIT-Caller-IP` off Get-JITRules
(`:116-118`). Local state: `ActiveRulesStore` (countdowns across restarts) and
`FavoritesStore` in `context.DataDir`.

---

## 13. Deployment & admin scripts

All in `src/scripts/`. `Deploy.ps1`, `Grant-JITPermissions.ps1`, `Remove-JITDeployment.ps1`,
`Test-JITAccess.ps1` drive **Azure CLI (`az`)**; `Set-JITPim.ps1` uses **Az PowerShell**
(Az.Accounts, Az.Resources) because PIM-for-Azure-resources has no clean `az` surface.

**`Deploy.ps1`** (params: `-SubscriptionId` (req), `-Location`, `-AppName` `pgjitazaccess`,
`-ResourceGroupName` `rg-jit-azaccess`, `-AzureTrayAppRegistrationName` `AzureTray`,
`-ParametersFile`, `-TargetSubscriptionIds`, `-SkipGraphPermission`). Order: Step 0 resolve
AzureTray app-reg object id via Graph -> Step 1 `az deployment sub create` (azuredeploy.json)
-> Step 2 zip-deploy code (`Compress-Archive` + `az functionapp deployment source config-zip`)
-> Step 3a `Grant-JITPermissions.ps1` -> Step 3b Graph `Application.ReadWrite.OwnedBy` + app-reg
ownership for the MI -> Step 3c write the `jit-baseurl` tag now -> Step 4 restart + warmup probe.

**`Grant-JITPermissions.ps1`** (params: `-TargetSubscriptionIds` (req),
`-FunctionAppPrincipalId` or the trio `-FunctionAppName/-ResourceGroupName/-FunctionAppSubscriptionId`).
Creates/updates the `JIT-AzAccess Manager` role (Actions `:54-132`) **merging** assignable
scopes across re-runs (`:186-192`), assigns it to the MI per target sub, and
creates/updates the `JIT-Requester` role **definition only** (empty Actions — a pure access
marker; assigning users to it is an operator action) with merged scopes (`:276-362`).
**Re-run this whenever a new asset type adds RBAC actions** — it refreshes the Manager role's
Actions.

**`Set-JITPim.ps1`** (params: `-Subscriptions` (req), `-ActiveAssignment` (req),
`-EligibleAssignment` (req), `-RoleName` `JIT-Requester`, `-TenantId`; supports `-WhatIf`).
Per sub: resolve role def (skip if absent), relax the PIM policy expiration rules
(`Expiration_Admin_Eligibility`, `Expiration_Admin_Assignment`) to allow permanent
assignments, then create permanent (NoExpiration) **eligible** and **active** assignments to
the two named Entra groups. Idempotent. Requires Entra ID P2 and Owner/UAA on each sub.

**`Remove-JITDeployment.ps1`** (params incl. `-SubscriptionId` (req), `-KeepFunctionApp` soft
mode, `-RemoveLegacyAppRegistration`, `-Force`, `-WhatIf`). Idempotent teardown: drop
`jit-baseurl` tag, remove MI from app-reg owners, revoke Graph app role, remove all
`JIT-Requester` + `JIT-AzAccess Manager` assignments, delete both role definitions (only if
unassigned), delete the RG, optionally delete the legacy `JIT-AzAccess` app reg. `-KeepFunctionApp`
keeps RG/app/MI/ownership/consent but still resets roles+assignments.

**`Test-JITAccess.ps1`** — 8 health checks (JIT-Requester def exists; caller holds it;
Manager role has every required Action `:193-250`; MI holds Manager per target sub; app
reachable/enforcing auth; required env vars present; MI Graph perm + app-reg ownership;
`jit-baseurl` tag present/matching). Read-only.

**ARM template** (`azuredeploy.json`): subscription-scoped; creates RG + nested deployment of
Storage (Standard_LRS, TLS1_2, no public blob), Consumption plan (Y1 Dynamic), and the
function app (SystemAssigned MI, `powerShellVersion 7.2`, `FUNCTIONS_WORKER_RUNTIME powershell`,
`FUNCTIONS_EXTENSION_VERSION ~4`, httpsOnly, ftps disabled). Outputs `functionAppPrincipalId`,
`functionAppName`, `functionAppHostname`, `resourceGroupName`.

---

## 14. Testing

Runner `test.ps1` (repo root). Modes: default **simple** (quiet, prints total/passed/failed/
skipped + failed names); `-Detailed` (full output — use only after simple flags a problem);
`-Target <name>` (one file by BaseName, else a Describe/It `*<name>*` name filter). Uses
**Pester 3.4.0** on PowerShell 7 (`test.ps1:41`). Two kinds of files under
`src/functionapp/tests/`: Pester `Describe` files run via `Invoke-Pester`, and standalone
assertion scripts (currently `HttpHelpers.Tests.ps1`) run in a child `pwsh` and judged by exit
code (`test.ps1:102-119`).

Test files: `HttpHelpers.Tests.ps1` (standalone), `JITHelpers.Tests.ps1`,
`JITHelpers.Audit.Tests.ps1`, `JITHelpers.Derivation.Tests.ps1`, `JITTargetsDetection.Tests.ps1`,
`JITArmReadModifyWrite.Tests.ps1`, `Request-JITAccess.Tests.ps1`, `Remove-ExpiredRules.Tests.ps1`.

**KNOWN pre-existing failures:** ~21 tests fail (running count ~155 total / ~134 passed / ~21
failed). They are **stale mocks** in older Pester files (notably `Remove-ExpiredRules.Tests.ps1`,
which mocks now-removed cmdlets — `Get-JITCloudTable`, `Az.Table`, and `Az` NSG cmdlets like
`Get-AzNetworkSecurityGroup`) that no longer exist since the app dropped all `Az.*` modules in
favor of REST helpers. These failures are pre-existing and not caused by current work; verify
your change does not *increase* the failure count rather than expecting a clean run.

---

## 15. Known limitations / gotchas

- **Array-type positive verification is `Skipped` in the plugin** — cosmosDb, containerRegistry,
  aiSearch, cognitiveServices, kusto, iotHub, signalR, eventHub, serviceBus, appService, aks
  return `VerificationResult.Skipped` from `ArmVerifier` (no addressable child), so their grant
  toast is neutral Info, never green (`ArmVerifier.cs:79-88`).
- **NSG dup-detection is exact single-IP only** — matches only `sourceAddressPrefix == ip` or
  `ip/32`; does NOT evaluate CIDR ranges, `sourceAddressPrefixes` arrays, service tags, or
  per-port scope, so a caller IP covered by a broader rule is treated as not-present (a new JIT
  rule is created) (`Nsg.ps1:29-39`). The NSG rule opens ANY source/dest port + all protocols;
  the requested port is audit-only (`Nsg.ps1:47-62`).
- **App Service only whitelists an ALREADY-restricted site** — a site whose ip restriction
  list is empty (implicit Allow-all) is left untouched (`SkippedOpen`); JIT only adds when a
  concrete rule exists or DefaultAction==Deny, per list (`AppService.ps1:41-53`, `:119-145`).
- **AKS never empties `authorizedIPRanges`** — ADD skips an open (empty) cluster; REMOVE
  refuses to remove the last range (`Refused`, row retained) (`Aks.ps1:79`, `:126-130`).
- **Private targets rejected** — Postgres private/VNet server and AKS private cluster throw
  the `PRIVATE_SERVER_REJECTED:` sentinel -> 409 (`PostgresqlFlexibleServer.ps1:53-55`,
  `Aks.ps1:70-72`, `Request-JITAccess/run.ps1:378-386`).
- **Tier/config caveats** (JIT never *creates* restriction): Redis/EventHub/ServiceBus/SignalR
  need Standard+ tier; ACR needs Premium + defaultAction=Deny; Cognitive/ACR/Cosmos need
  publicNetworkAccess enabled + defaultAction=Deny. EventHub/ServiceBus Basic-tier 404 on the
  `networkRuleSets/default` GET surfaces as a modification failure (500) (`EventHub.ps1:14-17`).
- **The two role-definition JSONs are UNREFERENCED exports with hardcoded subscription GUIDs** —
  `src/JIT-AzAccess-Manager.json` and `src/JIT-AzAccess.json` are point-in-time `az role
  definition` exports with fixed `AssignableScopes` (e.g. `9b9784dc-...`). No script reads them;
  the roles are created programmatically by `Grant-JITPermissions.ps1`. Do not treat them as the
  source of truth — `Grant-JITPermissions.ps1:54-132` is.
- **Azure table names cannot contain hyphens** — hence `JITRules` / `JITRulesAudit` (not
  `JIT-Rules`). Keep any new table name hyphen-free.
- **RuleIdentifier fallbacks exist for legacy rows** — Remove handlers tolerate a null
  `RuleIdentifier` by falling back to `RowKey` (child) or `CallerIp` (array) (`Nsg.ps1:76-82`).
- **`JIT_REQUESTER_ROLE_NAME` is checked by Test-JITAccess.ps1 but not read by the app** — the
  role name is hardcoded; that health check is stale.
- **ArmVerifier api-versions are a second copy** — kept in sync manually with the handlers.
```
