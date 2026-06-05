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

Authorization is gated entirely on Azure RBAC: the caller must hold the custom
**"JIT Requester"** role on the function app site resource (or a parent scope).
Deploy.ps1 creates this role at subscription scope; admins assign it to end users.

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
3. Grant the function app's MI:
   - `JIT-AzAccess Manager` custom RBAC role on the target subscriptions (so it can write firewall rules)
   - Microsoft Graph `Application.ReadWrite.OwnedBy` + ownership of the AzureTray app reg (so it can self-register its URL on cold start)
4. Register this deployment's URL as a `jit-baseurl:<sub>=<url>` tag on the AzureTray app reg
5. Create the `JIT Requester` custom RBAC role at subscription scope
6. Restart the function app so `profile.ps1` self-registers its URL tag

### 2. Assign the JIT Requester role to your users

The function app rejects callers who don't hold the `JIT Requester` role on its site resource.
Assign it via the portal, az CLI, or PIM:

```powershell
az role assignment create `
    --assignee-object-id <user-or-group-objectId> `
    --assignee-principal-type User `
    --role "JIT Requester" `
    --scope "/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Web/sites/func-jitazaccess"
```

You can scope the assignment higher (RG or subscription) — ARM inheritance applies.

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
| `jitRequesterRoleName` | `JIT Requester` | Name of the custom RBAC role that gates access |
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
- be issued by the function app's tenant (`tid` claim matches `AZURE_TENANT_ID`)
- carry an ARM audience (`https://management.azure.com/`)

**Authorization check:** the caller's AAD object ID (`oid` claim) must hold the
`JIT Requester` RBAC role at, above, or below the function app site resource.

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

Supported `targetType` values: `nsg`, `sqlServer`, `storageAccount`, `keyVault`.
`port` is NSG-only (omit for any-port; supports ranges like `8080-8090`).

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
- RBAC role assignments are looked up against ARM on every request; results are cached per-caller-per-site for 5 minutes.
- NSG priority assignment is protected by a distributed blob lease to prevent concurrent requests from colliding.
- Audit events (`JITGranted`, `JITDenied`, `JITExpired`, `JITRemoveFailed`, `JITRevoked`) are emitted as structured JSON to stdout and surfaced in the function app's standard logs (Log stream, Kudu, `az functionapp log tail`).
- The function app runs with a system-assigned managed identity; no credentials are stored.
- TLS 1.2 minimum, FTPS disabled, HTTPS-only enforced.
