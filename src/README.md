# JIT-AzAccess — Azure Function App

Grants callers temporary (JIT) IP-based access to Azure resources by dynamically adding and auto-expiring firewall/network rules. Supports:

- **NSG** inbound security rules
- **Azure SQL Server** firewall rules
- **Storage Account** network ACLs
- **Key Vault** network ACLs

Rules are automatically removed by a timer trigger when they expire (every 5 minutes).

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Azure CLI (`az`) | `az login` before deploying |
| Azure subscription | You need **Owner** or **User Access Administrator** to deploy the ARM template and create custom RBAC roles |
| AAD app registration | Create one for the JIT service itself (see below) |

---

## Quick Start

### 1. Create the AAD app registration

```powershell
# Create the app registration for the JIT service
$app = az ad app create --display-name "JIT-AzAccess" --output json | ConvertFrom-Json
$appObjectId = $app.id
$appClientId = $app.appId

# Set a scoped audience URI (optional but recommended)
az ad app update --id $appClientId --identifier-uris "api://jit-azaccess"
```

### 2. Deploy the infrastructure

```powershell
./scripts/Deploy.ps1 `
    -SubscriptionId          "<your-subscription-id>" `
    -Location                "eastus" `
    -AppRegistrationObjectId $appObjectId `
    -ApprovedClientIds       "<client-ids-of-callers>" `
    -JwtAudience             "api://jit-azaccess"
```

`Deploy.ps1` will:
1. Run the ARM template (creates resource group + all resources)
2. Zip-deploy the function app code
3. Configure the app registration (Graph permission + ownership)
4. Print the `Grant-JITPermissions.ps1` command to run

### 3. Grant the function app access to target subscriptions

```powershell
./scripts/Grant-JITPermissions.ps1 `
    -TargetSubscriptionIds  @("<sub-id-1>", "<sub-id-2>") `
    -FunctionAppPrincipalId "<principalId from Deploy output>"
```

This creates a minimal custom RBAC role ("JIT-AzAccess Manager") and assigns it to the function app's managed identity. The role grants **only** the control-plane actions needed to manage firewall/network rules — no data-plane access.

---

## Folder Structure

```
jit-azaccess/
  azuredeploy.json                    # Subscription-scoped ARM template
  azuredeploy.parameters.example.json # Parameter file template
  functionapp/                        # PowerShell Azure Functions code
    host.json
    requirements.psd1
    profile.ps1
    Request-jitazaccess/
      function.json                   # HTTP POST trigger
      run.ps1
    Remove-ExpiredRules/
      function.json                   # Timer trigger (every 5 min)
      run.ps1
    Modules/
      JITHelpers/JITHelpers.psm1      # JWT validation, audit logging, distributed lock
      JITTargets/JITTargets.psm1      # Per-resource-type Add/Remove handlers
  scripts/
    Deploy.ps1                        # End-to-end deployment orchestration
    Grant-JITPermissions.ps1          # Create RBAC role + assign to managed identity
    Set-JITAppRegistration.ps1        # Graph permission + app reg ownership
```

---

## ARM Template Parameters

| Parameter | Default | Description |
|---|---|---|
| `location` | _(required)_ | Azure region for all resources |
| `appName` | `jitazaccess` | Short lowercase alphanumeric name (3-15 chars) used to derive resource names |
| `resourceGroupName` | `rg-jit-azaccess` | Resource group to create |
| `approvedClientIds` | _(required)_ | Comma-separated AAD client IDs allowed to call the API |
| `jwtAudience` | _(required)_ | Expected `aud` claim (the app registration's Application ID URI) |
| `jitAppRegistrationObjectId` | _(empty)_ | App registration Object ID for self-registration of the endpoint URL |
| `allowedDurationsHours` | `1,4,8` | Comma-separated list of valid JIT durations in hours |
| `nsgPriorityMin` | `1000` | Lowest NSG rule priority the JIT app may assign |
| `nsgPriorityMax` | `3900` | Highest NSG rule priority the JIT app may assign |
| `maxRulesPerCaller` | `5` | Max simultaneously active rules per caller identity |
| `maxRulesPerResource` | `20` | Max simultaneously active rules per target resource |
| `logRetentionDays` | `90` | Log Analytics workspace retention in days |

Resource names are derived from `appName`:

| Resource | Name |
|---|---|
| Storage account | `st{appName}` |
| Consumption plan | `asp-{appName}` |
| Function app | `func-{appName}` |
| Key Vault | `key-{appName}` |
| Log Analytics | `log-{appName}` |
| Application Insights | `appin-{appName}` |

---

## API Usage

**Endpoint:** `POST https://func-{appName}.azurewebsites.net/api/Request-jitazaccess`

**Authorization:** `Bearer <AAD token>` — token must be issued by the correct tenant, with the configured audience and an approved client ID.

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

- All secrets (`approvedClientIds`, `jwtAudience`) are stored in Key Vault; the function app accesses them via Key Vault references (no secrets in app settings).
- JWT validation performs full RS256 signature verification against Azure AD's JWKS with a 1-hour in-process cache and automatic key rotation handling.
- NSG priority assignment is protected by a distributed blob lease to prevent concurrent requests from colliding.
- Audit events (`JITGranted`, `JITDenied`, `JITExpired`, `JITRemoveFailed`) are emitted as structured JSON and automatically ingested by Application Insights.
- The function app runs with a system-assigned managed identity; no credentials are stored.
- TLS 1.2 minimum, FTPS disabled, HTTPS-only enforced.
