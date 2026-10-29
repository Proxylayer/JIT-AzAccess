# JIT-AzAccess

Just-in-time, IP-scoped access to Azure resources.

A caller asks for access to a resource they are allowed to reach. The service
adds a firewall rule for **their current public IP**, records it, and removes it
again when it expires. Nothing stays open because somebody forgot to close it.

Two pieces ship from this repository:

| | |
|---|---|
| **Function app** (`src/functionapp`) | The backend. PowerShell 7.4 on Azure Functions v4. Authorises the request, writes the rule, expires it on a timer. |
| **AzureTray plugin** (`src/plugin`) | The client. A tray-menu front end published to NuGet as [`AzureTray.Plugin.JITAzAccess`](https://www.nuget.org/packages/AzureTray.Plugin.JITAzAccess). |

The backend is usable on its own over plain HTTP; the plugin is a convenience,
not a requirement.

## Supported resource types

19 types, each with its own rule shape:

| | | |
|---|---|---|
| NSG | Azure SQL | Storage |
| Key Vault | PostgreSQL flexible | MySQL flexible |
| Redis | Synapse | Cosmos DB |
| Container Registry | AI Search | Cognitive Services / OpenAI |
| Data Explorer (Kusto) | IoT Hub | SignalR |
| Event Hubs | Service Bus | App Service (incl. slots) |
| AKS | | |

## How a grant works

1. The caller sends an ARM-audience bearer token (`https://management.azure.com/`)
   to `POST /api/Request-JITAccess`. There is no dedicated app registration and
   no custom OAuth scope.
2. The app validates the token against its own tenant, then checks Azure RBAC:
   the caller must hold the custom **JIT-Requester** role **in the subscription
   the target resource lives in**.
3. The caller's IP is taken from the platform-written entry of `X-Forwarded-For`,
   never from a client-supplied header.
4. A blob lease serialises the request against the caller's other in-flight
   requests, abuse limits are evaluated, and a reservation row is written before
   anything in Azure changes.
5. The app's managed identity writes the rule through the ARM REST API,
   following long-running operations to completion.
6. `Remove-ExpiredRules` runs every 5 minutes and removes whatever has expired.

Revocation (`POST /api/Revoke-JITAccess`) re-checks RBAC in the rule's own
subscription. `GET /api/Get-JITRules` needs only authentication — it returns the
caller's own rules and nobody else's.

## Design constraints

These are deliberate and load-bearing. Changing one is a design decision, not a
cleanup.

- **No Az PowerShell modules.** Every Azure call is `Invoke-RestMethod` against
  ARM, Graph or the Storage REST API. Module load time dominates cold start on
  the Consumption plan, and the modules bring a dependency surface this app
  does not need.
- **No shared-key storage access.** The storage account is deployed with
  `allowSharedKeyAccess: false`; the managed identity authenticates to Table
  Storage with Entra tokens.
- **Zero operational configuration.** Subscription id, resource group, site
  name and tenant id are derived at runtime from platform-injected environment
  variables and the managed identity token, with IMDS as a fallback. Each can
  still be overridden by an App Setting when a deployment needs it.
- **Fail closed.** A check that cannot complete is not a check that passed. A
  403, 429 or 5xx while verifying a rule reports "could not verify", never
  "rule absent".

## Repository layout

```
src/functionapp/      PowerShell function app
  Request-JITAccess/    grant
  Revoke-JITAccess/     revoke
  Get-JITRules/         list the caller's own rules
  Remove-ExpiredRules/  timer-triggered expiry sweep
  Modules/              JITHelpers, JITTargets (the 19 handlers), HttpHelpers
  tests/                Pester 5 suite
src/plugin/           AzureTray plugin (C#, net8.0) + xUnit tests
src/scripts/          Deploy.ps1, Grant-JITPermissions.ps1, Test-JITAccess.ps1
src/azuredeploy.json  ARM template
docs/                 technical reference and host-contract notes
```

## Getting started

Deployment, RBAC setup and the operational detail live in
[src/README.md](src/README.md). The short version:

```powershell
./src/scripts/Deploy.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -Location <region>
```

You need Owner or User Access Administrator in the target subscription (the
template creates a custom RBAC role), and Application Administrator in the
tenant (the managed identity is granted Graph app roles).

## Build and test

```powershell
./build.ps1     # C# projects, plus a parse + PSScriptAnalyzer pass over the function app
./test.ps1      # Pester suite and the xUnit project
```

`./test.ps1 -Target <name>` runs one file or one test name; add `-Detailed`
only when a plain run has already flagged something. CI runs the same two
scripts plus an ARM template validation pass.

## Further reading

- [docs/TECHNICAL-REFERENCE.md](docs/TECHNICAL-REFERENCE.md) — API surface,
  storage schema, the trust boundaries and why each one is where it is.
- [docs/AZURETRAY-HOST-CHANGES.md](docs/AZURETRAY-HOST-CHANGES.md) — what the
  plugin needs from the AzureTray host.
- [docs/CONTRACTS-PROPOSALS.md](docs/CONTRACTS-PROPOSALS.md) — proposed
  additions to the plugin contracts.

## License

MIT — see [LICENSE](LICENSE).
