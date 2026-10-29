# AzureTray JIT Azure Access plugin

A plugin for [AzureTray](https://github.com/Proxylayer/AzureTray) that grants
**temporary (just-in-time) IP-based access** to Azure resources from the system
tray. It calls a [JIT-AzAccess](https://github.com/Proxylayer/JIT-AzAccess)
function app backend, which adds — and auto-expires — a firewall rule for the
caller's current public IP.

You pick a resource and a duration. Your IP is allowlisted. It disappears on
its own.

## Supported resource types

19 types, all driven from one catalog in the plugin:

| | | |
|---|---|---|
| NSG | Azure SQL | Storage |
| Key Vault | PostgreSQL flexible | MySQL flexible |
| Redis | Synapse | Cosmos DB |
| Container Registry | AI Search | Cognitive Services / OpenAI |
| Data Explorer (Kusto) | IoT Hub | SignalR |
| Event Hubs | Service Bus | App Service (incl. slots) |
| AKS | | |

## Features

- **Browse your own resources** — discovered client-side through ARM Resource
  Graph with your token, so the list only ever shows what you can already see.
- **Request access** — one click, pick a duration, done. The grant is confirmed
  independently via ARM rather than trusted from the response.
- **Active rules** — your live grants with countdown timers and one-click
  revoke, read from the server so they follow you across machines.
- **Favorites and search** — pin the resources you reach for; filter by name or
  environment.
- **Production confirmation** — a resource tagged `environment=prod` asks twice
  and always requires a justification.
- **Zero configuration to get started** — the backend URL is self-discovered
  from app-registration tags; no URL or tenant list to type in.

## How it works

1. Sign in to your tenant in AzureTray.
2. The plugin reads the app registrations you can see via Microsoft Graph and
   collects the backend URL from a `jit-baseurl:<subscriptionId>=<url>` tag.
3. Your request goes to that backend with an ARM-audience bearer token.
   The server authorises it on the custom **JIT-Requester** Azure RBAC role,
   evaluated **in the subscription the target resource lives in**.
4. The backend's managed identity writes the rule, records it, and a timer
   revokes it at expiry.

## Security notes

Worth knowing, because they shape what the plugin will and won't do:

- **The backend URL is validated before your token is sent to it.** That URL
  comes off an app-registration tag, and Entra lets ordinary users register
  applications — so an unvalidated value would be a route for exfiltrating your
  ARM token. The plugin requires absolute HTTPS, a host on an allowlist
  (`.azurewebsites.net` by default), no embedded credentials, the default port,
  and no query or fragment. Anything else is refused and logged, naming the app
  registration that advertised it.
- **The justification opt-out is only honoured from a real deployment.** An app
  registration can relax the justification prompt only if it also advertises a
  valid backend, so a drive-by registration cannot switch it off for everyone.
- **A verification that cannot complete says so.** A 403, 429 or 5xx while
  checking a rule reports "could not verify", not "rule missing".
- **Only your own grants are listed**, filtered server-side.

## Configuration

All optional — the defaults work.

| Option | Default | What it does |
|---|---|---|
| Default access duration (hours) | `4` | Pre-selected in the grant prompt |
| Offered durations (hours) | `1,2,4,8` | The choices in the prompt |
| Allowed JIT backend hosts | `.azurewebsites.net` | Hosts the plugin may send your token to. Only change this for a sovereign cloud or a custom domain |
| All asset types | on | Turn off to pick individual types below it |
| Include *(per type)* | on | One toggle per supported resource type |

## Requirements

- The AzureTray host.
- A deployed JIT-AzAccess function app in your tenant.
- The **JIT-Requester** RBAC role on your account, in each subscription you want
  to request access in.

## License

MIT — see [LICENSE](https://github.com/Proxylayer/JIT-AzAccess/blob/main/LICENSE).
