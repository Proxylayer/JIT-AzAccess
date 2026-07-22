# AzureTray JIT Azure Access plugin

A plugin for [AzureTray](https://github.com/Proxylayer/AzureTray) that grants
**temporary (just-in-time) IP-based access** to Azure resources from the system
tray. It calls a [JIT-AzAccess](https://github.com/Proxylayer/JIT-AzAccess)
function app backend, which adds — and auto-expires — firewall/network rules for
the caller's current public IP.

Supported targets:

- **NSG** inbound security rules
- **Azure SQL Server** firewall rules
- **Storage Account** network ACLs
- **Key Vault** network ACLs

## Features

- **Browse Resources** — lists the signed-in user's own ARM resources (discovered
  client-side), so the request list reflects what the caller can already see.
- **Request access** — pick a resource and duration; the backend whitelists your
  current public IP and the rule auto-expires.
- **My Active Rules** — server-side list of your live grants with countdown
  timers and one-click Revoke.
- **Post-grant ARM verification** — independently confirms the rule was written
  to the resource via ARM.
- **Zero plugin configuration** — the function-app URL is self-discovered by
  scanning the tags of every app registration you can read via Microsoft Graph;
  no app-registration name or tenant list needs to be entered.

## How it works

1. You sign in to your tenant in AzureTray.
2. The plugin scans the app registrations you can read via Graph and collects the
   JIT function-app URL from whichever one carries the
   `jit-baseurl:<subscriptionId>=<url>` tags (normally the "AzureTray" app
   registration, but the name is not assumed).
3. Requests are sent to the function app with a plain **ARM-audience** bearer
   token (`https://management.azure.com/`). Authorization is gated on the caller
   holding the custom **"JIT-Requester"** Azure RBAC role on the function app
   site resource.
4. The function app's managed identity writes the firewall rule and a timer
   trigger removes it when it expires.

## Requirements

- AzureTray host (the plugin is loaded into the host's collectible
  `AssemblyLoadContext`).
- A deployed JIT-AzAccess function app in your tenant.
- The **JIT-Requester** RBAC role assigned to your account on the function app
  (or a parent scope).

## License

MIT — see [LICENSE](https://github.com/Proxylayer/JIT-AzAccess/blob/main/LICENSE).
