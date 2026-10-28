# AzureTray Host — Changes Requested by the JIT-AzAccess Plugin

## What this document is

A record of host-side bugs and gaps found while building the JIT-AzAccess plugin, and
what became of each. It used to be an implementation spec addressed to an engineer
working inside the AzureTray repo (`c:\Users\jbland\source\repos\AzureTray`).

**Every item in it has since shipped.** It is kept as history — so the next reader does
not re-plan solved work, and so the plugin-side adoption of each fix has something to
point at.

Verified against AzureTray at `25ea5e9` and `AzureTray.Plugin.Contracts` 1.5.0 on
2026-10-28. Quoted code is the host's *current* source; match on the quoted text rather
than the line number if it has drifted again.

### Status

| # | Change | Was | Status | Verified in |
|---|--------|-----|--------|-------------|
| 1 | Dedupe loaded plugins by `Plugin.Id`, not assembly path | **REQUIRED** | **Shipped** | `Plugins/PluginLoader.cs:558-575` |
| 2 | Collect after `TrayIcon` releases plugin refs | OPTIONAL | **Shipped** | `TrayIcon.cs` `OnPluginsChanged` |
| 3 | Render `Select` and `Secret` option kinds | OPTIONAL | **Shipped** | `ViewModels/PluginOptionViewModel.cs:37-41`, `PluginConfigWindow.xaml:111` |
| 4 | Plugin-triggerable token refresh for an RBAC 403 | OPTIONAL | **Shipped** | `IPluginContext.RefreshTokenAsync`, contracts 1.3.0+ |

`PluginApiVersion.Current` is **4** (`PluginApiVersion.cs:35`). An earlier revision of
this document said 3; that was stale.

---

## 1. Dedupe loaded plugins by `Plugin.Id` — SHIPPED

**Was:** a version swap could leave two entries sharing one `Plugin.Id`. The tray menu,
built from the loaded-plugin list, showed both; the superseded instance was never shut
down, so its poll timer rooted it and pinned its collectible `AssemblyLoadContext`.

**Now:** `PluginLoader` tears down any existing entry claiming the same Id before
registering the replacement, keyed on the Id rather than the path:

```csharp
// Plugins/PluginLoader.cs:558-575 — comment abridged
// Dedupe by Plugin.Id, not assembly path. A new version can land at a
// different path than the one it replaces ... so a path-keyed check would
// miss it and leave two entries sharing an Id.
superseded = _entries.FirstOrDefault(e =>
    string.Equals(e.Loaded.Plugin.Id, plugin.Id, StringComparison.OrdinalIgnoreCase));
if (superseded is not null) _entries.Remove(superseded);
```

**Plugin side:** nothing to do. `JitAzAccessPlugin.Id` is
`net.proxylayer.AzureTray.Plugin.JITAzAccess` and matches the package id the host
installs under, which `PluginDeclarationTests.Plugin_id_is_the_package_id_the_host_installs_under`
now guards.

Closes **TODO-0012**. The patch drafted for this at
`c:\tmp\azuretray-plugin-id-dedupe.patch` is superseded and can be deleted.

---

## 2. Collect after `TrayIcon` releases plugin refs — SHIPPED

**Was:** `TrayIcon` rooted plugin instances through its menu-change and badge
subscription lists and cleared them on the WPF dispatcher via `BeginInvoke`, which ran
*after* the loader's own unload `GC.Collect()`. The superseded instance therefore
survived that collection. With #1 applied this was promptness, not a leak.

**Now:** `OnPluginsChanged` collects inside the dispatcher callback, after the
unsubscribe, and says why:

```csharp
// TrayIcon.cs — OnPluginsChanged / Apply()
// The unsubscribe/resubscribe above has released this instance's refs
// to any superseded plugin(s). Force a collection now ...
GC.Collect();
GC.WaitForPendingFinalizers();
GC.Collect();
```

**Plugin side:** nothing to do, but the plugin holds up its end — `Dispose` and
`ShutdownAsync` both stop the poll timer and unsubscribe from `IPluginContext` events,
so the host's refs are the only ones left to drop.

---

## 3. Render `Select` and `Secret` option kinds — SHIPPED

**Was:** the generic option grid rendered Boolean, Text and Number only, so a plugin
declaring `Select` got nothing usable. That is why JIT-AzAccess expressed its asset-type
picker as 19 Boolean checkboxes and its duration list as free text.

**Now:** both kinds render — `IsSelect` / `IsSecret` on `PluginOptionViewModel:37-41`,
with the combo box bound to `AllowedValues` at `PluginConfigWindow.xaml:111`.

**Plugin side, adopted:** `allowedDurations` is now
`PluginOptionKind.Select` over a fixed `AllowedValues` preset list. It was free text,
where a typo fell back to `1,2,4,8` silently and the user was offered durations they had
not chosen.

**Plugin side, deliberately NOT adopted:** the asset-type grid stays 19 checkboxes.
`Select` is single-choice and there is no multi-select kind, so a 19-type picker needs 19
controls either way. `GroupWithKey` looks like it would tidy this up and does not — see
proposal **G** in [CONTRACTS-PROPOSALS.md](CONTRACTS-PROPOSALS.md), which documents what
the shipped implementation actually does with multiple followers. No `Secret` option
exists in this plugin: nothing it stores is a credential.

---

## 4. Plugin-triggerable token refresh — SHIPPED

**Was:** a `JIT-Requester` role assignment made moments ago is not in the caller's token,
because group and role claims are baked in at issue time. The plugin saw a 403 it could
do nothing about and could only tell the user to sign out and back in. **TODO-0009**
recorded this as "IMPOSSIBLE via Contracts 1.3.0".

**Now:** `IPluginContext.RefreshTokenAsync(tenantId, ct)` re-acquires the tenant's tokens
bypassing the cache. Per its contract documentation it never triggers interactive
sign-in, is safe to call repeatedly and from multiple threads (the host serialises and
debounces per tenant), throws nothing at the plugin, and returns `false` — rather than
failing — when the host is too old to implement it, the tenant is not enabled, or no
genuinely new token could be obtained.

**Plugin side, adopted:** the 401/403 toast was a passive `InformationRequest` telling
the user to go and sign in again. It is now an `ActionRequest` with a **Refresh sign-in**
button wired to `RefreshTokenAsync`, which on success clears the per-tenant TTLs and
re-polls so the user sees the result of what they clicked. A `false` return is reported
as "nothing to refresh" at Info, not as an error — which is what the contract says to do
with it.

Because `RefreshTokenAsync` self-reports on an old host, the plugin does **not** gate it
on `IPluginContext.HostVersion`. Asking the feature is more reliable than comparing
version strings. `HostVersion` is logged once at initialise instead, so a support report
says which host was running.

Closes **TODO-0009**.

---

## Still open

Nothing in this document. Gaps that remain are in the **contract**, not the host
implementation, and are written up separately as proposals in
[CONTRACTS-PROPOSALS.md](CONTRACTS-PROPOSALS.md).
