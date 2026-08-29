# AzureTray Host — Changes Required by the JIT-AzAccess Plugin

## What this document is

This is an implementation spec for the **AzureTray host application** (repo:
`c:\Users\jbland\source\repos\AzureTray`). It records host-side bugs and gaps found
while building the JIT-AzAccess plugin (a separate repo). It is written for an
engineering agent working *inside* the AzureTray repo — every file:line pointer below
is into that repo and was verified against the current source.

All quoted code is the **current** AzureTray code (before any change here). Line
numbers are as they stand today; a mechanical patch may shift them, so match on the
quoted text, not the number, if they have drifted.

### Summary

| # | Change | Severity | AzureTray files | Contract / API-version impact |
|---|--------|----------|-----------------|-------------------------------|
| 1 | Dedupe loaded plugins by `Plugin.Id`, not assembly path | **REQUIRED** | `Plugins/PluginLoader.cs` | None (host-only) |
| 2 | Prompter ALC unload after `TrayIcon` releases plugin refs | OPTIONAL | `TrayIcon.cs`, `Plugins/PluginLoader.cs` | None (host-only) |
| 3 | Render `Select` (ComboBox) and `Secret` (PasswordBox) option kinds | OPTIONAL | `ViewModels/PluginOptionViewModel.cs`, `PluginConfigWindow.xaml` | None (contract already defines the kinds) |
| 4 | Plugin-triggerable token invalidation for RBAC group-membership 403 | OPTIONAL | `AzureTray.Plugin.Contracts/*`, `Plugins/PluginContext.cs`, `Plugins/HostPluginHttpClient.cs` | Contracts change + `PluginApiVersion.Current` bump |

**Only #1 is required.** It is a real user-facing bug plus a live-object leak. #2–#4
are enhancements; ship #1 alone first.

A ready-to-apply patch for #1 exists at `c:\tmp\azuretray-plugin-id-dedupe.patch`
(verified with `git apply --check` against the AzureTray repo). See §1.

---

## 1. REQUIRED — Stale/duplicate plugin menu after a version swap

### Symptom / motivation

Uninstall a plugin version and install a different one, and the **old plugin's tray
menu stays present** — sometimes the menu is *duplicated* (the same plugin's items
appear twice). The old instance is also **leaked**: its background poll timer keeps
it rooted, which pins its collectible `AssemblyLoadContext` so the ALC never unloads,
and the dead instance keeps polling in the background.

This is the concrete bug the user hit.

### Root cause

`PluginLoader` keys its "is this already loaded?" decisions on the **assembly file
path**, not on `Plugin.Id`. When a new version's DLL lands at a *different path* than
the version it replaces, the loader takes the fresh-load branch and **adds a second
`_entries` row for the same `Plugin.Id`** instead of tearing down the old one.

Two real-world path changes trigger this:

- Legacy top-level layout `plugins/<id>.dll` → NuGet subfolder layout
  `plugins/<id>/<id>.dll` (the loader enumerates both — see `LoadAllAsync`, step (1)
  at `Plugins/PluginLoader.cs:158-164` and step (2) at `:171-209`).
- A renamed plugin DLL inside the same subfolder.

The path-keyed decision points, all in `Plugins/PluginLoader.cs`:

- **`LoadOneAsync` idempotency check** — `:223-228`:

  ```csharp
  // Idempotent: if a plugin from this file is already loaded, return it.
  lock (_entriesGate)
  {
      var existing = _entries.FirstOrDefault(e =>
          string.Equals(e.Loaded.AssemblyPath, dllPath, StringComparison.OrdinalIgnoreCase));
      if (existing is not null) return existing.Loaded;
  }
  ```

- **`LoadOrReloadAsync` load-vs-reload branch** — `:321-336`. It decides whether to
  hot-swap or fresh-load by looking up an entry whose `AssemblyPath` equals `dllPath`:

  ```csharp
  string? loadedId;
  lock (_entriesGate)
  {
      loadedId = _entries.FirstOrDefault(e =>
          string.Equals(e.Loaded.AssemblyPath, dllPath, StringComparison.OrdinalIgnoreCase))
          ?.Loaded.Plugin.Id;
  }

  return loadedId is not null
      ? await ReloadOneAsync(loadedId, dllPath, cancellationToken).ConfigureAwait(false)
      : await LoadOneAsync(dllPath, cancellationToken).ConfigureAwait(false);
  ```

  A same-Id DLL at a new path yields `loadedId == null`, so it routes to
  `LoadOneAsync` → `TryLoadAsync`, which appends a new entry.

- **`TryLoadAsync` registration** — the append point, `:509-514`:

  ```csharp
  var loadedPlugin = new LoadedPlugin(plugin, dllPath, verdict);
  var entry = new LoadedPluginEntry(loadedPlugin, loadContext, context);
  lock (_entriesGate)
  {
      _entries.Add(entry);
  }
  ```

  Nothing here checks whether an entry with the same `Plugin.Id` already exists.

The list itself: `private readonly List<LoadedPluginEntry> _entries` at `:44`, guarded
by `private readonly Lock _entriesGate` at `:45`.

Why this surfaces as the visible symptoms:

- **Menu duplication / staleness** — `TrayIcon.BuildMenuItems` iterates
  `pluginLoader.LoadedPlugins` (`TrayIcon.cs:235`) and concatenates every entry's
  `GetMenuItems()`. Two entries for one plugin → two menu blocks. `LoadedPlugins`
  projects straight off `_entries` (`PluginLoader.cs:94-103`).
- **Leak** — the correct teardown path, `UnloadEntryAsync` (`:260-282`), is never
  called for the superseded entry, so the plugin's `ShutdownAsync` (which stops its
  poll timer and unsubscribes its events) never runs. The running timer roots the
  instance; the instance roots the collectible `PluginLoadContext`
  (`Plugins/PluginLoadContext.cs:26-36`, `isCollectible: true` at `:32`), so the ALC
  can't unload. Note the DLL *file* is not locked — the host loads via
  `LoadFromBytes`/`LoadFromStream` (`PluginLoadContext.cs:48-64`), so the uninstall's
  file delete succeeds; only the in-memory instance leaks.

`UnloadEntryAsync` already does the right teardown sequence and is the method the fix
reuses:

```csharp
// PluginLoader.cs:260-282 (abridged)
try { await entry.Loaded.Plugin.ShutdownAsync(cancellationToken).ConfigureAwait(false); }
catch (Exception ex) { _logger.LogError(ex, "Plugin {Id} threw during shutdown.", pluginId); }
entry.Context.Dispose();
try { entry.LoadContext.Unload(); }
catch (Exception ex) { _logger.LogWarning(ex, "Failed to unload AssemblyLoadContext for {Id}.", pluginId); }
GC.Collect();
GC.WaitForPendingFinalizers();
GC.Collect();
```

`UnloadOneAsync` (`:235-252`) and `ReloadOneAsync` (`:290-315`) already dedupe by
`Plugin.Id` — they find the entry by `e.Loaded.Plugin.Id` and unload it. The bug is
purely that the *fresh-load path* (`TryLoadAsync`) has no equivalent Id guard.

### The fix

Dedupe by `Plugin.Id` at the **single chokepoint** where every load funnels:
`TryLoadAsync`, **after** the plugin instance is initialized (so `plugin.Id` is known)
and **BEFORE** the new entry is registered. Find any existing `_entries` item with the
same `Plugin.Id` and tear it down via `UnloadEntryAsync`, regardless of its
`AssemblyPath`.

Code sketch (this is what the ready patch does — see below):

```csharp
var loadedPlugin = new LoadedPlugin(plugin, dllPath, verdict);
var entry = new LoadedPluginEntry(loadedPlugin, loadContext, context);

// Dedupe by Plugin.Id, not assembly path. A new version can land at a
// different path than the one it replaces, so a path-keyed check would miss
// it and leave two entries sharing an Id.
LoadedPluginEntry? superseded;
lock (_entriesGate)
{
    superseded = _entries.FirstOrDefault(e =>
        string.Equals(e.Loaded.Plugin.Id, plugin.Id, StringComparison.OrdinalIgnoreCase));
    if (superseded is not null) _entries.Remove(superseded);
}

if (superseded is not null)
{
    await UnloadEntryAsync(superseded, plugin.Id, cancellationToken).ConfigureAwait(false);
}

lock (_entriesGate)
{
    _entries.Add(entry);
}
```

The removal and the `UnloadEntryAsync` call are split across two `lock` blocks on
purpose: `UnloadEntryAsync` is `async` (awaits `ShutdownAsync`) and forces GC, so it
must not run while holding `_entriesGate` (which is a `System.Threading.Lock`, not
awaitable-safe to hold across an `await`). Remove under the lock, unload outside it,
then add under the lock again.

**Why NOT change `LoadOneAsync`'s idempotency check to key on `Id`:** that check
(`:223-228`) is a genuine idempotency short-circuit — "this exact file is already
loaded, hand back the existing instance." If it matched on `Id` instead of path, a
*different-path same-Id* DLL (exactly the upgrade case) would return the **old**
instance and the new bytes would never load — silently blocking the upgrade. The Id
check belongs only at the registration chokepoint in `TryLoadAsync`, where its job is
"evict the predecessor," not "skip the load." Leave `LoadOneAsync` path-keyed.

### The ready patch

`c:\tmp\azuretray-plugin-id-dedupe.patch` implements exactly the sketch above.
Confirmed contents: it targets **`src/AzureTray/Plugins/PluginLoader.cs`**, replaces
the plain `lock (_entriesGate) { _entries.Add(entry); }` registration block with the
find-superseded / remove-under-lock / `await UnloadEntryAsync(...)` / add-under-lock
sequence, and carries an explanatory comment matching this section. It changes nothing
else.

Apply from the AzureTray repo root:

```
git apply c:/tmp/azuretray-plugin-id-dedupe.patch
```

(Verified with `git apply --check`.)

### Plugin side

**No plugin change required.** The JIT-AzAccess plugin's `Dispose`/`ShutdownAsync`
already stop its poll timer and unsubscribe its `IPluginContext` event handlers, so
once the host actually calls `ShutdownAsync` on the superseded instance (which this
fix makes it do), the old instance tears down cleanly and its ALC unloads.

### Contract / API-version impact

None. Host-internal behavior only.

---

## 2. OPTIONAL — `TrayIcon` ALC-unload timing

### Severity

OPTIONAL. With #1 applied this is **promptness only, not a leak** — the old instance
*does* get collected; it just happens one GC cycle later than strictly necessary.

### Motivation / root cause

`TrayIcon` roots plugin instances through two subscription dictionaries:

```csharp
// TrayIcon.cs:28-29
private readonly List<(IMenuChangeNotifier Notifier, Action Handler)> _menuChangeSubscriptions = new();
private readonly List<(IBadgeProvider Provider, Action Handler)> _badgeSubscriptions = new();
```

It clears them in `OnPluginsChanged`, but on the **WPF dispatcher**:

```csharp
// TrayIcon.cs:71-88
private void OnPluginsChanged()
{
    var dispatcher = System.Windows.Application.Current?.Dispatcher;
    if (dispatcher is null) return;

    void Apply()
    {
        UnsubscribeFromPluginMenuChanges();
        UnsubscribeFromBadgeProviders();
        SubscribeToPluginMenuChanges();
        SubscribeToBadgeProviders();
        RefreshIcon();
        OnPluginMenuChanged();
    }

    if (dispatcher.CheckAccess()) Apply();
    else dispatcher.BeginInvoke(new Action(Apply));
}
```

`PluginsChanged` is raised by `PluginLoader` **after** `UnloadEntryAsync` has already
run its `GC.Collect()` (see the call in `UnloadOneAsync`/`ReloadOneAsync`, and note
`TryLoadAsync` under #1 raises the event via its callers). Because `OnPluginsChanged`
marshals the unsubscribe onto the dispatcher via `BeginInvoke`, the refs in
`_menuChangeSubscriptions` / `_badgeSubscriptions` are still held at the instant the
loader's GC runs. So the superseded instance survives that collection and is only
reclaimed on the *next* GC after the dispatcher drains — an ALC reclaimed a cycle
later than needed.

(The `PluginsChanged += OnPluginsChanged` subscription is wired at `TrayIcon.cs:67`;
teardown handlers `UnsubscribeFromPluginMenuChanges`/`UnsubscribeFromBadgeProviders`
at `:90-97` / `:114-121`.)

### Options

- **Low-risk (recommended if you touch this at all):** after `OnPluginsChanged`'s
  `Apply()` has released the old refs (i.e. after the unsubscribe/resubscribe on the
  dispatcher), trigger a `GC.Collect()` / `GC.WaitForPendingFinalizers()` /
  `GC.Collect()` so the now-unrooted superseded ALC is reclaimed immediately. Cheap,
  contained to `TrayIcon`, no contract change.
- **Higher-risk:** add a dedicated `PluginUnloading` event on `IPluginLoader` that
  fires *before* the ALC unload, and have `TrayIcon` unsubscribe that specific
  plugin's handlers **synchronously on the dispatcher** before the loader proceeds.
  This orders the ref-release strictly ahead of the unload GC, but introduces a new
  loader→UI synchronization point and a blocking dispatcher round-trip inside the
  unload path — more moving parts and more deadlock surface.

### Recommendation

Ship #1 alone first. Only revisit this if profiling shows the extra-cycle retention
actually matters. If you do, take the low-risk option.

### Contract / API-version impact

Low-risk option: none. Higher-risk option: adds `IPluginLoader.PluginUnloading`
(host-internal interface, not the plugin contract) — no `PluginApiVersion` bump.

---

## 3. OPTIONAL — Host config grid renders only Boolean / Text / Number

### Severity

OPTIONAL.

### Motivation

The JIT plugin wanted a **multi-select / dropdown** control for its asset-type
selector. The contract already defines the kinds for it — `PluginOptionKind.Select`
and `PluginOptionKind.Secret` — and `PluginOption.AllowedValues` exists to feed a
combo-box. But the host's generic option grid renders **only** Boolean, Text, and
Number. So the JIT plugin fell back to a stack of Boolean checkboxes instead of a
proper `Select` dropdown. Implementing this lets JIT (and any other plugin) use a real
dropdown, and unlocks masked secret entry.

**Note a live doc/behavior discrepancy:** the contract already *documents* behavior
that the host does not implement. `PluginOption.cs:12-14` states "The host renders a
combo-box and validates that the stored value is one of the listed choices" for
`Select`, and `:16-22` / the `Secret` enum doc at `:69-77` promise "The host stores it
encrypted at rest and masks it in the Settings UI" for `Secret`. Neither is true
today. This change closes that gap (or, at minimum, the doc should be corrected).

### Evidence

- **ViewModel flags** — `ViewModels/PluginOptionViewModel.cs:33-35` expose only three
  kind predicates:

  ```csharp
  public bool IsBoolean => Definition.Kind == PluginOptionKind.Boolean;
  public bool IsText => Definition.Kind == PluginOptionKind.Text;
  public bool IsNumber => Definition.Kind == PluginOptionKind.Number;
  ```

  Backing observable scalars are `_boolValue` / `_textValue` / `_numberValue`
  (`:52-59`) with commit handlers `OnBoolValueChanged` / `OnTextValueChanged` /
  `OnNumberValueChanged` (`:61-86`). There is no `IsSelect`, no `IsSecret`, no
  `AllowedValues` passthrough, and no string-valued property distinct from
  `_textValue` for a selected choice.

- **XAML template** — `PluginConfigWindow.xaml:64-124` (the `Options` `ItemsControl`
  `DataTemplate`) contains exactly one `CheckBox` (`:88-92`, bound `BoolValue`), one
  `TextBox` for text (`:93-96`, bound `TextValue`), one `TextBox` for number
  (`:97-100`, bound `NumberValue`), and the compound Boolean+companion row
  (`:104-120`). **No `ComboBox` and no `PasswordBox` anywhere** in the file. Each
  control's visibility is driven by the matching `Is*` flag via `BoolToVisibility`.

- **Contract already ready** — `PluginOption.AllowedValues` at
  `AzureTray.Plugin.Contracts/PluginOption.cs:46`; `PluginOptionKind.Select` at `:67`;
  `PluginOptionKind.Secret` at `:77`.

### The fix

**`PluginOptionViewModel.cs`:**

- Add `public bool IsSelect => Definition.Kind == PluginOptionKind.Select;` and
  `public bool IsSecret => Definition.Kind == PluginOptionKind.Secret;`.
- Expose the choice list: `public IReadOnlyList<string> AllowedValues =>
  Definition.AllowedValues ?? Array.Empty<string>();`.
- For `Select`, bind the selected item to a string property (reuse `TextValue`, since
  the stored `Select` value type is `string`, or add a dedicated `SelectedValue`
  observable that commits like the others). Initialize it from `initialValue` /
  `DefaultValue` the same way the existing scalars are initialized (`:22-27`).
- `Secret` is a `string` value type too — it can bind to `TextValue`; the difference
  is purely the *control* (masked entry). Persist as usual through `_commit`.
- **Secret-at-rest caveat:** the contract doc promises encryption at rest for
  `Secret`. The current `IPluginConfigStore` persists option values as plain JSON (see
  the persistence wiring in `PluginLoader.TryLoadAsync:467-507`). Implementing a
  *masked control* alone satisfies the UI half but **not** the "encrypted at rest"
  promise. If you ship `Secret`, either also encrypt secret-kind values in the config
  store or narrow the contract doc to say "masked in the UI" only. Flag this to the
  owner; do not silently ship a masked box that writes plaintext while the doc claims
  encryption.

**`PluginConfigWindow.xaml`:** in the `Options` item template, add two controls in
column 1 alongside the existing three:

```xml
<ComboBox Grid.Column="1"
          ItemsSource="{Binding AllowedValues}"
          SelectedItem="{Binding TextValue, Mode=TwoWay}"
          VerticalAlignment="Center"
          Visibility="{Binding IsSelect, Converter={StaticResource BoolToVisibility}}"/>

<PasswordBox Grid.Column="1"
             VerticalAlignment="Center"
             Visibility="{Binding IsSecret, Converter={StaticResource BoolToVisibility}}"/>
```

`PasswordBox.Password` is not a bindable `DependencyProperty`, so wire it either with
a small attached-property behavior or a `PasswordChanged` handler in
`PluginConfigWindow.xaml.cs` that calls the VM's commit — mirror how the existing
`UpdateSourceTrigger=PropertyChanged` text boxes flow values back.

### Contract / API-version impact

None — the contract already declares `Select`, `Secret`, and `AllowedValues`. This is
a pure host-UI implementation catching up to the contract. (If you also add
encryption-at-rest for `Secret`, that is still host-internal — no contract change.)

---

## 4. OPTIONAL — Plugin-triggerable token invalidation (RBAC group-membership 403)

### Severity

OPTIONAL.

### Motivation

When a user is granted the JIT-Requester role **via an Entra group** (rather than a
direct assignment), ARM does not see the role until a **new token is issued** — group
membership claims are baked into the token at acquisition time. Until then, the
plugin's ARM calls return **403** even though the grant succeeded. Today the plugin
can only advise the user to re-sign-in, because the plugin-facing contract exposes no
way to force a fresh token.

### Evidence

- **Contract has no refresh hook.** `IPluginContext`
  (`AzureTray.Plugin.Contracts/IPluginContext.cs`) exposes `GetHttpClient`, `Notifier`,
  `Clipboard`, tenant lists, scopes, `DataDir`, and the default `HostVersion` member
  (`:121`) — **no `InvalidateToken` / force-refresh**. `IPluginHttpClient.SendAsync`
  (`AzureTray.Plugin.Contracts/IPluginHttpClient.cs:53-57`) takes
  `clientName, scope, request, cancellationToken` — **no `forceRefresh` flag**.

- **Host already can invalidate.** `CredentialFactory.Invalidate(string tenantId)`
  exists (`Auth/CredentialFactory.cs:60-67`) and is already on the interface
  `ICredentialFactory.Invalidate` (`Auth/ICredentialFactory.cs:22`). It drops the
  cached wrapped `TokenCredential` for the tenant:

  ```csharp
  // CredentialFactory.cs:60-67
  public void Invalidate(string tenantId)
  {
      if (string.IsNullOrWhiteSpace(tenantId)) return;
      if (_byTenant.TryRemove(tenantId, out var credential) && credential is IDisposable disposable)
      {
          disposable.Dispose();
      }
  }
  ```

- **It is not reachable from a plugin.** The plugin's HTTP path is
  `IPluginContext.GetHttpClient` → `TenantScopedPluginHttpClient` →
  `IPluginHttpClientCore.SendCoreAsync`. `PluginContext` holds only
  `IPluginHttpClientCore _httpCore` (`Plugins/PluginContext.cs:16`, ctor `:35-45`) —
  it has **no** reference to `ICredentialFactory`. The credential factory lives one
  layer down in `HostPluginHttpClient`, which calls `_credentials.GetForTenant(tenantId)`
  (`Plugins/HostPluginHttpClient.cs:47`) and already special-cases
  `AuthenticationRequiredException` to flag re-auth (`:55-62`).

### The fix (two shapes; pick one)

**Shape A — explicit method on the context.** Add to `IPluginContext`:

```csharp
/// <summary>
/// Drops the host's cached credential for <paramref name="tenantId"/> so the
/// next request re-acquires a token. Use after an operation that changes the
/// caller's own directory role/group membership (e.g. a JIT grant delivered via
/// a group), where the in-flight token predates the change and returns 403.
/// </summary>
void InvalidateToken(string tenantId);
```

Route it: `PluginContext.InvalidateToken` → a new `IPluginHttpClientCore` member (e.g.
`void InvalidateTenant(string tenantId)`) implemented on `HostPluginHttpClient` as
`_credentials.Invalidate(tenantId)`. Keeping the plumbing on the existing
`IPluginHttpClientCore` avoids giving `PluginContext` a second host dependency and
matches how egress already flows.

**Shape B — `forceRefresh` flag on send.** Add an overload/parameter to
`IPluginHttpClient.SendAsync` (and `IPluginHttpClientCore.SendCoreAsync`,
`HostPluginHttpClient.SendCoreAsync`) so a call can request a fresh token inline. This
is a bigger contract-surface change and mixes credential-lifecycle into every send.
Shape A is cleaner.

### Important implementation caveat (call out to the AzureTray owner)

`CredentialFactory.Invalidate` only removes the **in-memory wrapped credential**. The
next `GetForTenant` rebuilds an `InteractiveBrowserCredential` over the **same
persistent MSAL token cache** (`TokenCachePersistenceOptions.Name =
$"AzureTray-{tenantId}"`, `CredentialFactory.cs:262-265`) with
`DisableAutomaticAuthentication = true`. MSAL's silent path can therefore return the
**same still-valid access token** (group claims unchanged) until it expires (~1h) or
its refresh token is exercised. So `Invalidate` alone may **not** reliably produce a
token with the new group claim.

To *guarantee* fresh group claims, the host likely needs one of:

- force a token refresh that bypasses the MSAL access-token cache (a
  `TokenRequestContext` configured to refresh, or clearing the tenant's MSAL cache
  entry), or
- route through the existing interactive `ICredentialFactory.SignInAsync` (which
  re-anchors WAM and lands a brand-new token — `CredentialFactory.SignInAsync:69-119`).

Whichever is chosen, `InvalidateToken` should do the thing that actually forces new
claims, not just drop the wrapper. Decide this on the host side; the plugin only needs
a single "get me a token that reflects my just-changed membership" entry point.

### Contract / API-version impact

**Yes.** Adding a member to `IPluginContext` (or to `IPluginHttpClient`) is an
additive contract change. Per the evolution policy in
`AzureTray.Plugin.Contracts/PluginApiVersion.cs:9-27`, an additive, binary-compatible
surface change bumps `PluginApiVersion.Current` and leaves `MinSupported` alone.
`Current` is `3` today (`PluginApiVersion.cs:35`); this change makes it `4`. Prefer a
default-implemented interface member if the addition can carry a safe default, so
older plugins keep loading unchanged. The plugin would consume the new member in its
403 handling (guarded by a `HostVersion` / `ApiVersion` capability check so it still
runs on older hosts).

---

## Verification notes

All references above were read directly from the current AzureTray source at
`c:\Users\jbland\source\repos\AzureTray`:

- `src/AzureTray/Plugins/PluginLoader.cs`
- `src/AzureTray/Plugins/PluginLoadContext.cs`
- `src/AzureTray/Plugins/PluginContext.cs`
- `src/AzureTray/Plugins/HostPluginHttpClient.cs`
- `src/AzureTray/Plugins/IPluginHttpClientCore.cs`
- `src/AzureTray/TrayIcon.cs`
- `src/AzureTray/ViewModels/PluginOptionViewModel.cs`
- `src/AzureTray/PluginConfigWindow.xaml`
- `src/AzureTray/Auth/CredentialFactory.cs`
- `src/AzureTray/Auth/ICredentialFactory.cs`
- `src/AzureTray.Plugin.Contracts/IPluginContext.cs`
- `src/AzureTray.Plugin.Contracts/IPluginHttpClient.cs`
- `src/AzureTray.Plugin.Contracts/PluginOption.cs`
- `src/AzureTray.Plugin.Contracts/PluginApiVersion.cs`

The §1 description was reconciled against `c:\tmp\azuretray-plugin-id-dedupe.patch`.
