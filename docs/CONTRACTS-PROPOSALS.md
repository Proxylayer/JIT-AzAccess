# AzureTray.Plugin.Contracts — Proposals from the JIT-AzAccess Plugin

## What this document is

Gaps in **`AzureTray.Plugin.Contracts`** found while hardening the JIT-AzAccess plugin,
written up for the AzureTray owner. It is the sibling of
[AZURETRAY-HOST-CHANGES.md](AZURETRAY-HOST-CHANGES.md), which tracked host *implementation*
bugs — all of those have shipped. What is left is contract surface.

Verified against `AzureTray.Plugin.Contracts` **1.5.0** and AzureTray at `25ea5e9`,
2026-10-28. The plugin references 1.5.0 and declares `PluginApiVersion.Current` (**4**);
no version upgrade is pending. Every proposal below is **additive** and would bump
`Current` without moving `MinSupported`.

File:line references are into `c:\Users\jbland\source\repos\AzureTray`.

### Summary

| # | Proposal | Why it matters here | Shape |
|---|----------|---------------------|-------|
| A | Declare a permission against a **custom API** | Blocks the structural fix for "the backend accepts any ARM token in the tenant" | `PermissionApi.Custom` + `ResourceAppId` |
| B | Signed-in **user identity** | Caller UPN in errors; `oid` as the identity key instead of UPN | `IPluginContext.GetAccount(tenantId)` |
| C | **Egress allowlist** enforced by the host | The contract tells plugins to do this and gives them no primitive | `IPluginHttpClient.RestrictDestinations` |
| D | **Multi-select** option kind | 19 asset types are 19 checkboxes | `PluginOptionKind.MultiSelect` |
| E | **Resilience policy** visible, and retries controllable | The host retries non-idempotent writes; the plugin cannot see or stop it | `IPluginContext.GetHttpPolicy` |
| F | Cross-process-safe **plugin state** | `DataDir` and nothing else — no lock, no transaction | `IPluginContext.AcquireDataLockAsync` |
| G | `GroupWithKey` for **more than one follower** | Using it as documented would hide 18 of 19 options | Fix or document the 1:1 limit |

---

## A. Declare a permission against a custom API

**Today.** `PermissionApi` offers exactly two values:

```csharp
// AzureTray.Plugin.Contracts — PermissionApi
MicrosoftGraph, AzureResourceManager
```

Meanwhile `IPluginHttpClient.SendAsync` explicitly accepts a custom scope such as
`api://my-backend/.default`. So a plugin can *call* its own backend but cannot *declare*
the scope for the host to pre-consent — the one thing `RequiredPermissions` exists for.

**Why it matters here.** This is the blocker for the structural fix to the JIT backend's
authentication. The plugin sends an **ARM-audience** token to the JIT function app, which
is precisely why the server has to accept any ARM token in the tenant: every token Azure
CLI, Azure PowerShell or any consented app mints is accepted verbatim by all three
endpoints. A dedicated JIT app registration exposing
`api://<jit-app-id>/user_impersonation` would make an intercepted token useless against
ARM, and would turn the server-side `appid` allowlist from the only control into a
backstop.

**Note this reverses a deliberate design choice** (`src/README.md`: "plain ARM-audience
tokens, no dedicated app registration") and costs a per-tenant app registration plus
consent. It is a decision for the JIT-AzAccess owner, not a change to make silently.

**Proposal.** Add `PermissionApi.Custom` and `string? ResourceAppId` to
`PluginPermissionRequirement`. The host resolves the service principal by `ResourceAppId`
to find the scope, exactly as it does for the two well-known APIs.

---

## B. Signed-in user identity

**Today.** `PluginTenant` is `(TenantId, DisplayName)`. A plugin cannot learn who is
signed in.

**Why it matters here.** Two things want it. Error context currently says "a grant
failed" without saying for whom. More substantially, JIT rules are keyed by **UPN**
(`RequestedBy`), which `Revoke-JITAccess` and `Get-JITRules` match on — so a renamed UPN
loses its grants and a recycled one inherits them. Moving the key to `oid` needs the
plugin to know the caller's object id.

**The host already holds this.** `CredentialFactory` keeps a per-tenant
`AuthenticationRecord` (`Auth/CredentialFactory.cs:43`), whose `Username` is the UPN and
whose `HomeAccountId` is `<oid>.<tid>`; the host logs the username on sign-in
(`:355-356`). `PluginContext` already injects `ICredentialFactory`, so it can forward
behind its existing tenant-enabled check. The host also already declares Graph
`User.Read` for its own `/me` lookup.

**Proposal.** A default-implemented member so old hosts stay source-compatible:

```csharp
PluginAccount? GetAccount(string tenantId) => null;

public sealed record PluginAccount(
    string TenantId, string? UserPrincipalName, string? ObjectId);
```

---

## C. Egress allowlist enforced by the host

**Today.** `IPluginHttpClient`'s own documentation instructs plugins to validate scheme
and host against an allowlist before forwarding a URL — and provides no primitive to do
it with. Every plugin reimplements it, and this one **didn't**.

**Why it matters here.** That was the single worst defect found in this plugin. The JIT
backend URL is read from a `jit-baseurl:` tag on *any* app registration the signed-in
user can read, and Entra lets ordinary users register applications by default. The URL
went unvalidated into `JitClient`, which sent it the host-acquired **ARM bearer token**
on every grant, revoke and 90-second poll. Any user in the tenant could have published a
tag and collected every AzureTray user's ARM token.

The host attaches the bearer to whatever absolute URI the plugin supplies:

```csharp
// Plugins/HostPluginHttpClient.cs:68
request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
```

with no scheme or host check — and because that URI is absolute, the named `arm` client's
`BaseAddress` is bypassed rather than enforced.

The plugin now validates this itself (`JitUrlDiscovery.IsAllowedBackendUrl`: absolute,
https, allowlisted host suffix, no userinfo, default port, no query or fragment) and that
stands regardless of what the contract does. But a host-enforced check is the difference
between a convention and a control.

**Proposal, two shapes.**

*Opt-in (smaller).* A default-implemented
`void RestrictDestinations(IReadOnlyList<string> allowedHosts) { }` on
`IPluginHttpClient`, stored by `TenantScopedPluginHttpClient` and checked in
`SendCoreAsync` **before** the bearer is attached. The no-op default is fail-open, so it
protects only plugins that opt in.

*Fail-closed (bigger, better).* Validate against the named client's own `BaseAddress`,
and add an explicit `PluginHttpClientNames.CustomBackend` for off-ARM destinations that a
plugin must ask for. This catches the whole class of bug for every plugin, including ones
whose authors never read the warning. Worth putting to the host owner as the design
question.

---

## D. Multi-select option kind

**Today.** `PluginOptionKind.Select` is a single-choice combo box over `AllowedValues`.

**Why it matters here.** JIT-AzAccess discovers 19 asset types and lets the user narrow
that. With no multi-select kind the picker is 19 Boolean checkboxes plus an "All" master,
and the master has to be kept in sync with the individual boxes in `SetValue`. Adding a
twentieth asset type adds a twentieth checkbox.

**Proposal.** `PluginOptionKind.MultiSelect` over `AllowedValues`, value type `string[]`.
That collapses the grid to one control and removes the master-checkbox bookkeeping —
and with it the need for proposal G.

---

## E. Resilience policy is opaque, and it retries non-idempotent writes

**Today.** The host wraps the `arm` and `graph` named clients in a standard resilience
handler (`Program.cs:336-339`, configured at `:387-392`): 30s per attempt, 100s total,
60s circuit-breaker sampling window. None of it is visible to a plugin, and none of it
can be disabled.

**Why it matters here, concretely.** The retry **re-sends the JIT grant POST**. The
host's own comment at `Program.cs:328-334` already identifies this hazard for ARM writes:

> When an attempt times out after the server has already committed the write, the retry
> re-sends it and ARM answers 409 — surfacing a spurious failure for a request that
> actually succeeded.

The host reconciled that for PIM inside `ArmPimClient`. The JIT plugin cannot: a slow
LRO-backed grant exceeds the 30s attempt timeout, the POST is re-sent, the second attempt
finds the row the first one wrote, and the user is told their grant conflicted when it
had in fact succeeded.

That had to be fixed **server-side** instead: `Request-JITAccess` now treats a cooldown
hit whose existing rule matches the same caller IP as success and returns the existing
rule, deliberately without extending its expiry. That is the right behaviour anyway, but
it was forced by an invisible client policy.

**Proposal.** A default-implemented
`PluginHttpPolicy? GetHttpPolicy(string clientName) => null;` on `IPluginContext`,
exposing attempt timeout, total timeout, max retries and whether non-idempotent requests
are retried — projected from `IOptionsMonitor<HttpStandardResilienceOptions>.Get(clientName)`
so it cannot drift from the real configuration.

If actual *control* is wanted rather than visibility, a `SendAsync` overload taking
`bool disableRetries` is the alternative, and it keeps Polly-shaped types out of the
contracts assembly.

---

## F. Cross-process-safe plugin state

**Today.** Contracts offer `DataDir` and nothing else: no lock, no transaction, no change
notification.

**Why it matters here.** `FavoritesStore` guards with an in-process `object _lock` and
used a non-atomic `File.WriteAllText`, which truncates before it writes — so a crash, an
upgrade overlap or a second user session mid-write left a zero-length file that reads
back as "no favorites", a silent reset the user never asked for. The plugin now writes
through `AtomicFile` (temp file in the same directory, then `File.Move(overwrite: true)`),
which fixes the torn-write half. It does **not** fix two processes racing.

**Proposal.**

```csharp
Task<IDisposable?> AcquireDataLockAsync(
    string name, TimeSpan timeout, CancellationToken ct = default)
    => Task.FromResult<IDisposable?>(null);
```

backed by a named mutex keyed on the sanitized plugin id the host already computes
(`Plugins/PluginLoader.cs:482`). The atomic-write fix stands regardless and does not wait
on this.

---

## G. `GroupWithKey` supports only one follower per master

**Today.** `PluginOption.GroupWithKey` is documented as:

> When set, this option renders inline beside the option whose `Key` matches — typically
> a `Boolean` "enabled" checkbox that gates this option's input. The host disables this
> option's editor when the partner's value is `false`.

Reading that, the obvious use here is to tie the 19 asset-type checkboxes to the "All
asset types" master so the host greys them out when the master is set. **That does not
work**, in two separate ways, and both are only visible in the host implementation:

1. **One slot per master.** `SettingsViewModel.cs:643-656` assigns
   `master.Companion = optionVm` — a single reference — then adds every follower to an
   `attached` set which is excluded from the flat `Options` list. Point 19 followers at
   one master and the last one wins: **18 asset-type checkboxes disappear from the
   settings window entirely.**

2. **The compound row is Boolean-master-gates-Number-follower.**
   `PluginConfigWindow.xaml:133-150` binds `Companion.NumberValue` into a `TextBox` with
   `IsEnabled="{Binding BoolValue}"`. A Boolean follower would render as a number box.
   The gate polarity is also the opposite of what this UI needs — enabled while the
   master is **true**, where the per-type checkboxes should be editable precisely when
   "All" is **off**.

So JIT-AzAccess does **not** set `GroupWithKey`, and
`PluginDeclarationTests.Asset_type_checkboxes_are_not_grouped_against_the_All_master`
asserts it stays that way.

**Proposal, cheapest first.**

1. **Document the real contract.** Say that `GroupWithKey` pairs exactly one Number
   follower to one Boolean master, and that the follower is enabled while the master is
   true. That alone prevents the next plugin author losing options silently.
2. **Fail loudly** when two options name the same master, rather than dropping the
   extras from the UI.
3. If general grouping is wanted: make `Companion` a list, render followers by their own
   `Kind`, and add something like `GroupGateInverted` for the "disable while the master
   is on" case.

Proposal **D** removes the need for any of this in *this* plugin — but the silent
option-loss is worth fixing for every other one.

---

## Not proposed

* **`PluginOptionKind.Secret`** — shipped in 1.3.0 and rendered since host v0.7.0, but
  JIT-AzAccess stores no credential. Its one security-relevant option, the backend host
  allowlist, is deliberately plain text so the user can read and audit it.
* **A `HostVersion` capability gate** — `HostVersion` exists and is logged at initialise
  for support, but the one capability worth gating on, `RefreshTokenAsync`, already
  self-reports by returning `false` on a host that does not implement it. Asking the
  feature beats comparing version strings.
