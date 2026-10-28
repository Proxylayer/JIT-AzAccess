using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using AzureTray.Plugin.Contracts;
using Xunit;

namespace AzureTray.Plugin.JITAzAccess.Tests;

/// <summary>
/// Guards the plugin's declarative surface — the permission requirements and
/// the option list. Both are data the HOST consumes before the plugin runs, so
/// nothing in the plugin itself ever notices when they are wrong: the
/// permission declaration had its ScopeName and ScopeId swapped and the only
/// symptom was a silent 401 on first use.
/// </summary>
public class PluginDeclarationTests
{
    private static readonly JitAzAccessPlugin Plugin = new();

    // ── Permissions ──────────────────────────────────────────────────────────

    [Fact]
    public void Every_ScopeId_is_a_guid()
    {
        // THE BUG: ScopeId held the wire name ("user_impersonation") and
        // ScopeName held prose. Neither ScopeId parsed, so the host's
        // pre-consent and "Fix Permissions" flow could not resolve either
        // scope and skipped them.
        Assert.All(Plugin.RequiredPermissions, p =>
            Assert.True(Guid.TryParse(p.ScopeId, out _),
                $"ScopeId for '{p.ScopeName}' is not a GUID: '{p.ScopeId}'"));
    }

    [Fact]
    public void Every_ScopeName_is_a_wire_name_not_prose()
    {
        // Wire names have no spaces: "user_impersonation", "Application.Read.All".
        Assert.All(Plugin.RequiredPermissions, p =>
        {
            Assert.False(string.IsNullOrWhiteSpace(p.ScopeName));
            Assert.DoesNotContain(' ', p.ScopeName);
        });
    }

    [Theory]
    // Verified against a live tenant; identical in every tenant, which is why
    // they can be baked in:
    //   az ad sp show --id <resource sp> --query "oauth2PermissionScopes[?value=='<scope>'].id"
    [InlineData(PermissionApi.AzureResourceManager, "user_impersonation", "41094075-9dad-400e-a0bd-54e686782033")]
    [InlineData(PermissionApi.MicrosoftGraph, "Application.Read.All", "c79f8feb-a9db-4090-85f9-90d820caa0eb")]
    public void Declares_the_expected_scope(PermissionApi api, string scopeName, string scopeId)
    {
        var match = Plugin.RequiredPermissions.SingleOrDefault(
            p => p.Api == api && p.ScopeName == scopeName);

        Assert.NotNull(match);
        Assert.Equal(scopeId, match!.ScopeId);
    }

    [Fact]
    public void Declares_no_scope_it_does_not_call()
    {
        // Least privilege: every declared scope triggers a consent prompt.
        // ARM is used by JitClient and ArmVerifier, Graph by JitUrlDiscovery.
        // Anything beyond those two needs a caller to justify it.
        Assert.Equal(2, Plugin.RequiredPermissions.Count);
    }

    [Fact]
    public void Every_permission_has_a_human_readable_display_name()
    {
        Assert.All(Plugin.RequiredPermissions,
            p => Assert.False(string.IsNullOrWhiteSpace(p.DisplayName)));
    }

    // ── Options ──────────────────────────────────────────────────────────────

    [Fact]
    public void Option_keys_are_unique()
    {
        var keys = Plugin.Options.Select(o => o.Key).ToList();
        Assert.Equal(keys.Count, keys.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Every_option_has_a_label_and_a_description()
    {
        Assert.All(Plugin.Options, o =>
        {
            Assert.False(string.IsNullOrWhiteSpace(o.Label));
            Assert.False(string.IsNullOrWhiteSpace(o.Description));
        });
    }

    [Fact]
    public void Every_option_key_is_seeded_with_a_default_value()
    {
        // The typed accessors read straight out of Values, so a key present in
        // Options but absent from Values reads as null and silently falls back.
        var values = Plugin.Values;
        Assert.All(Plugin.Options, o => Assert.True(values.ContainsKey(o.Key),
            $"Option '{o.Key}' is declared but not seeded."));
    }

    [Fact]
    public void Select_options_offer_choices_and_default_to_one_of_them()
    {
        // "Populate AllowedValues or the host renders an empty combo-box."
        var selects = Plugin.Options.Where(o => o.Kind == PluginOptionKind.Select).ToList();
        Assert.NotEmpty(selects);

        Assert.All(selects, o =>
        {
            Assert.NotNull(o.AllowedValues);
            Assert.NotEmpty(o.AllowedValues!);
            Assert.Contains(
                Convert.ToString(o.DefaultValue, CultureInfo.InvariantCulture),
                o.AllowedValues!);
        });
    }

    [Fact]
    public void Offered_durations_is_a_select()
    {
        var option = Plugin.Options.Single(o => o.Key == "allowedDurations");
        Assert.Equal(PluginOptionKind.Select, option.Kind);
    }

    [Fact]
    public void Every_offered_duration_preset_parses_to_a_usable_list()
    {
        // A preset the parser rejects would silently fall back to 1,2,4,8 and
        // the user would be offered durations they did not pick.
        var option = Plugin.Options.Single(o => o.Key == "allowedDurations");

        foreach (var preset in option.AllowedValues!)
        {
            var parsed = preset
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => int.TryParse(x, out var n) ? n : 0)
                .ToList();

            Assert.All(parsed, n => Assert.True(n > 0, $"preset '{preset}' has a non-positive entry"));
            Assert.Equal(parsed.Count, parsed.Distinct().Count());
        }
    }

    [Fact]
    public void Asset_type_checkboxes_are_not_grouped_against_the_All_master()
    {
        // GroupWithKey disables a grouped option's editor when the PARTNER is
        // false. Pointing the per-type checkboxes at "include.all" would grey
        // them out exactly when "All" is OFF — when the user needs them. This
        // asserts the trap stays un-sprung; see docs/CONTRACTS-PROPOSALS.md
        // proposal G.
        var perType = Plugin.Options
            .Where(o => o.Key.StartsWith("include.", StringComparison.Ordinal) && o.Key != "include.all")
            .ToList();

        Assert.Equal(AssetTypeCatalog.All.Count, perType.Count);
        Assert.All(perType, o => Assert.Null(o.GroupWithKey));
    }

    [Fact]
    public void There_is_one_include_checkbox_per_catalog_type()
    {
        foreach (var t in AssetTypeCatalog.All)
        {
            Assert.Contains(Plugin.Options, o => o.Key == "include." + t.Token);
        }
    }

    // ── Identity ─────────────────────────────────────────────────────────────

    [Fact]
    public void Declares_the_current_contract_api_version()
    {
        Assert.Equal(PluginApiVersion.Current, Plugin.ApiVersion);
    }

    [Fact]
    public void Plugin_id_is_the_package_id_the_host_installs_under()
    {
        // The host installs into plugins/<packageId>/ and only loads
        // plugins/<packageId>/<packageId>.dll, and it dedupes loaded plugins
        // by Plugin.Id. A drift here means the plugin extracts but never
        // appears as installed.
        Assert.Equal("net.proxylayer.AzureTray.Plugin.JITAzAccess", Plugin.Id);
    }
}
