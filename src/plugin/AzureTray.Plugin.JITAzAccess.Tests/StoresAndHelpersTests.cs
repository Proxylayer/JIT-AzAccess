using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AzureTray.Plugin.JITAzAccess.Models;
using Xunit;

namespace AzureTray.Plugin.JITAzAccess.Tests;

public sealed class AtomicFileTests : IDisposable
{
    private readonly string _dir =
        Path.Combine(Path.GetTempPath(), "jit-atomic-" + Guid.NewGuid().ToString("N"));

    public AtomicFileTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public void Writes_a_new_file()
    {
        var path = Path.Combine(_dir, "store.json");
        AtomicFile.WriteAllText(path, "[\"a\"]");
        Assert.Equal("[\"a\"]", File.ReadAllText(path));
    }

    [Fact]
    public void Replaces_existing_content()
    {
        var path = Path.Combine(_dir, "store.json");
        File.WriteAllText(path, "[\"old\"]");
        AtomicFile.WriteAllText(path, "[\"new\"]");
        Assert.Equal("[\"new\"]", File.ReadAllText(path));
    }

    [Fact]
    public void Leaves_no_temp_files_behind_on_success()
    {
        var path = Path.Combine(_dir, "store.json");
        AtomicFile.WriteAllText(path, "x");
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    [Fact]
    public void Leaves_the_previous_content_intact_when_the_write_fails()
    {
        // The whole point of the temp-file-then-rename: File.WriteAllText
        // truncates first, so a failure mid-write used to leave a zero-length
        // file that reads back as "no favorites".
        var path = Path.Combine(_dir, "store.json");
        File.WriteAllText(path, "[\"keep-me\"]");

        var missingDir = Path.Combine(_dir, "nope", "store.json");
        Assert.ThrowsAny<IOException>(() => AtomicFile.WriteAllText(missingDir, "irrelevant"));

        Assert.Equal("[\"keep-me\"]", File.ReadAllText(path));
    }

    [Fact]
    public void Survives_a_round_trip_through_FavoritesStore()
    {
        var store = new FavoritesStore(_dir);
        Assert.True(store.Toggle("/subscriptions/s/resourceGroups/rg/providers/p/n"));
        Assert.True(store.IsFavorite("/subscriptions/s/resourceGroups/rg/providers/p/n"));

        var reloaded = new FavoritesStore(_dir);
        Assert.True(reloaded.IsFavorite("/subscriptions/s/resourceGroups/rg/providers/p/n"));
    }

    [Fact]
    public void FavoritesStore_toggles_off_and_persists_the_removal()
    {
        var store = new FavoritesStore(_dir);
        store.Toggle("id-1");
        Assert.False(store.Toggle("id-1"));

        Assert.False(new FavoritesStore(_dir).IsFavorite("id-1"));
    }

    [Fact]
    public void FavoritesStore_starts_empty_rather_than_throwing_on_a_corrupt_file()
    {
        File.WriteAllText(Path.Combine(_dir, "favorites.json"), "{ this is not json");
        var store = new FavoritesStore(_dir);
        Assert.False(store.IsFavorite("anything"));
    }
}

public class FetchFailureGateTests
{
    [Fact]
    public void First_failure_is_loud()
    {
        var gate = new FetchFailureGate();
        Assert.Equal(FetchFailureGate.FailureLog.WarnWithException, gate.RecordFailure(knownCondition: false));
    }

    [Fact]
    public void Repeat_failures_are_quiet()
    {
        var gate = new FetchFailureGate();
        gate.RecordFailure(knownCondition: false);
        Assert.Equal(FetchFailureGate.FailureLog.DebugOneLine, gate.RecordFailure(knownCondition: false));
        Assert.Equal(FetchFailureGate.FailureLog.DebugOneLine, gate.RecordFailure(knownCondition: false));
    }

    [Fact]
    public void A_condition_reported_elsewhere_is_quiet_from_the_first_occurrence()
    {
        var gate = new FetchFailureGate();
        Assert.Equal(FetchFailureGate.FailureLog.DebugOneLine, gate.RecordFailure(knownCondition: true));
    }

    [Fact]
    public void Recovery_is_announced_once_then_not_again()
    {
        var gate = new FetchFailureGate();
        gate.RecordFailure(knownCondition: false);
        Assert.True(gate.RecordSuccess());
        Assert.False(gate.RecordSuccess());
    }

    [Fact]
    public void A_known_condition_still_counts_toward_the_streak_so_recovery_is_reported()
    {
        var gate = new FetchFailureGate();
        gate.RecordFailure(knownCondition: true);
        Assert.True(gate.RecordSuccess());
    }

    [Fact]
    public void A_success_with_no_prior_failure_announces_nothing()
    {
        Assert.False(new FetchFailureGate().RecordSuccess());
    }
}

public class AssetTypeCatalogTests
{
    [Fact]
    public void Covers_all_nineteen_supported_types()
    {
        Assert.Equal(19, AssetTypeCatalog.All.Count);
    }

    [Fact]
    public void Tokens_are_unique()
    {
        var tokens = AssetTypeCatalog.All.Select(t => t.Token).ToList();
        Assert.Equal(tokens.Count, tokens.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void ArgTypes_are_unique_and_lowercase()
    {
        // The Resource Graph `type in~` filter and the ARM-row-to-token map
        // both key off ArgType; a duplicate or a stray capital silently drops
        // a whole asset type out of discovery.
        var argTypes = AssetTypeCatalog.All.Select(t => t.ArgType).ToList();
        Assert.Equal(argTypes.Count, argTypes.Distinct(StringComparer.Ordinal).Count());
        Assert.All(argTypes, a => Assert.Equal(a.ToLowerInvariant(), a));
    }

    [Fact]
    public void ArgType_is_the_lowercase_form_of_ArmType()
    {
        Assert.All(AssetTypeCatalog.All,
            t => Assert.Equal(t.ArmType.ToLowerInvariant(), t.ArgType));
    }

    [Fact]
    public void Every_type_has_a_display_label()
    {
        Assert.All(AssetTypeCatalog.All, t => Assert.False(string.IsNullOrWhiteSpace(t.DisplayLabel)));
    }

    [Fact]
    public void Maps_an_arm_row_type_back_to_its_token()
    {
        Assert.Equal("nsg", AssetTypeCatalog.TokenForArgType("microsoft.network/networksecuritygroups"));
        Assert.Equal("keyVault", AssetTypeCatalog.TokenForArgType("microsoft.keyvault/vaults"));
    }

    [Fact]
    public void Returns_null_for_a_type_outside_the_catalog()
    {
        Assert.Null(AssetTypeCatalog.TokenForArgType("microsoft.compute/virtualmachines"));
    }
}

public class UtcDateTimeConverterTests
{
    private sealed record Holder(DateTime ExpiresUtc);

    private static DateTime Read(string json)
    {
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        options.Converters.Add(new UtcDateTimeConverter());
        return JsonSerializer.Deserialize<Holder>(json, options)!.ExpiresUtc;
    }

    [Fact]
    public void Reads_a_Z_suffixed_timestamp_as_utc()
    {
        var v = Read("{\"expiresUtc\":\"2026-01-02T03:04:05Z\"}");
        Assert.Equal(DateTimeKind.Utc, v.Kind);
        Assert.Equal(3, v.Hour);
    }

    [Fact]
    public void Treats_an_offset_less_timestamp_as_utc_rather_than_local()
    {
        // The server means UTC. Reading it as Unspecified and then comparing
        // against DateTime.UtcNow is how a live grant renders as expired west
        // of UTC, and an expired one as live east of it.
        var v = Read("{\"expiresUtc\":\"2026-01-02T03:04:05\"}");
        Assert.Equal(DateTimeKind.Utc, v.Kind);
        Assert.Equal(3, v.Hour);
    }

    [Fact]
    public void Converts_an_offset_bearing_timestamp_to_the_same_instant()
    {
        var v = Read("{\"expiresUtc\":\"2026-01-02T08:04:05+05:00\"}");
        Assert.Equal(DateTimeKind.Utc, v.Kind);
        Assert.Equal(new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc), v);
    }

    [Fact]
    public void Server_rule_expiry_is_read_through_the_converter()
    {
        var rule = JsonSerializer.Deserialize<JitServerRule>(
            "{\"ruleId\":\"jit-a-0badf00d\",\"expiresUtc\":\"2026-01-02T03:04:05\"}",
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

        Assert.Equal(DateTimeKind.Utc, rule.ExpiresUtc.Kind);
    }

    [Fact]
    public void Grant_response_expiry_is_read_through_the_converter()
    {
        var grant = JsonSerializer.Deserialize<JitGrantResponse>(
            "{\"ruleId\":\"jit-a-0badf00d\",\"expiresUtc\":\"2026-01-02T03:04:05\"}",
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

        Assert.Equal(DateTimeKind.Utc, grant.ExpiresUtc.Kind);
    }
}
