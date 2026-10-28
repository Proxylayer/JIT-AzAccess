using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.JITAzAccess.Tests.Fakes;
using Xunit;

namespace AzureTray.Plugin.JITAzAccess.Tests;

/// <summary>
/// The egress allowlist is the control that stops the plugin sending the
/// user's ARM bearer token to a host named by an app-registration tag. Entra
/// lets ordinary users register applications by default, so that tag is
/// attacker-writable: anything that gets past these checks is a token
/// exfiltration route.
/// </summary>
public class IsAllowedBackendUrlTests
{
    private static readonly IReadOnlyList<string> Default =
        JitUrlDiscovery.ParseHostSuffixes(JitUrlDiscovery.DefaultAllowedHostSuffixes);

    private static bool Allowed(string? url, IReadOnlyList<string>? allowlist = null) =>
        JitUrlDiscovery.IsAllowedBackendUrl(url, allowlist ?? Default, out _, out _);

    private static string Reason(string? url)
    {
        JitUrlDiscovery.IsAllowedBackendUrl(url, Default, out _, out var reason);
        return reason;
    }

    [Fact]
    public void Accepts_a_function_app_url()
    {
        Assert.True(Allowed("https://func-pgjitazaccess.azurewebsites.net"));
    }

    [Fact]
    public void Accepts_a_url_with_a_path()
    {
        Assert.True(Allowed("https://func-jit.azurewebsites.net/api"));
    }

    [Theory]
    [InlineData("http://func-jit.azurewebsites.net")]          // plaintext
    [InlineData("HTTP://func-jit.azurewebsites.net")]
    public void Rejects_non_https(string url)
    {
        Assert.False(Allowed(url));
        Assert.Contains("not https", Reason(url), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://attacker.example.com")]
    [InlineData("https://azurewebsites.net.attacker.example.com")]  // suffix as a prefix
    [InlineData("https://evil-azurewebsites.net")]                  // no dot before the suffix
    // The allowlist must match the END of the host, not appear anywhere in it.
    // These two read as a legitimate subdomain but resolve to the attacker's
    // domain, and a substring check would wave both through. Found by
    // mutation-testing EndsWith -> Contains, which the cases above did not
    // catch.
    [InlineData("https://func-jit.azurewebsites.net.attacker.example.com")]
    [InlineData("https://login.azurewebsites.net.evil.io")]
    public void Rejects_a_host_off_the_allowlist(string url)
    {
        Assert.False(Allowed(url));
        Assert.Contains("not on the backend allowlist", Reason(url), StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_embedded_credentials()
    {
        // https://func-jit.azurewebsites.net@attacker.example.com/ resolves to
        // the ATTACKER host; the part that looks like the real one is userinfo.
        const string url = "https://func-jit.azurewebsites.net@attacker.example.com/";
        Assert.False(Allowed(url));
    }

    [Fact]
    public void Rejects_a_non_default_port()
    {
        Assert.False(Allowed("https://func-jit.azurewebsites.net:8443"));
        Assert.Contains("non-default port", Reason("https://func-jit.azurewebsites.net:8443"),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://func-jit.azurewebsites.net/?redirect=http://evil")]
    [InlineData("https://func-jit.azurewebsites.net/#frag")]
    public void Rejects_a_query_or_fragment(string url)
    {
        Assert.False(Allowed(url));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-uri")]
    [InlineData("/relative/path")]
    public void Rejects_empty_and_non_absolute_values(string? url)
    {
        Assert.False(Allowed(url));
    }

    [Fact]
    public void Honours_a_custom_exact_host_entry()
    {
        var allowlist = JitUrlDiscovery.ParseHostSuffixes("jit.contoso.com");
        Assert.True(Allowed("https://jit.contoso.com", allowlist));
        // An exact entry must not behave as a suffix.
        Assert.False(Allowed("https://evil.jit.contoso.com", allowlist));
    }

    [Fact]
    public void Honours_a_custom_suffix_entry()
    {
        var allowlist = JitUrlDiscovery.ParseHostSuffixes(".contoso.com");
        Assert.True(Allowed("https://jit.contoso.com", allowlist));
        Assert.False(Allowed("https://contoso.com.evil.net", allowlist));
    }

    [Fact]
    public void Normalises_the_accepted_url_to_what_was_validated()
    {
        JitUrlDiscovery.IsAllowedBackendUrl(
            "https://func-jit.azurewebsites.net/api/", Default, out var parsed, out _);
        Assert.NotNull(parsed);
        Assert.Equal("https://func-jit.azurewebsites.net/api/", parsed!.GetLeftPart(UriPartial.Path));
    }

    [Fact]
    public void ParseHostSuffixes_falls_back_to_the_default_rather_than_disabling_the_check()
    {
        // A blank or junk option value must never mean "allow everything".
        foreach (var raw in new string?[] { null, "", "   ", ",,,", ";" })
        {
            var parsed = JitUrlDiscovery.ParseHostSuffixes(raw);
            Assert.Equal(new[] { JitUrlDiscovery.DefaultAllowedHostSuffixes }, parsed);
        }
    }

    [Fact]
    public void ParseHostSuffixes_splits_and_trims_multiple_entries()
    {
        var parsed = JitUrlDiscovery.ParseHostSuffixes(" .azurewebsites.net , jit.contoso.com ; .azurewebsites.us ");
        Assert.Equal(new[] { ".azurewebsites.net", "jit.contoso.com", ".azurewebsites.us" }, parsed);
    }
}

/// <summary>
/// Tag scanning end to end through a fake Graph response, so the rejection
/// path and the justification opt-out pairing are exercised as the plugin
/// actually runs them.
/// </summary>
public class JitUrlDiscoveryTagTests
{
    private const string Sub = "11111111-1111-1111-1111-111111111111";

    private static string GraphPage(params string[] appsJson) =>
        $"{{\"value\":[{string.Join(",", appsJson)}]}}";

    private static string App(string displayName, params string[] tags) =>
        $"{{\"id\":\"x\",\"appId\":\"app-1\",\"displayName\":\"{displayName}\"," +
        $"\"tags\":[{string.Join(",", tags.Select(t => $"\"{t}\""))}]}}";

    private static JitUrlDiscovery Discovery(FakePluginContext ctx, string? allowlist = null) =>
        new(ctx, () => JitUrlDiscovery.ParseHostSuffixes(
            allowlist ?? JitUrlDiscovery.DefaultAllowedHostSuffixes));

    [Fact]
    public async Task Collects_a_valid_backend_url()
    {
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("AzureTray", $"jit-baseurl:{Sub}=https://func-jit.azurewebsites.net")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.False(result.IsEmpty);
        Assert.Equal("https://func-jit.azurewebsites.net", result.UrlForSubscription(Sub));
    }

    [Fact]
    public async Task Rejects_a_tag_pointing_at_an_attacker_host()
    {
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("Totally Legit App", $"jit-baseurl:{Sub}=https://attacker.example.com")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        // Empty means the plugin has nowhere to send the token.
        Assert.True(result.IsEmpty);
        Assert.Null(result.UrlForSubscription(Sub));
    }

    [Fact]
    public async Task Rejects_a_plaintext_tag_even_on_an_allowlisted_host()
    {
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("AzureTray", $"jit-baseurl:{Sub}=http://func-jit.azurewebsites.net")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.True(result.IsEmpty);
    }

    [Fact]
    public async Task Keeps_a_valid_tag_alongside_a_rejected_one()
    {
        const string other = "22222222-2222-2222-2222-222222222222";
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("Rogue", $"jit-baseurl:{Sub}=https://attacker.example.com"),
            App("AzureTray", $"jit-baseurl:{other}=https://func-jit.azurewebsites.net")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.Null(result.UrlForSubscription(Sub));
        Assert.Equal("https://func-jit.azurewebsites.net", result.UrlForSubscription(other));
    }

    [Fact]
    public async Task Honours_the_justification_opt_out_from_a_real_jit_deployment()
    {
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("AzureTray",
                $"jit-baseurl:{Sub}=https://func-jit.azurewebsites.net",
                "JustificationRequired:false")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.True(result.JustificationOptional);
    }

    [Fact]
    public async Task Ignores_the_justification_opt_out_from_an_app_with_no_valid_backend()
    {
        // Otherwise any user who can register an application could switch off
        // the justification prompt for every AzureTray user in the tenant.
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("AzureTray", $"jit-baseurl:{Sub}=https://func-jit.azurewebsites.net"),
            App("Drive-by", "JustificationRequired:false")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.False(result.IsEmpty);
        Assert.False(result.JustificationOptional);
    }

    [Fact]
    public async Task Ignores_the_opt_out_when_the_apps_only_backend_tag_was_rejected()
    {
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("Rogue",
                $"jit-baseurl:{Sub}=https://attacker.example.com",
                "JustificationRequired:false")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.False(result.JustificationOptional);
    }

    [Fact]
    public async Task First_app_wins_when_two_advertise_the_same_subscription()
    {
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("First",  $"jit-baseurl:{Sub}=https://func-first.azurewebsites.net"),
            App("Second", $"jit-baseurl:{Sub}=https://func-second.azurewebsites.net")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.Equal("https://func-first.azurewebsites.net", result.UrlForSubscription(Sub));
    }

    [Fact]
    public async Task Returns_empty_when_graph_fails()
    {
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.Forbidden, "{}");

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.True(result.IsEmpty);
    }

    [Fact]
    public async Task AllUrls_deduplicates_subscriptions_sharing_one_deployment()
    {
        const string other = "22222222-2222-2222-2222-222222222222";
        var ctx = new FakePluginContext();
        ctx.Http.Enqueue(HttpStatusCode.OK, GraphPage(
            App("AzureTray",
                $"jit-baseurl:{Sub}=https://func-jit.azurewebsites.net",
                $"jit-baseurl:{other}=https://func-jit.azurewebsites.net")));

        var result = await Discovery(ctx).DiscoverAsync("tenant", CancellationToken.None);

        Assert.Single(result.AllUrls);
    }
}
