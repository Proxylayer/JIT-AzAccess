using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AzureTray.Plugin.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AzureTray.Plugin.JITAzAccess.Tests.Fakes;

/// <summary>
/// Canned HTTP responder. Each queued entry answers one SendAsync call, in
/// order; requests are recorded so a test can assert what the plugin asked for
/// — and, for the egress tests, that it asked for nothing at all.
/// </summary>
internal sealed class FakeHttpClient : IPluginHttpClient
{
    private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new();

    public List<HttpRequestMessage> Requests { get; } = new();

    public void Enqueue(HttpStatusCode status, string body) =>
        _responses.Enqueue(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(body),
        });

    public void Enqueue(Func<HttpRequestMessage, HttpResponseMessage> responder) =>
        _responses.Enqueue(responder);

    public Task<HttpResponseMessage> SendAsync(
        string clientName, string scope, HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        if (_responses.Count == 0)
        {
            throw new InvalidOperationException(
                $"FakeHttpClient had no queued response for {request.Method} {request.RequestUri}.");
        }
        return Task.FromResult(_responses.Dequeue()(request));
    }
}

/// <summary>
/// Minimal <see cref="IPluginContext"/> for exercising plugin internals without
/// a running host.
/// </summary>
internal sealed class FakePluginContext : IPluginContext
{
    public FakePluginContext(string? dataDir = null, ILogger? logger = null)
    {
        DataDir = dataDir ?? Environment.CurrentDirectory;
        Logger = logger ?? NullLogger.Instance;
    }

    public FakeHttpClient Http { get; } = new();

    public ILogger Logger { get; }
    public string DataDir { get; }
    public string GraphScope => "https://graph.microsoft.com/.default";
    public string ArmScope => "https://management.azure.com/.default";
    public string? HostVersion => "0.12.2";

    public IPluginHttpClient GetHttpClient(string tenantId) => Http;

    public IReadOnlyList<PluginTenant> Tenants { get; set; } = Array.Empty<PluginTenant>();
    public IReadOnlyList<PluginTenant> ReadyTenants { get; set; } = Array.Empty<PluginTenant>();
    public bool IsTenantReady(string tenantId) => true;

    public event Action<PluginTenant>? TenantReady;
    public event Action<string>? TenantRemoved;

    public INotifier Notifier { get; } = new FakeNotifier();
    public IClipboard Clipboard { get; } = new FakeClipboard();

    // Raised only so the compiler does not warn the events are never used; no
    // test drives tenant lifecycle through the fake.
    internal void RaiseTenantReady(PluginTenant t) => TenantReady?.Invoke(t);
    internal void RaiseTenantRemoved(string id) => TenantRemoved?.Invoke(id);
}

internal sealed class FakeNotifier : INotifier
{
    public List<NotificationRequest> Shown { get; } = new();

    /// <summary>
    /// Records the request and answers with <see cref="Reply"/>. The default
    /// null stands for a dismissed prompt, which is what the plugin's
    /// `is not ChoiceResult { ... }` guards are written against.
    /// </summary>
    public Task<NotificationResult> ShowAsync(
        NotificationRequest request, CancellationToken cancellationToken)
    {
        Shown.Add(request);
        return Task.FromResult(Reply!);
    }

    /// <summary>What the next ShowAsync answers with; null means dismissed.</summary>
    public NotificationResult? Reply { get; set; }
}

internal sealed class FakeClipboard : IClipboard
{
    public string? Text { get; private set; }
    public void SetText(string text) => Text = text;
}
