using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Ipc.Transport;
using DnsCryptControl.Platform.Diagnostics;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The single serialized typed pipe client every UI screen talks to the helper
/// through (BE-2). All calls are gated by one <see cref="SemaphoreSlim"/> because the
/// helper's pipe server is single-instance/serial: <see cref="IpcPipeClient"/> opens a
/// fresh one-shot connection per call, and the gate serializes those calls so the UI
/// never races two requests against the helper's single serial server. The gate is
/// purely call-serialization; it is NOT a "busy" indicator (C1 owns that concept via
/// its own in-flight flag).
/// </summary>
public sealed class HelperClient : IHelperClient
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly Func<string, CancellationToken, Task<string?>> _send;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IpcPipeClient? _ownedPipeClient;

    /// <summary>Test seam: inject a fake <paramref name="send"/> to avoid touching a real
    /// named pipe. Production code should use the parameterless-equivalent
    /// <see cref="HelperClient()"/> ctor instead.</summary>
    public HelperClient(Func<string, CancellationToken, Task<string?>> send)
    {
        ArgumentNullException.ThrowIfNull(send);
        _send = send;
    }

    /// <summary>Production ctor: owns a real <see cref="IpcPipeClient"/> connected to the
    /// helper's named pipe, disposed by <see cref="DisposeAsync"/>.</summary>
    public HelperClient(TimeSpan? timeout = null)
    {
        var pipeClient = new IpcPipeClient(PipeNames.Helper);
        _ownedPipeClient = pipeClient;
        var effectiveTimeout = timeout ?? DefaultTimeout;
        _send = (requestJson, ct) => pipeClient.SendAsync(requestJson, effectiveTimeout, ct);
    }

    public Task<Result<StatusResponse>?> GetStatusAsync(CancellationToken ct) =>
        CallAsync<StatusResponse>(IpcCommandType.GetStatus, ct);

    public Task<Result<ProtectionResponse>?> EnableProtectionAsync(bool withKillSwitch, CancellationToken ct) =>
        CallAsync<EnableProtectionPayload, ProtectionResponse>(
            IpcCommandType.EnableProtection, new EnableProtectionPayload(withKillSwitch), ct);

    public Task<Result<ProtectionResponse>?> DisableProtectionAsync(CancellationToken ct) =>
        CallAsync<ProtectionResponse>(IpcCommandType.DisableProtection, ct);

    public Task<Result<DiagnosticsSnapshot>?> RunDiagnosticsAsync(CancellationToken ct) =>
        CallAsync<DiagnosticsSnapshot>(IpcCommandType.RunDiagnostics, ct);

    public Task<Result<ResolveVerification>?> VerifyResolutionAsync(CancellationToken ct) =>
        CallAsync<ResolveVerification>(IpcCommandType.VerifyResolution, ct);

    public Task<Result<ServiceLifecycleResponse>?> RestartProxyAsync(CancellationToken ct) =>
        CallAsync<ServiceLifecycleResponse>(IpcCommandType.RestartProxy, ct);

    public Task<Result?> FlushDnsCacheAsync(CancellationToken ct) =>
        InvokeAsync(
            IpcSerializer.Serialize(new IpcRequest(IpcCommandType.FlushDnsCache, null)),
            static json => IpcSerializer.DeserializePayload<Result>(json),
            ct);

    public Task<Result?> WriteConfigAsync(string tomlText, string baseSha256, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tomlText);
        ArgumentNullException.ThrowIfNull(baseSha256);
        return CallAsync(IpcCommandType.WriteConfig, new WriteConfigPayload(tomlText, baseSha256), ct);
    }

    public Task<Result?> WriteRuleFileAsync(string kind, string content, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(kind);
        ArgumentNullException.ThrowIfNull(content);
        return CallAsync(IpcCommandType.WriteRuleFile, new WriteRuleFilePayload(kind, content), ct);
    }

    public Task<Result?> UninstallProxyServiceAsync(CancellationToken ct) =>
        InvokeAsync(
            IpcSerializer.Serialize(new IpcRequest(IpcCommandType.UninstallProxyService, null)),
            static json => IpcSerializer.DeserializePayload<Result>(json),
            ct);

    public Task<Result?> SetBrowserDohPolicyAsync(bool enable, CancellationToken ct) =>
        CallAsync(IpcCommandType.SetBrowserDohPolicy, new SetTogglePayload(enable), ct);

    public Task<Result?> PlaceOdohCacheAsync(CancellationToken ct) =>
        InvokeAsync(
            IpcSerializer.Serialize(new IpcRequest(IpcCommandType.PlaceOdohCache, null)),
            static json => IpcSerializer.DeserializePayload<Result>(json),
            ct);

    /// <summary>Generic-response verb WITH a typed payload. The payload generic parameter
    /// must stay concrete (never <c>object</c>) — reflection is off in Ipc, so
    /// <see cref="IpcSerializer.SerializePayload{T}"/> resolves the source-gen
    /// <c>JsonTypeInfo</c> via the generic parameter itself.</summary>
    private Task<Result<TResp>?> CallAsync<TPayload, TResp>(IpcCommandType cmd, TPayload payload, CancellationToken ct) =>
        InvokeAsync(
            IpcSerializer.Serialize(new IpcRequest(cmd, IpcSerializer.SerializePayload(payload))),
            static json => IpcSerializer.DeserializePayload<Result<TResp>>(json),
            ct);

    /// <summary>NON-generic-response verb WITH a typed payload (WriteConfig). Same
    /// source-gen constraint as <see cref="CallAsync{TPayload,TResp}"/>: the payload
    /// generic stays concrete because reflection is off in Ipc.</summary>
    private Task<Result?> CallAsync<TPayload>(IpcCommandType cmd, TPayload payload, CancellationToken ct) =>
        InvokeAsync(
            IpcSerializer.Serialize(new IpcRequest(cmd, IpcSerializer.SerializePayload(payload))),
            static json => IpcSerializer.DeserializePayload<Result>(json),
            ct);

    /// <summary>Generic-response verb WITHOUT a payload.</summary>
    private Task<Result<TResp>?> CallAsync<TResp>(IpcCommandType cmd, CancellationToken ct) =>
        InvokeAsync(
            IpcSerializer.Serialize(new IpcRequest(cmd, null)),
            static json => IpcSerializer.DeserializePayload<Result<TResp>>(json),
            ct);

    private async Task<TResult?> InvokeAsync<TResult>(
        string requestJson, Func<string, TResult?> parse, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var response = await _send(requestJson, ct).ConfigureAwait(false);
            return response is null ? default : parse(response);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_ownedPipeClient is not null)
        {
            await _ownedPipeClient.DisposeAsync().ConfigureAwait(false);
        }
        _gate.Dispose();
    }
}
