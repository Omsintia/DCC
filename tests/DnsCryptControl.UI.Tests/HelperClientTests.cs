using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B2: the single serialized typed pipe client every UI screen talks to the helper
/// through. Tests inject a fake <c>send</c> delegate — never a real
/// <see cref="DnsCryptControl.Ipc.Transport.IpcPipeClient"/> — so they run headlessly
/// and can assert on the exact wire request/response shape per verb.
/// </summary>
public class HelperClientTests
{
    [Fact]
    public async Task EnableProtectionAsync_serializes_verb_and_payload()
    {
        IpcRequest? captured = null;
        Task<string?> Send(string requestJson, CancellationToken ct)
        {
            captured = IpcSerializer.DeserializeRequest(requestJson);
            var response = Result<ProtectionResponse>.Ok(
                new ProtectionResponse(true, true, true, false, null));
            return Task.FromResult<string?>(IpcSerializer.SerializePayload(response));
        }

        var client = new HelperClient(Send);

        var result = await client.EnableProtectionAsync(withKillSwitch: true, CancellationToken.None);

        Assert.NotNull(captured);
        Assert.Equal(IpcCommandType.EnableProtection, captured!.Command);
        Assert.NotNull(captured.PayloadJson);
        var payload = IpcSerializer.DeserializePayload<EnableProtectionPayload>(captured.PayloadJson!);
        Assert.NotNull(payload);
        Assert.True(payload!.WithKillSwitch);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    [Fact]
    public async Task GetStatusAsync_deserializes_generic_result()
    {
        var canned = Result<StatusResponse>.Ok(
            new StatusResponse(true, "example.resolver", true, false, IpcProtocol.Version, "1.0.0"));
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(IpcSerializer.SerializePayload(canned));

        var client = new HelperClient(Send);

        var result = await client.GetStatusAsync(CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal("example.resolver", result.Value!.ActiveResolver);
    }

    [Fact]
    public async Task FlushDnsCacheAsync_deserializes_non_generic_Result()
    {
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(IpcSerializer.SerializePayload(Result.Ok()));

        var client = new HelperClient(Send);

        var result = await client.FlushDnsCacheAsync(CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    /// <summary>
    /// D1: WriteConfig is the only payload-carrying verb whose handler answers with the
    /// NON-generic <see cref="Result"/>. The helper deserializes with the source-gen
    /// default (PascalCase, case-SENSITIVE) property names, so this pins the exact wire
    /// shape — verb + <c>TomlText</c>/<c>BaseSha256</c> spelled PascalCase — not just a
    /// round-trip through the same serializer.
    /// </summary>
    [Fact]
    public async Task WriteConfigAsync_serializes_verb_and_pascal_case_payload()
    {
        var baseSha = new string('a', 64);
        string? capturedRequestJson = null;
        Task<string?> Send(string requestJson, CancellationToken ct)
        {
            capturedRequestJson = requestJson;
            return Task.FromResult<string?>(IpcSerializer.SerializePayload(Result.Ok()));
        }

        var client = new HelperClient(Send);

        var result = await client.WriteConfigAsync("server_names = ['example']", baseSha, CancellationToken.None);

        Assert.NotNull(capturedRequestJson);
        var captured = IpcSerializer.DeserializeRequest(capturedRequestJson!);
        Assert.NotNull(captured);
        Assert.Equal(IpcCommandType.WriteConfig, captured!.Command);
        Assert.NotNull(captured.PayloadJson);
        Assert.Contains("\"TomlText\":", captured.PayloadJson!, StringComparison.Ordinal);
        Assert.Contains("\"BaseSha256\":", captured.PayloadJson!, StringComparison.Ordinal);
        var payload = IpcSerializer.DeserializePayload<WriteConfigPayload>(captured.PayloadJson!);
        Assert.NotNull(payload);
        Assert.Equal("server_names = ['example']", payload!.TomlText);
        Assert.Equal(baseSha, payload.BaseSha256);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    /// <summary>D2 depends on the helper's refusal code/message (Conflict, OPSEC guard,
    /// schema) arriving intact — assert the non-generic failure Result passes through.</summary>
    [Fact]
    public async Task WriteConfigAsync_surfaces_failure_code_and_message()
    {
        var canned = Result.Fail(
            IpcErrorCode.Conflict,
            "config file changed on disk since it was loaded — reload before saving");
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(IpcSerializer.SerializePayload(canned));

        var client = new HelperClient(Send);

        var result = await client.WriteConfigAsync("cache = true", new string('b', 64), CancellationToken.None);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.Conflict, result.Code);
        Assert.Equal(canned.Message, result.Message);
    }

    [Fact]
    public async Task Null_send_yields_null_for_writeConfig()
    {
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(null);

        var client = new HelperClient(Send);

        var result = await client.WriteConfigAsync("cache = true", new string('c', 64), CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task Null_send_yields_null_for_generic_verb()
    {
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(null);

        var client = new HelperClient(Send);

        var result = await client.GetStatusAsync(CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task Null_send_yields_null_for_flush()
    {
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(null);

        var client = new HelperClient(Send);

        var result = await client.FlushDnsCacheAsync(CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task Concurrent_calls_are_serialized()
    {
        var active = 0;
        var maxObserved = 0;
        var gate = new object();

        async Task<string?> Send(string requestJson, CancellationToken ct)
        {
            lock (gate)
            {
                active++;
                if (active > maxObserved) maxObserved = active;
            }
            Assert.True(active <= 1, "send was re-entered while another call was in flight");
            await Task.Delay(5, ct).ConfigureAwait(false);
            lock (gate)
            {
                active--;
            }
            return IpcSerializer.SerializePayload(Result<StatusResponse>.Ok(
                new StatusResponse(true, null, false, false, IpcProtocol.Version, "1.0.0")));
        }

        var client = new HelperClient(Send);

        var tasks = Enumerable.Range(0, 20)
            .Select(_ => client.GetStatusAsync(CancellationToken.None))
            .ToArray();

        await Task.WhenAll(tasks);

        Assert.Equal(1, maxObserved);
    }

    /// <summary>Phase 5f: UninstallProxyService is a no-payload verb answering with the NON-generic
    /// <see cref="Result"/> (like FlushDnsCache); its wrapper must send the exact verb with no payload.</summary>
    [Fact]
    public async Task UninstallProxyServiceAsync_serializes_verb_and_deserializes_non_generic_Result()
    {
        IpcRequest? captured = null;
        Task<string?> Send(string requestJson, CancellationToken ct)
        {
            captured = IpcSerializer.DeserializeRequest(requestJson);
            return Task.FromResult<string?>(IpcSerializer.SerializePayload(Result.Ok()));
        }

        var client = new HelperClient(Send);

        var result = await client.UninstallProxyServiceAsync(CancellationToken.None);

        Assert.NotNull(captured);
        Assert.Equal(IpcCommandType.UninstallProxyService, captured!.Command);
        Assert.Null(captured.PayloadJson);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    /// <summary>Phase 5f: SetBrowserDohPolicy carries a <see cref="SetTogglePayload"/> and answers with the
    /// NON-generic <see cref="Result"/>; the wrapper reuses the EXISTING verb + payload (no new wire).</summary>
    [Fact]
    public async Task SetBrowserDohPolicyAsync_serializes_verb_and_toggle_payload()
    {
        IpcRequest? captured = null;
        Task<string?> Send(string requestJson, CancellationToken ct)
        {
            captured = IpcSerializer.DeserializeRequest(requestJson);
            return Task.FromResult<string?>(IpcSerializer.SerializePayload(Result.Ok()));
        }

        var client = new HelperClient(Send);

        var result = await client.SetBrowserDohPolicyAsync(enable: true, CancellationToken.None);

        Assert.NotNull(captured);
        Assert.Equal(IpcCommandType.SetBrowserDohPolicy, captured!.Command);
        Assert.NotNull(captured.PayloadJson);
        var payload = IpcSerializer.DeserializePayload<SetTogglePayload>(captured.PayloadJson!);
        Assert.NotNull(payload);
        Assert.True(payload!.Enable);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    [Fact]
    public async Task Null_send_yields_null_for_uninstall_and_setBrowserDoh()
    {
        Task<string?> Send(string requestJson, CancellationToken ct) => Task.FromResult<string?>(null);
        var client = new HelperClient(Send);

        Assert.Null(await client.UninstallProxyServiceAsync(CancellationToken.None));
        Assert.Null(await client.SetBrowserDohPolicyAsync(enable: false, CancellationToken.None));
    }
}
