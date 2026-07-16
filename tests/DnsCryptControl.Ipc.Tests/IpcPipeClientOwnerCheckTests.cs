using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Ipc.Transport;
using DnsCryptControl.Platform;
using Microsoft.Win32.SafeHandles;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// F11: before the UI trusts a helper pipe, <see cref="IpcPipeClient"/> must confirm the
/// pipe's server-side owner is LocalSystem, defeating a user-level impostor pipe that won
/// the create race. These tests inject a fake owner-check delegate (the real
/// <see cref="PipeServerOwner.IsServerLocalSystem"/> P/Invoke path is exercised only when
/// running as SYSTEM, which xUnit does not) against a real pipe server — same harness
/// pattern as <see cref="IpcPipeClientTests"/> (plain <see cref="NamedPipeServerStream"/>,
/// same-user testing).
/// </summary>
public class IpcPipeClientOwnerCheckTests
{
    /// <summary>Starts a real server loop that mirrors production <see cref="IpcPipeServer"/>
    /// semantics: one-shot-per-connection. Each iteration accepts a single client, dispatches
    /// exactly one GetStatus request through the real handler pipeline, disconnects, and
    /// re-arms a fresh <see cref="NamedPipeServerStream"/> instance for the next connection —
    /// same shape as <c>IpcPipeServer.RunAsync</c>. Runs until <paramref name="ct"/> is
    /// cancelled.</summary>
    private static Task StartDispatchingServer(string pipeName, CancellationToken ct)
    {
        var dispatcher = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController { State = ProxyServiceState.Running },
            new FakeConfigStore());

        return Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                using var server = new NamedPipeServerStream(
                    pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);
                try
                {
                    await server.WaitForConnectionAsync(ct);
                    var requestJson = await IpcFraming.ReadFrameAsync(server, ct);
                    if (requestJson is null) continue;
                    var responseJson = dispatcher.Dispatch(requestJson);
                    await IpcFraming.WriteFrameAsync(server, responseJson, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (IOException)
                {
                    // client vanished mid-exchange; re-arm the loop, same as IpcPipeServer.RunAsync
                }
                finally
                {
                    if (server.IsConnected) server.Disconnect();
                }
            }
        }, ct);
    }

    [Fact]
    public async Task OwnerCheck_returningFalse_failsClosed_andNeverDeliversRequestToServer()
    {
        if (!OperatingSystem.IsWindows()) return;

        const string pipe = "DnsCryptControl.Test." + nameof(OwnerCheck_returningFalse_failsClosed_andNeverDeliversRequestToServer);

        using var server = new NamedPipeServerStream(
            pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);

        var serverSawRequest = false;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(cts.Token);
            // If the client's owner check fails closed, it must never write a request frame:
            // this read will simply time out with the outer cts, proving no frame arrived.
            var req = await IpcFraming.ReadFrameAsync(server, cts.Token);
            if (req is not null) serverSawRequest = true;
        }, cts.Token);

        await using var client = new IpcPipeClient(pipe, _ => false);
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        var resp = await client.SendAsync(req, TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Null(resp); // fail closed: impostor/non-SYSTEM owner

        cts.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(2000));
        Assert.False(serverSawRequest, "client must not deliver a request when the owner check fails");
    }

    [Fact]
    public async Task OwnerCheck_returningTrue_allowsNormalRoundTrip()
    {
        if (!OperatingSystem.IsWindows()) return;

        const string pipe = "DnsCryptControl.Test." + nameof(OwnerCheck_returningTrue_allowsNormalRoundTrip);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = StartDispatchingServer(pipe, cts.Token);

        await using var client = new IpcPipeClient(pipe, _ => true);
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        var resp = await client.SendAsync(req, TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.NotNull(resp);
        var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(resp!);
        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(result.Value!.ProxyRunning);

        cts.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(2000));
    }

    [Fact]
    public async Task OwnerCheck_isInvokedOncePerCall_becauseEveryCallIsAFreshConnection()
    {
        // IpcPipeServer is one-shot-per-connection (accepts, handles one request,
        // Disconnect()s, re-arms). IpcPipeClient therefore never reuses a stream across
        // SendAsync calls — every call opens its own fresh connection, and the F11 owner
        // check runs on every fresh connection. Two SendAsync calls must invoke the owner
        // check twice, once per connection.
        if (!OperatingSystem.IsWindows()) return;

        const string pipe = "DnsCryptControl.Test." + nameof(OwnerCheck_isInvokedOncePerCall_becauseEveryCallIsAFreshConnection);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = StartDispatchingServer(pipe, cts.Token);

        var ownerCheckCalls = 0;
        bool OwnerCheck(SafePipeHandle handle)
        {
            Interlocked.Increment(ref ownerCheckCalls);
            return true;
        }

        await using var client = new IpcPipeClient(pipe, OwnerCheck);
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));

        // 10s (not the usual 5s) per call: this test's server re-arms a fresh pipe instance
        // between the two calls, and under heavy parallel-test-run CPU contention that
        // re-arm can be slow to get scheduled — give it headroom rather than flake.
        var resp1 = await client.SendAsync(req, TimeSpan.FromSeconds(10), CancellationToken.None);
        Assert.NotNull(resp1);

        var resp2 = await client.SendAsync(req, TimeSpan.FromSeconds(10), CancellationToken.None);
        Assert.NotNull(resp2);

        Assert.Equal(2, ownerCheckCalls); // once per SendAsync call, since each call reconnects

        cts.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(2000));
    }
}
