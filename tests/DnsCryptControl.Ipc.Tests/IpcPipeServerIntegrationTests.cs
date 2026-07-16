using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Ipc.Security;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Ipc.Transport;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// End-to-end tests over a real named pipe. Uses <c>HandleConnectionAsync</c> (internal)
/// directly so the test can create a plain pipe without needing SYSTEM privileges to set the
/// pipe owner. The DACL / owner contract is verified in <see cref="PipeServerSecurityTests"/>
/// (pure unit test). The RunAsync accept loop is the integration of those two pieces; it
/// requires the service to run as LocalSystem (production constraint, not testable headless).
/// </summary>
[Trait("Category", "ManualIntegration")]
[SupportedOSPlatform("windows")]
public class IpcPipeServerIntegrationTests
{
    private static SecurityIdentifier CurrentUserSid() =>
        WindowsIdentity.GetCurrent().User!;

    [Fact]
    public async Task TrustedCaller_getsDispatchedResponse()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string pipe = "DnsCryptControl.Test.IntegrationTrusted";

        var dispatcher = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController { State = DnsCryptControl.Platform.ProxyServiceState.Running },
            new FakeConfigStore());
        var verifier = new FakeCallerVerifier { Allow = true };

        // Create a plain server pipe (no DACL / owner — same-user testing) to validate the
        // gate+dispatch logic without needing LocalSystem privileges for SetOwner.
        // Explicit buffer sizes (4096) are required: zero-byte buffers cause a deadlock when
        // the server writes a response/deny frame before reading the client's request frame.
        using var server = new NamedPipeServerStream(
            pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);

        var pipeServer = new IpcPipeServer(
            dispatcher, verifier, () => CurrentUserSid(), pipe,
            _ => new CallerIdentity(42, @"C:\app\ui.exe"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(cts.Token);
            await pipeServer.HandleConnectionAsync(server, cts.Token);
            if (server.IsConnected) server.Disconnect();
        }, cts.Token);

        await using var client = new IpcPipeClient(pipe);
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        var resp = await client.SendAsync(req, TimeSpan.FromSeconds(5), CancellationToken.None);
        var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(resp!);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(result.Value!.ProxyRunning);

        cts.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(2000));
    }

    [Fact]
    public async Task UntrustedCaller_getsNotAuthorized()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string pipe = "DnsCryptControl.Test.IntegrationUntrusted";

        var dispatcher = TestHandlerRegistry.BuildDispatcher(new FakeProxyServiceController(), new FakeConfigStore());
        var verifier = new FakeCallerVerifier { Allow = false };

        // Explicit buffer sizes (4096) required — see TrustedCaller test comment above.
        using var server = new NamedPipeServerStream(
            pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);

        var pipeServer = new IpcPipeServer(
            dispatcher, verifier, () => CurrentUserSid(), pipe,
            _ => new CallerIdentity(42, @"C:\evil\hacker.exe"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(cts.Token);
            await pipeServer.HandleConnectionAsync(server, cts.Token);
            if (server.IsConnected) server.Disconnect();
        }, cts.Token);

        await using var client = new IpcPipeClient(pipe);
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        var resp = await client.SendAsync(req, TimeSpan.FromSeconds(5), CancellationToken.None);
        var result = IpcSerializer.DeserializePayload<Result>(resp!);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.NotAuthorized, result.Code);

        cts.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(2000));
    }
}

/// <summary>
/// Regression coverage for the one-shot-server / stream-reuse flicker bug: IpcPipeServer is
/// one-shot-per-connection (RunAsync accepts, handles exactly one request, Disconnect()s, and
/// re-arms a fresh pipe instance for the next client). Before the fix, IpcPipeClient.SendAsync
/// cached and reused its NamedPipeClientStream whenever NamedPipeClientStream.IsConnected was
/// still (stale-)true, so the second sequential call on one client reused a stream the server
/// had already disconnected — the write/read failed and SendAsync returned null. Symptom in
/// the field: the UI polls status every ~1.5s on one long-lived IpcPipeClient, so every OTHER
/// poll failed closed and the "helper unavailable" banner flickered on/off.
///
/// Not marked ManualIntegration (unlike <see cref="IpcPipeServerIntegrationTests"/>): this
/// harness drives a hand-rolled accept loop over a plain, no-DACL NamedPipeServerStream (same
/// same-user-testing trick used throughout this file) that repeats WaitForConnectionAsync +
/// HandleConnectionAsync + Disconnect() across multiple connections — the same shape as the
/// real RunAsync loop — so it runs headlessly in CI under the default
/// "Category!=ManualIntegration" filter and can actually catch this regression.
/// </summary>
[SupportedOSPlatform("windows")]
public class IpcPipeServerSequentialRequestsTests
{
    private static SecurityIdentifier CurrentUserSid() =>
        WindowsIdentity.GetCurrent().User!;

    /// <summary>Runs a one-shot-per-connection accept loop against the REAL
    /// <see cref="IpcPipeServer.HandleConnectionAsync"/>, mirroring RunAsync: accept one
    /// client, handle exactly one request, Disconnect(), re-arm a fresh server-stream
    /// instance, repeat until <paramref name="ct"/> is cancelled.</summary>
    private static Task RunOneShotPerConnectionLoop(IpcPipeServer pipeServer, string pipeName, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                using var server = new NamedPipeServerStream(
                    pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);
                try
                {
                    await server.WaitForConnectionAsync(ct);
                    await pipeServer.HandleConnectionAsync(server, ct);
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
    public async Task Sequential_requests_on_one_client_all_succeed_against_one_shot_server()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string pipe = "DnsCryptControl.Test.SequentialOneShot";

        var dispatcher = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController { State = DnsCryptControl.Platform.ProxyServiceState.Running },
            new FakeConfigStore());
        // Fake allow-all verifier (matches the other integration tests): the caller gate is
        // not what this regression test is about, so it must never interfere.
        var verifier = new FakeCallerVerifier { Allow = true };

        var pipeServer = new IpcPipeServer(
            dispatcher, verifier, () => CurrentUserSid(), pipe,
            _ => new CallerIdentity(42, @"C:\app\ui.exe"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = RunOneShotPerConnectionLoop(pipeServer, pipe, cts.Token);

        // ONE long-lived client, THREE sequential requests — exactly how the UI's status
        // poller uses IpcPipeClient. With the old stream-reuse bug, request #2 (and any
        // further odd-numbered request beyond #1) would reuse a stream the server had
        // already Disconnect()ed after request #1, and SendAsync would return null.
        // Same-user test pipe has no SYSTEM owner, so inject an always-true owner check
        // (F11's real owner=SYSTEM gate is covered by IpcPipeClientOwnerCheckTests) — this
        // test is about connection reuse across sequential calls, not the owner gate.
        await using var client = new IpcPipeClient(pipe, _ => true);
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));

        for (var i = 1; i <= 3; i++)
        {
            // 10s (not the usual 5s): the server re-arms a fresh pipe instance between each
            // call, and under heavy parallel-test-run CPU contention that can be slow to get
            // scheduled — give it headroom rather than flake.
            var resp = await client.SendAsync(req, TimeSpan.FromSeconds(10), CancellationToken.None);
            Assert.True(resp is not null, $"request #{i} returned null (stream-reuse-after-disconnect regression)");

            var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(resp!);
            Assert.NotNull(result);
            Assert.True(result!.Success, $"request #{i} was not a success result");
            Assert.True(result.Value!.ProxyRunning, $"request #{i} did not deserialize the expected payload");
        }

        cts.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(2000));
    }

    /// <summary>
    /// Covers the server-side drain (<c>DrainToClientAsync</c> → <c>WaitForPipeDrain</c>) that fixes
    /// the flicker: the response must be delivered in full even though the accept loop
    /// <c>Disconnect()</c>s right after, and the drain must swallow the "client already closed"
    /// faults rather than throw out of <see cref="IpcPipeServer.HandleConnectionAsync"/>. The client
    /// reads the whole frame then disposes immediately (its <c>finally</c>), exercising the drain and
    /// its tolerance of a client that closes its end at (or just after) drain completion.
    /// </summary>
    [Fact]
    public async Task Drain_deliversFullResponse_andNeverThrowsWhenClientClosesImmediately()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string pipe = "DnsCryptControl.Test.DrainDelivery";

        var dispatcher = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController { State = DnsCryptControl.Platform.ProxyServiceState.Running },
            new FakeConfigStore());
        var verifier = new FakeCallerVerifier { Allow = true };

        using var server = new NamedPipeServerStream(
            pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);

        var pipeServer = new IpcPipeServer(
            dispatcher, verifier, () => CurrentUserSid(), pipe,
            _ => new CallerIdentity(42, @"C:\app\ui.exe"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        Exception? serverFault = null;
        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(cts.Token);
            try { await pipeServer.HandleConnectionAsync(server, cts.Token); }
            catch (Exception ex) { serverFault = ex; }
            // Aggressive disconnect immediately after Handle returns — the drain must have already
            // ensured the client read the frame, so this cannot truncate the response.
            if (server.IsConnected) server.Disconnect();
        }, cts.Token);

        string? resp;
        await using (var client = new IpcPipeClient(pipe, _ => true))
        {
            var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
            resp = await client.SendAsync(req, TimeSpan.FromSeconds(5), CancellationToken.None);
        }

        await Task.WhenAny(serverTask, Task.Delay(3000));

        Assert.Null(serverFault);           // drain never throws out of HandleConnectionAsync
        Assert.NotNull(resp);               // a full, untruncated response was delivered
        var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(resp!);
        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(result.Value!.ProxyRunning);
    }
}
