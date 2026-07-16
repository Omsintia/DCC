using System;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Ipc.Security;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Ipc.Transport;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class IpcPipeClientTests
{
    [Fact]
    public async Task SendAsync_writesRequestFrame_andReadsResponseFrame()
    {
        if (!OperatingSystem.IsWindows()) return; // pipe transport is Windows-only

        const string pipe = "DnsCryptControl.Test." + nameof(SendAsync_writesRequestFrame_andReadsResponseFrame);

        using var server = new NamedPipeServerStream(
            pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            var req = await IpcFraming.ReadFrameAsync(server, CancellationToken.None);
            Assert.Equal("REQ", req);
            await IpcFraming.WriteFrameAsync(server, "RESP", CancellationToken.None);
        });

        // Same-user test pipe has no SYSTEM owner; inject an owner check that passes
        // (F11's owner=SYSTEM gate is covered by IpcPipeClientOwnerCheckTests) so this
        // test can focus on framing round-trip behavior.
        await using var client = new IpcPipeClient(pipe, _ => true);
        var resp = await client.SendAsync("REQ", TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal("RESP", resp);
        await serverTask;
    }

    [Fact]
    public async Task SendAsync_oversizeRequest_returnsNull_andFreshClientNormalCallStillWorks()
    {
        if (!OperatingSystem.IsWindows()) return; // pipe transport is Windows-only

        const string pipe = "DnsCryptControl.Test." + nameof(SendAsync_oversizeRequest_returnsNull_andFreshClientNormalCallStillWorks);

        var serverTask = Task.Run(async () =>
        {
            // One fresh server instance per accepted connection (the production server is
            // likewise one-shot per connection). The oversize client trips its frame guard
            // BEFORE any bytes hit the pipe and closes at once; depending on timing the
            // server observes that either as accept → EOF (ReadFrameAsync null) or as an
            // IOException from WaitForConnectionAsync (client connected and vanished before
            // ConnectNamedPipe ran). Loop past both until the normal round-trip is served.
            while (true)
            {
                using var server = new NamedPipeServerStream(
                    pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                try
                {
                    await server.WaitForConnectionAsync();
                }
                catch (IOException)
                {
                    continue; // oversize client's connect+close raced the accept: nothing was sent
                }

                var req = await IpcFraming.ReadFrameAsync(server, CancellationToken.None);
                if (req is null)
                {
                    continue; // accepted the oversize client's connection, saw zero bytes
                }

                // The only frame that ever reaches the wire is the normal-size one.
                Assert.Equal("REQ", req);
                await IpcFraming.WriteFrameAsync(server, "RESP", CancellationToken.None);
                return;
            }
        });

        // > IpcSerializer.MaxBytes UTF-8 bytes ('a' is 1 byte each): directly reachable from
        // a large pasted config. P5b-E7: this must fail CLOSED (null), never throw.
        var oversize = new string('a', IpcSerializer.MaxBytes + 1);
        await using var client = new IpcPipeClient(pipe, _ => true);
        var resp = await client.SendAsync(oversize, TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.Null(resp);

        // A subsequent NORMAL-size call on a fresh client succeeds — the meaningful
        // post-condition (the oversize failure poisoned nothing).
        await using var freshClient = new IpcPipeClient(pipe, _ => true);
        var normalResp = await freshClient.SendAsync("REQ", TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.Equal("RESP", normalResp);

        await serverTask;
    }

    [Fact]
    public async Task SendAsync_timeoutConnecting_returnsNull()
    {
        if (!OperatingSystem.IsWindows()) return;

        await using var client = new IpcPipeClient("DnsCryptControl.Test.NoSuchServer.PleaseTimeout");
        var resp = await client.SendAsync("REQ", TimeSpan.FromMilliseconds(200), CancellationToken.None);
        Assert.Null(resp); // no server: connect times out, fails closed
    }

    [Fact]
    public async Task SendAsync_afterDispose_returnsNull_neverThrows()
    {
        if (!OperatingSystem.IsWindows()) return; // pipe transport is Windows-only

        var client = new IpcPipeClient();
        await client.DisposeAsync();
        // Sending after dispose must fail closed (null), not throw ObjectDisposedException.
        var result = await client.SendAsync("{\"Command\":0,\"PayloadJson\":null}", TimeSpan.FromSeconds(1), System.Threading.CancellationToken.None);
        Assert.Null(result);
    }

    private sealed class AllowVerifier : ICallerVerifier
    {
        public bool IsTrusted(CallerIdentity caller) => true;
    }

    [Fact]
    public void CallerIdentity_andVerifier_compose()
    {
        ICallerVerifier v = new AllowVerifier();
        Assert.True(v.IsTrusted(new CallerIdentity(1234, @"C:\app\ui.exe")));
    }
}
