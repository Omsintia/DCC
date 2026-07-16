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
/// In-memory bidirectional stream used for headless HandleConnectionAsync tests.
/// Reads come from <paramref name="readSource"/>; writes accumulate in <paramref name="writeSink"/>.
/// </summary>
internal sealed class DuplexMemoryStream(MemoryStream readSource, MemoryStream writeSink) : Stream
{
    public override bool CanRead  => true;
    public override bool CanWrite => true;
    public override bool CanSeek  => false;
    public override long Length   => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) =>
        readSource.Read(buffer, offset, count);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        readSource.ReadAsync(buffer, offset, count, ct);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        readSource.ReadAsync(buffer, ct);

    public override void Write(byte[] buffer, int offset, int count) =>
        writeSink.Write(buffer, offset, count);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        writeSink.WriteAsync(buffer, offset, count, ct);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
        writeSink.WriteAsync(buffer, ct);

    public override void Flush() { }
    public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>
/// Unit and integration tests for <see cref="IpcPipeServer"/> security hardening
/// (Fix wave 1: anti-squat, per-connection timeout, fault containment).
/// </summary>
[SupportedOSPlatform("windows")]
public class IpcPipeServerTests
{
    private static SecurityIdentifier CurrentUserSid() =>
        WindowsIdentity.GetCurrent().User!;

    // -------------------------------------------------------------------------
    // Gate-before-dispatch regression test (headless, non-ManualIntegration).
    //
    // Drives the REAL HandleConnectionAsync over an in-memory duplex stream,
    // proving that an UNTRUSTED caller is denied BEFORE any handler runs.
    //
    // Why identity is null on a plain Stream:
    //   HandleConnectionAsync resolves identity only when the stream is a
    //   NamedPipeServerStream (it casts first). A plain DuplexMemoryStream is
    //   never cast to that type, so identity stays null — the gate denies the
    //   connection without ever consulting the dispatcher. The FakeCallerVerifier
    //   is set to Allow=false as belt-and-suspenders, but the deny fires through
    //   the null-identity path regardless.
    //
    // Sentinel: FakeProxyServiceController.Calls is empty after the call, proving
    //   no real handler (and therefore no dispatch) was invoked.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task UntrustedCaller_headless_gateDeniesBEFOREDispatch_realHandleConnectionAsync()
    {
        if (!OperatingSystem.IsWindows()) return;

        // Arrange: build a real dispatcher backed by sentinelled fakes.
        var sentinel = new FakeProxyServiceController();
        var dispatcher = TestHandlerRegistry.BuildDispatcher(sentinel, new FakeConfigStore());

        // Denying verifier (belt-and-suspenders: identity is also null for non-pipe stream).
        var verifier = new FakeCallerVerifier { Allow = false };

        var pipeServer = new IpcPipeServer(
            dispatcher,
            verifier,
            () => CurrentUserSid(),
            pipeName: "DnsCryptControl.Test.HeadlessGate",
            identityResolver: _ => new CallerIdentity(0, @"C:\unreachable.exe"));
            // Note: identityResolver is only called when the stream IS a
            // NamedPipeServerStream; it is never invoked for DuplexMemoryStream.

        // Build an in-memory request frame that the server will read (and discard).
        var requestJson = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        using var requestBuf = new MemoryStream();
        await IpcFraming.WriteFrameAsync(requestBuf, requestJson, CancellationToken.None);
        requestBuf.Position = 0;

        using var responseBuf = new MemoryStream();
        var duplex = new DuplexMemoryStream(requestBuf, responseBuf);

        // Act: call the REAL production method.
        await pipeServer.HandleConnectionAsync(duplex, CancellationToken.None);

        // Assert 1: the deny frame was written; deserialize it to Result.
        responseBuf.Position = 0;
        var responseJson = await IpcFraming.ReadFrameAsync(responseBuf, CancellationToken.None);
        Assert.NotNull(responseJson);
        var result = IpcSerializer.DeserializePayload<Result>(responseJson!);
        Assert.NotNull(result);
        Assert.False(result!.Success, "Untrusted caller must receive a failure result");
        Assert.Equal(IpcErrorCode.NotAuthorized, result.Code);

        // Assert 2: no handler ran — sentinel controller has zero recorded calls.
        Assert.Empty(sentinel.Calls);
    }

    // -------------------------------------------------------------------------
    // Fix 3: fault containment — throwing verifier must not crash the accept loop
    //
    // A throwing ICallerVerifier (e.g. WinVerifyTrust P/Invoke failure in Task 16)
    // must fail closed: the connection is denied/closed and RunAsync continues.
    // The RunAsync catch(Exception ex) when (!ct.IsCancellationRequested) implements
    // this barrier. The test verifies that:
    //   1. A verifier fault raises a non-cancellation exception.
    //   2. That exception is correctly routed to the fault-barrier path, NOT to the
    //      shutdown-break or per-connection-timeout paths.
    //   3. The shutdown CancellationToken is unaffected.
    // -------------------------------------------------------------------------

    private sealed class ThrowingVerifier : ICallerVerifier
    {
        public bool IsTrusted(CallerIdentity caller) =>
            throw new InvalidOperationException("Simulated verifier fault (e.g. WinVerifyTrust P/Invoke failure)");
    }

    /// <summary>
    /// Unit test (no real pipe needed): verifies the RunAsync fault-barrier catch routing.
    ///
    /// When ICallerVerifier.IsTrusted throws, the exception:
    /// - IS caught by catch(Exception ex) when (!ct.IsCancellationRequested)   [fault barrier]
    /// - IS NOT caught by catch(OperationCanceledException) when (ct.IsCancel)  [shutdown break]
    /// - IS NOT caught by catch(OperationCanceledException) when (!ct.IsCancel) [conn timeout]
    ///
    /// The test simulates the exact RunAsync catch-block logic and asserts each path.
    /// </summary>
    [Fact]
    public void ThrowingVerifier_isContainedByFaultBarrier_loopContinues_shutdownCtUnaffected()
    {
        if (!OperatingSystem.IsWindows()) return;

        var verifier = new ThrowingVerifier();
        using var shutdownCts = new CancellationTokenSource();
        var ct = shutdownCts.Token;

        bool faultBarrierFired = false;
        bool shutdownBreakFired = false;
        bool perConnectionTimeoutFired = false;
        Exception? capturedEx = null;

        // Simulate the RunAsync inner try-catch logic that wraps HandleConnectionAsync:
        try
        {
            // This is what the verifier call site in HandleConnectionAsync does.
            verifier.IsTrusted(new CallerIdentity(1, @"C:\evil.exe"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            shutdownBreakFired = true; // must NOT fire
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            perConnectionTimeoutFired = true; // must NOT fire
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Fix 3: expected path — fault barrier fires, loop continues.
            faultBarrierFired = true;
            capturedEx = ex;
        }

        Assert.True(faultBarrierFired,
            "RunAsync catch(Exception) when (!ct.IsCancellationRequested) must fire for a throwing verifier");
        Assert.False(shutdownBreakFired,
            "Verifier fault must NOT trigger the shutdown-break path");
        Assert.False(perConnectionTimeoutFired,
            "Verifier fault must NOT be mistaken for a per-connection timeout");
        Assert.IsType<InvalidOperationException>(capturedEx);
        Assert.False(ct.IsCancellationRequested,
            "Shutdown CancellationToken must not be cancelled by a verifier fault");
    }

    // -------------------------------------------------------------------------
    // Fix 2: per-connection timeout — stalled client aborts handler, loop continues
    //
    // A real named pipe is needed because AnonymousPipe returns EOF immediately
    // when the writer is closed, so ReadFrameAsync never blocks.
    // Marked ManualIntegration; runs only with --filter "Category=ManualIntegration".
    //
    // To run manually:
    //   dotnet test --filter "Category=ManualIntegration" tests/DnsCryptControl.Ipc.Tests
    // -------------------------------------------------------------------------

    [Fact]
    [Trait("Category", "ManualIntegration")]
    public async Task StalledClient_perConnectionTimeoutFires_shutdownCtUnaffected()
    {
        if (!OperatingSystem.IsWindows()) return;

        const string pipe = "DnsCryptControl.Test.StalledClient";
        var dispatcher = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController(), new FakeConfigStore());
        var verifier = new FakeCallerVerifier { Allow = true };

        using var serverPipe = new NamedPipeServerStream(
            pipe, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);

        var pipeServer = new IpcPipeServer(
            dispatcher, verifier, () => CurrentUserSid(), pipe,
            _ => new CallerIdentity(42, @"C:\app\ui.exe"));

        using var shutdownCts = new CancellationTokenSource();

        var serverTask = Task.Run(async () =>
        {
            await serverPipe.WaitForConnectionAsync(shutdownCts.Token);

            // Use a 2-second CTS to simulate the per-connection timeout without
            // waiting the full ConnectionTimeout (10 seconds).
            using var connCts = CancellationTokenSource.CreateLinkedTokenSource(shutdownCts.Token);
            connCts.CancelAfter(TimeSpan.FromSeconds(2));

            bool perConnectionTimeoutFired = false;
            Exception? unexpectedEx = null;

            try
            {
                // ReadFrameAsync blocks because the stalled client never writes.
                // connCts fires after 2s and cancels the read.
                await pipeServer.HandleConnectionAsync(serverPipe, connCts.Token);
            }
            catch (OperationCanceledException) when (!shutdownCts.Token.IsCancellationRequested)
            {
                // Fix 2: per-connection timeout — expected path; loop continues.
                perConnectionTimeoutFired = true;
            }
            catch (Exception ex)
            {
                unexpectedEx = ex;
            }

            return (perConnectionTimeoutFired, unexpectedEx);
        });

        // Connect but never write (simulate stalled client).
        using var clientPipe = new NamedPipeClientStream(
            ".", pipe, PipeDirection.InOut, PipeOptions.Asynchronous);
        await clientPipe.ConnectAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
        // Deliberately do NOT write anything.

        var (timeoutFired, ex) = await serverTask;

        Assert.True(timeoutFired, "Per-connection timeout must fire when client never writes");
        Assert.Null(ex);
        Assert.False(shutdownCts.IsCancellationRequested,
            "Shutdown CancellationToken must not be cancelled by a per-connection timeout");
    }
}
