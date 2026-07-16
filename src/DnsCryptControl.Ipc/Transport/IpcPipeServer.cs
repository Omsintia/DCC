using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Ipc.Security;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.Ipc.Transport;

/// <summary>
/// Helper-side pipe server. For each connection: creates an ACL'd pipe instance, accepts a
/// client, resolves and verifies the caller (deny =&gt; NotAuthorized frame, disconnect),
/// then reads one request frame, dispatches it, and writes the response frame. The caller
/// identity is resolved through an injected delegate so the accept loop stays testable and
/// the GetNamedPipeClientProcessId P/Invoke lives in the Service project.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpcPipeServer : IAsyncDisposable
{
    /// <summary>
    /// Maximum time a connected client has to send its first request frame.
    /// A client that never writes blocks the serial accept loop indefinitely without this guard.
    /// </summary>
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(10);

    /// <summary>How often the idle accept loop re-arms to re-resolve the interactive user and
    /// rebuild the pipe DACL — so a login or session change after the helper started (e.g. an
    /// auto-start at boot before anyone logged in) is picked up WITHOUT a manual service restart.
    /// A real connection returns sooner; this only bounds the idle wait.</summary>
    private static readonly TimeSpan DaclRefreshInterval = TimeSpan.FromSeconds(2);

    /// <summary>Backoff before re-arming after a transient re-create/resolve fault on a NON-first
    /// iteration (e.g. the just-disposed pipe instance is still closing, or a transient
    /// WTSEnumerateSessions error), so a benign self-race re-arms instead of hot-looping or faulting
    /// the LocalSystem host.</summary>
    private static readonly TimeSpan ReArmBackoff = TimeSpan.FromMilliseconds(200);

    private readonly CommandDispatcher _dispatcher;
    private readonly ICallerVerifier _verifier;
    private readonly Func<SecurityIdentifier?> _resolveInteractiveUser;
    private readonly string _pipeName;
    private readonly Func<SafePipeHandle, CallerIdentity?> _identityResolver;

    /// <param name="resolveInteractiveUser">Called on EVERY accept-loop iteration to resolve the
    /// currently-active interactive user's SID (or null if none is active yet). The pipe DACL is
    /// rebuilt from its result each iteration, so a user that logs in after the helper started is
    /// granted access without a restart. Never expected to throw; a null result yields a
    /// SYSTEM-only pipe (fail closed).</param>
    public IpcPipeServer(
        CommandDispatcher dispatcher,
        ICallerVerifier verifier,
        Func<SecurityIdentifier?> resolveInteractiveUser,
        string pipeName,
        Func<SafePipeHandle, CallerIdentity?> identityResolver)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(resolveInteractiveUser);
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentNullException.ThrowIfNull(identityResolver);

        _dispatcher = dispatcher;
        _verifier = verifier;
        _resolveInteractiveUser = resolveInteractiveUser;
        _pipeName = pipeName;
        _identityResolver = identityResolver;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var firstIteration = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                // Re-resolve the ACTIVE interactive user each iteration and rebuild the DACL. This is
                // the "Phase 5 retry logic": if the helper auto-started at boot before anyone logged
                // in, the DACL is SYSTEM-only, but once a user logs in (or an RDP/Enhanced session
                // becomes active) the next iteration grants them ReadWrite — no manual service
                // restart. A null user keeps the pipe SYSTEM-only (fail closed; never a broad SID).
                //
                // resolve + BuildDacl + Create are INSIDE the try so a transient WTS/resolve error,
                // or a re-create self-race (our just-disposed instance still closing), re-arms the
                // loop via the non-first-iteration catch below rather than faulting the LocalSystem
                // host. On the FIRST iteration a Create failure is NOT re-armed: PipeOptions.
                // FirstPipeInstance makes it throw only if another process already owns the pipe name
                // (a squatter), and the service must fail loud at startup (anti-squat).
                // maxNumberOfServerInstances = 1 is coherent with FirstPipeInstance (serial loop).
                // TODO(perf): a WTS session-change notification would avoid re-resolving every tick.
                var interactiveUser = _resolveInteractiveUser();
                var dacl = PipeServerSecurity.BuildDacl(interactiveUser);
                server = NamedPipeServerStreamAcl.Create(
                    _pipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                    inBufferSize: 4096,
                    outBufferSize: 4096,
                    pipeSecurity: dacl);
                firstIteration = false;

                // Bound the idle wait so the loop periodically re-arms and re-resolves the
                // interactive user (picking up a login/session change within DaclRefreshInterval).
                // A real connection returns earlier; a timeout just re-iterates to rebuild the DACL.
                using (var idleCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    idleCts.CancelAfter(DaclRefreshInterval);
                    try
                    {
                        await server.WaitForConnectionAsync(idleCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        continue; // idle refresh tick: re-resolve + rebuild the pipe DACL
                    }
                }

                // Fix 2 (per-connection read timeout): create a linked CTS that
                // cancels after ConnectionTimeout, so a stalled client cannot wedge
                // the serial accept loop indefinitely. Pass connCts.Token (not ct)
                // into HandleConnectionAsync so only this connection's reads are aborted.
                //
                // Dispatch hold-time note (bounded availability characteristic):
                // connCts / ConnectionTimeout bounds the async FRAMING reads only (the
                // ReadFrameAsync call before Dispatch). A synchronous privileged Dispatch
                // — e.g. a service lifecycle operation such as Start/Stop — runs entirely
                // inside _dispatcher.Dispatch(...) after the frame has been read, so it
                // is NOT interrupted by connCts cancellation. Such an operation can hold
                // the serial accept loop for up to the controller's own internal timeout
                // (~30 s). This is an accepted bounded availability characteristic of the
                // single-instance serial server design (one client at a time). A Phase 3/5
                // follow-up could make Dispatch async and cancellable to tighten this bound.
                using var connCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connCts.CancelAfter(ConnectionTimeout);

                // Fix 3 (fault containment): any exception from the identity resolver,
                // IsTrusted, framing, or dispatch denies/closes this connection and
                // continues the loop. OperationCanceledException from the shutdown ct
                // still breaks the loop; per-connection timeout (connCts only) continues.
                try
                {
                    await HandleConnectionAsync(server, connCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // Per-connection timeout fired (connCts cancelled, shutdown ct NOT cancelled).
                    // Treat as a dropped/slow client: fall through to finally → continue loop.
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    // Any non-cancellation fault (throwing verifier, framing error, etc.)
                    // is contained here. Swallow and continue (Debug-build trace only:
                    // Debug.WriteLine is compiled out of Release) - one bad connection
                    // must not stop the privileged helper.
                    System.Diagnostics.Debug.WriteLine(
                        $"[IpcPipeServer] Per-connection fault contained (connection denied/closed): {ex}");
                }
            }
            catch (OperationCanceledException)
            {
                break; // shutting down — ct was cancelled
            }
            catch (Exception ex) when (!firstIteration)
            {
                // Transient re-create/resolve fault on a re-arm iteration (IOException/
                // UnauthorizedAccessException because our prior pipe instance is still closing, or a
                // transient WTSEnumerateSessions error). Back off briefly and re-arm rather than
                // faulting the host. (A FIRST-iteration Create failure is NOT caught here — a genuine
                // pipe-name squatter still fails loud at startup.)
                System.Diagnostics.Debug.WriteLine($"[IpcPipeServer] Re-arm fault (retrying): {ex}");
                try
                {
                    await Task.Delay(ReArmBackoff, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break; // shutting down during backoff
                }
            }
            finally
            {
                if (server is not null)
                {
                    if (server.IsConnected) server.Disconnect();
                    server.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// Handles one accepted pipe connection: gates the caller, then reads → dispatches →
    /// writes. Separated from the accept loop so the gate+dispatch logic is unit-testable
    /// over any <see cref="Stream"/>.
    /// </summary>
    internal async Task HandleConnectionAsync(Stream stream, CancellationToken ct)
    {
        // Gate: resolve caller identity and verify trust BEFORE dispatching anything.
        CallerIdentity? identity = null;
        if (stream is NamedPipeServerStream pipeStream)
        {
            identity = _identityResolver(pipeStream.SafePipeHandle);
        }

        if (identity is not { } caller || !_verifier.IsTrusted(caller))
        {
            // Read and discard the client's request first. This allows the client's
            // WriteAsync/FlushAsync to complete before we send the deny frame, preventing
            // a race where Disconnect() is called while the client is still flushing its
            // request (which would cause the client to see a broken-pipe error instead of
            // the deny response). ReadFrameAsync is already hardened (1 MiB cap, fail-closed).
            _ = await IpcFraming.ReadFrameAsync(stream, ct).ConfigureAwait(false);

            var denied = IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.NotAuthorized, "Caller is not a trusted, signed peer."));
            await IpcFraming.WriteFrameAsync(stream, denied, ct).ConfigureAwait(false);
            // No post-write drain on the deny path. A denied (untrusted) caller has no delivery
            // guarantee: if Disconnect() discards its deny frame it just reads EOF, which it already
            // treats as "denied". Draining here would let an untrusted caller that opens the pipe,
            // sends a request, then never reads block the single-instance serial accept loop
            // (WaitForPipeDrain is uncancellable) — an unbounded, pre-gate DoS. So the deny path
            // deliberately does not drain.
            return;
        }

        // Read request, dispatch, write response — only reached for trusted callers.
        var requestJson = await IpcFraming.ReadFrameAsync(stream, ct).ConfigureAwait(false);
        if (requestJson is null)
            return; // malformed/oversized/truncated frame: drop the connection

        var responseJson = _dispatcher.Dispatch(requestJson);

        // Guard: Dispatch is fail-closed and always returns a non-null, non-empty string,
        // but defend against any future regression (Task 9 review flag).
        if (string.IsNullOrEmpty(responseJson))
            return;

        await IpcFraming.WriteFrameAsync(stream, responseJson, ct).ConfigureAwait(false);
        await DrainToClientAsync(stream, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Waits until the trusted client has read the just-written response frame, so the accept
    /// loop's subsequent <see cref="NamedPipeServerStream.Disconnect"/> cannot discard it.
    /// DisconnectNamedPipe drops any bytes the client has not yet consumed; without this drain the
    /// client reads EOF on a thread-scheduling-dependent fraction of otherwise-healthy calls
    /// (observed ~1 in 5 status polls — the "helper unavailable" flicker, and the same drop would
    /// silently fail ~20% of real toggle/restart commands).
    ///
    /// <para><see cref="PipeStream.WaitForPipeDrain"/> is synchronous and takes no cancellation
    /// token, so it runs on the thread pool and the wait is bounded by <paramref name="ct"/> (the
    /// per-connection <c>ConnectionTimeout</c>). This is critical: a trusted client that stops
    /// reading must NOT be able to wedge the single-instance serial accept loop indefinitely. On
    /// timeout we return and let the loop <see cref="NamedPipeServerStream.Disconnect"/> — only
    /// that one already-sent response is then lost, which is strictly better than blocking every
    /// other caller. The pool task swallows the benign "client already closed" faults itself, so it
    /// never faults unobserved.</para>
    /// </summary>
    private static async Task DrainToClientAsync(Stream stream, CancellationToken ct)
    {
        if (stream is not PipeStream pipe) return;

        var drain = Task.Run(() =>
        {
            try { pipe.WaitForPipeDrain(); }
            catch (IOException) { /* client already drained + closed its end: response delivered */ }
            catch (ObjectDisposedException) { /* stream torn down after delivery: benign */ }
            catch (InvalidOperationException) { /* no longer connected: response delivered */ }
            catch (NotSupportedException) { /* platform without drain support: prior behaviour */ }
        }, CancellationToken.None);

        try
        {
            await drain.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Drain exceeded the per-connection timeout (client stopped reading): return and let
            // the accept loop Disconnect. Only this one already-sent response is lost; the loop
            // stays free for every other caller. The pool task self-clears when the pipe is torn down.
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
