using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace DnsCryptControl.Ipc.Transport;

/// <summary>
/// UI-side IPC client. Connects to the helper's named pipe with
/// TokenImpersonationLevel.Identification (so a hostile pipe-squatting server cannot
/// impersonate the interactive user — spec §5.2), writes one request frame, and reads one
/// response frame. All failures fail closed (return null). Before any request is sent, the
/// client verifies the connected pipe's server-side owner SID is LocalSystem (the F11 check
/// below); client-side verification of the server IMAGE signature is deferred (never
/// implemented). This transport also passes the restricted impersonation level.
///
/// IpcPipeServer is one-shot-per-connection (RunAsync accepts a client, handles exactly one
/// request, then Disconnect()s and re-arms a fresh pipe instance). Consequently every
/// SendAsync here opens a FRESH connection — there is no cross-call stream reuse. Reusing a
/// stream across calls previously caused every other UI status poll to hit a server-closed
/// pipe (stale IsConnected == true) and fail closed, producing a flickering
/// "helper unavailable" banner. The F11 owner=SYSTEM check therefore also runs on every call
/// (once per fresh connection), which is correct: each connection is a new handle to verify.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpcPipeClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly Func<SafePipeHandle, bool> _ownerIsSystem;

    public IpcPipeClient() : this(PipeNames.Helper) { }

    public IpcPipeClient(string pipeName) : this(pipeName, null) { }

    /// <summary>
    /// F11: <paramref name="ownerIsSystem"/> verifies the connected pipe's server-side
    /// owner is LocalSystem before any request is sent. Defaults to
    /// <see cref="PipeServerOwner.IsServerLocalSystem"/>; overridable for testing.
    /// </summary>
    public IpcPipeClient(string pipeName, Func<SafePipeHandle, bool>? ownerIsSystem)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        _pipeName = pipeName;
        _ownerIsSystem = ownerIsSystem ?? PipeServerOwner.IsServerLocalSystem;
    }

    public async Task<string?> SendAsync(string requestJson, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(requestJson);

        // One-shot server => one-shot connection: every call gets its own fresh stream,
        // used exactly once, and disposed before returning. Nothing is ever cached/reused
        // across calls, so a server-side Disconnect() between calls can never leave this
        // client holding a stale "connected" stream.
        NamedPipeClientStream? stream = null;
        try
        {
            stream = new NamedPipeClientStream(
                serverName: ".",
                pipeName: _pipeName,
                direction: PipeDirection.InOut,
                options: PipeOptions.Asynchronous,
                impersonationLevel: TokenImpersonationLevel.Identification,
                inheritability: HandleInheritability.None);

            // One linked+timed token bounds the WHOLE call (connect + write + read) by `timeout`,
            // not just the connect: a server that accepts the connection and the request frame but
            // never writes a response must not hang the client past `timeout`. Still honours the
            // caller's ct via the linked source.
            using var callCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            callCts.CancelAfter(timeout);
            await stream.ConnectAsync(callCts.Token).ConfigureAwait(false);

            // F11: verify THIS connection's server-side owner is SYSTEM before sending
            // anything. Runs on every fresh connection (i.e. every call), since each
            // connection is a distinct handle that could in principle hit a different
            // (impostor) server instance.
            if (!_ownerIsSystem(stream.SafePipeHandle))
            {
                return null; // server is not SYSTEM: possible impostor pipe — fail closed (F11)
            }

            try
            {
                await IpcFraming.WriteFrameAsync(stream, requestJson, callCts.Token).ConfigureAwait(false);
            }
            catch (ArgumentException)
            {
                // Scoped to the frame-write call ONLY (never broadened to Exception): the
                // single ArgumentException source here is IpcFraming.WriteFrameAsync's size
                // guard rejecting a frame > IpcSerializer.MaxBytes — directly reachable from
                // a large pasted config (P5b-E7). Fail closed like every other transport
                // failure instead of leaking the throw to the caller. The null-guard on
                // requestJson at method entry is outside this scope and still throws.
                return null; // request frame over the 1 MiB cap: fail closed
            }
            return await IpcFraming.ReadFrameAsync(stream, callCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null; // connect/read timed out: fail closed
        }
        catch (IOException)
        {
            return null; // pipe broken: fail closed
        }
        catch (UnauthorizedAccessException)
        {
            return null; // ACL denied us: fail closed
        }
        catch (ObjectDisposedException)
        {
            return null; // concurrent dispose during in-flight send: fail closed
        }
        finally
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask; // nothing to dispose: SendAsync owns its stream per call
}
