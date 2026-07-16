using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// Serves the FlushDnsCache verb: flushes the Windows DNS resolver cache (the same benign
/// maintenance action as Clear-DnsClientCache / "ipconfig /flushdns") via IDnsCacheFlusher and
/// reports the outcome as a non-generic Result. Never throws for input it can reject.
/// </summary>
public sealed class FlushDnsCacheHandler : ICommandHandler
{
    private readonly IDnsCacheFlusher _flusher;

    public FlushDnsCacheHandler(IDnsCacheFlusher flusher)
    {
        ArgumentNullException.ThrowIfNull(flusher);
        _flusher = flusher;
    }

    public IpcCommandType Command => IpcCommandType.FlushDnsCache;

    public string Handle(IpcRequest request)
    {
        var op = _flusher.Flush();
        var result = op.Success
            ? Result.Ok()
            : Result.Fail(PlatformResultMapping.ToIpc(op.Error), op.Message ?? "DNS cache flush failed");
        return IpcSerializer.SerializePayload(result);
    }
}
