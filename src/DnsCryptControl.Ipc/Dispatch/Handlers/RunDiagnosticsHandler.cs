using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>RunDiagnostics: runs the read-only health + DNS-leak self-check and returns the snapshot.
/// Takes no payload (the probe needs no input) and never mutates state. A probe failure maps to the
/// IPC error code via PlatformResultMapping; the handler never throws for the input it is given.</summary>
public sealed class RunDiagnosticsHandler : ICommandHandler
{
    private readonly IDiagnosticsProbe _probe;

    public RunDiagnosticsHandler(IDiagnosticsProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        _probe = probe;
    }

    public IpcCommandType Command => IpcCommandType.RunDiagnostics;

    public string Handle(IpcRequest request)
    {
        var probe = _probe.Run();
        if (!probe.Success || probe.Value is null)
        {
            return IpcSerializer.SerializePayload(
                Result<DiagnosticsSnapshot>.Fail(
                    PlatformResultMapping.ToIpc(probe.Error),
                    probe.Message ?? "diagnostics probe failed"));
        }

        return IpcSerializer.SerializePayload(Result<DiagnosticsSnapshot>.Ok(probe.Value));
    }
}
