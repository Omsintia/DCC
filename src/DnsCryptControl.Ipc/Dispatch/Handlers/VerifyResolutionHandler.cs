using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>VerifyResolution (protocol v4, FIX #1): runs the bounded real-name resolve check that
/// proves the proxy's configured upstream route actually resolves — the thing the RunDiagnostics
/// self-check structurally cannot (its undelegated .test name is answered locally). Takes no
/// payload and never mutates state. A DEAD ROUTE is a SUCCESS result whose value says
/// Resolved=false; only a probe that could not run maps to a failed <see cref="Result{T}"/> via
/// PlatformResultMapping (mirrors <see cref="RunDiagnosticsHandler"/>). The handler never throws
/// for the input it is given.</summary>
public sealed class VerifyResolutionHandler : ICommandHandler
{
    private readonly IDiagnosticsProbe _probe;

    public VerifyResolutionHandler(IDiagnosticsProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        _probe = probe;
    }

    public IpcCommandType Command => IpcCommandType.VerifyResolution;

    public string Handle(IpcRequest request)
    {
        var probe = _probe.VerifyUpstreamResolution();
        if (!probe.Success || probe.Value is null)
        {
            return IpcSerializer.SerializePayload(
                Result<ResolveVerification>.Fail(
                    PlatformResultMapping.ToIpc(probe.Error),
                    probe.Message ?? "resolve verification failed"));
        }

        return IpcSerializer.SerializePayload(Result<ResolveVerification>.Ok(probe.Value));
    }
}
