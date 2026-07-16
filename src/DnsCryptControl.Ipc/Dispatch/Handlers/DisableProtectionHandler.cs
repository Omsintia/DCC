using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// DisableProtection: the atomic, helper-owned master-toggle-off operation (BE-8). Takes no
/// payload — delegates the entire teardown sequence (kill switch, leak mitigations, DNS restore,
/// proxy stop, clear intent) to the injected <see cref="IProtectionOrchestrator"/>.
/// </summary>
public sealed class DisableProtectionHandler : ICommandHandler
{
    private readonly IProtectionOrchestrator _orchestrator;

    public DisableProtectionHandler(IProtectionOrchestrator orchestrator)
    {
        ArgumentNullException.ThrowIfNull(orchestrator);
        _orchestrator = orchestrator;
    }

    public IpcCommandType Command => IpcCommandType.DisableProtection;

    public string Handle(IpcRequest request)
    {
        var r = _orchestrator.DisableProtection();
        if (!r.Success)
            return IpcSerializer.SerializePayload(
                Result<ProtectionResponse>.Fail(
                    PlatformResultMapping.ToIpc(r.Error), r.Message ?? "disable protection failed"));

        return IpcSerializer.SerializePayload(Result<ProtectionResponse>.Ok(
            new ProtectionResponse(
                ProtectionEnabled: false,
                KillSwitchEnabled: false,
                LeakMitigationsEnabled: false,
                RebootRecommended: false,
                KillSwitchAdvisory: null)));
    }
}
