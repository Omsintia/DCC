using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// EnableProtection: the atomic, helper-owned master-toggle-on operation (BE-8). Deserializes
/// the required <see cref="EnableProtectionPayload"/> and delegates the entire enable sequence
/// (proxy start, loopback DNS, leak mitigations, optional kill switch) to the injected
/// <see cref="IProtectionOrchestrator"/>, which owns the leak-safe invariants. Rejects a
/// missing/invalid payload without ever calling the orchestrator (the handler never throws for
/// input it can reject).
/// </summary>
public sealed class EnableProtectionHandler : ICommandHandler
{
    private readonly IProtectionOrchestrator _orchestrator;

    public EnableProtectionHandler(IProtectionOrchestrator orchestrator)
    {
        ArgumentNullException.ThrowIfNull(orchestrator);
        _orchestrator = orchestrator;
    }

    public IpcCommandType Command => IpcCommandType.EnableProtection;

    public string Handle(IpcRequest request)
    {
        if (request.PayloadJson is null
            || IpcSerializer.DeserializePayload<EnableProtectionPayload>(request.PayloadJson) is not { } payload)
        {
            return IpcSerializer.SerializePayload(
                Result<ProtectionResponse>.Fail(
                    IpcErrorCode.ValidationFailed, "EnableProtection requires a WithKillSwitch payload."));
        }

        var r = _orchestrator.EnableProtection(payload.WithKillSwitch);
        if (!r.Success)
            return IpcSerializer.SerializePayload(
                Result<ProtectionResponse>.Fail(
                    PlatformResultMapping.ToIpc(r.Error), r.Message ?? "enable protection failed"));

        var o = r.Value!;
        return IpcSerializer.SerializePayload(Result<ProtectionResponse>.Ok(
            new ProtectionResponse(
                ProtectionEnabled: true,
                o.KillSwitchEnabled,
                o.LeakMitigationsEnabled,
                o.RebootRecommended,
                o.KillSwitchAdvisory)));
    }
}
