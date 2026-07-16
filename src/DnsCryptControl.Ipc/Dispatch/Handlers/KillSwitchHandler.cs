using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// SetKillSwitch: toggles the opt-in Windows Defender Firewall outbound BLOCK rules for plaintext
/// DNS (UDP/53, TCP/53, TCP/853) via <see cref="IFirewallKillSwitch"/>. Reuses the shared
/// SetTogglePayload and returns the non-generic Result. Rejects a missing/invalid payload without
/// touching the subsystem (the handler never throws for input it can reject). Persists intent AFTER
/// a successful subsystem call so the recorded state always matches reality.
/// </summary>
public sealed class KillSwitchHandler : ICommandHandler
{
    private readonly IFirewallKillSwitch _killSwitch;
    private readonly IProtectionStateWriter _protectionWriter;

    public KillSwitchHandler(IFirewallKillSwitch killSwitch, IProtectionStateWriter protectionWriter)
    {
        ArgumentNullException.ThrowIfNull(killSwitch);
        ArgumentNullException.ThrowIfNull(protectionWriter);
        _killSwitch = killSwitch;
        _protectionWriter = protectionWriter;
    }

    public IpcCommandType Command => IpcCommandType.SetKillSwitch;

    public string Handle(IpcRequest request)
    {
        if (request.PayloadJson is null
            || IpcSerializer.DeserializePayload<SetTogglePayload>(request.PayloadJson) is not { } payload)
        {
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.ValidationFailed, "SetKillSwitch requires an Enable payload."));
        }

        var op = _killSwitch.SetKillSwitch(payload.Enable);
        if (!op.Success)
            return IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(op.Error), op.Message ?? "kill-switch operation failed"));

        var intent = _protectionWriter.SetKillSwitchEnabled(payload.Enable);
        return intent.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(intent.Error), intent.Message ?? "record kill-switch intent failed"));
    }
}
