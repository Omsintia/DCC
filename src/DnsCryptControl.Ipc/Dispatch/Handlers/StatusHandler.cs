using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>GetStatus: reports whether the proxy service is running plus the live kill-switch and
/// leak-mitigation state from the OPSEC subsystems. ActiveResolver is a reserved wire slot that is
/// always null: the UI derives the active resolver from the on-disk config via
/// IActiveResolverReader, not from the helper.</summary>
public sealed class StatusHandler : ICommandHandler
{
    private readonly IProxyServiceController _proxy;
    private readonly IFirewallKillSwitch _killSwitch;
    private readonly ILeakMitigationPolicy _leak;

    public StatusHandler(IProxyServiceController proxy, IFirewallKillSwitch killSwitch, ILeakMitigationPolicy leak)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(killSwitch);
        ArgumentNullException.ThrowIfNull(leak);
        _proxy = proxy;
        _killSwitch = killSwitch;
        _leak = leak;
    }

    public IpcCommandType Command => IpcCommandType.GetStatus;

    public string Handle(IpcRequest request)
    {
        var state = _proxy.GetState();
        if (!state.Success)
            return IpcSerializer.SerializePayload(
                Result<StatusResponse>.Fail(PlatformResultMapping.ToIpc(state.Error), state.Message ?? "status query failed"));

        var running = state.Value == ProxyServiceState.Running;
        var response = new StatusResponse(
            ProxyRunning: running,
            ActiveResolver: null,   // reserved wire slot - the UI derives it from the config (IActiveResolverReader)
            KillSwitchEnabled: _killSwitch.IsKillSwitchActive(),
            LeakMitigationsEnabled: _leak.AreLeakMitigationsEnabled(),
            ProtocolVersion: IpcProtocol.Version,
            HelperBuild: typeof(StatusHandler).Assembly.GetName().Version?.ToString() ?? "0.0.0");
        return IpcSerializer.SerializePayload(Result<StatusResponse>.Ok(response));
    }
}
