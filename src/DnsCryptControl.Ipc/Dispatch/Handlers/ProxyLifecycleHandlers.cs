using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>Shared base for the five proxy-lifecycle handlers. Each runs one
/// IProxyServiceController operation, then reports the resulting service state.</summary>
public abstract class ProxyLifecycleHandlerBase : ICommandHandler
{
    protected ProxyLifecycleHandlerBase(IProxyServiceController proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        Proxy = proxy;
    }

    protected IProxyServiceController Proxy { get; }

    public abstract IpcCommandType Command { get; }

    protected abstract PlatformResult Execute();

    public string Handle(IpcRequest request)
    {
        var op = Execute();
        if (!op.Success)
            return IpcSerializer.SerializePayload(
                Result<ServiceLifecycleResponse>.Fail(PlatformResultMapping.ToIpc(op.Error), op.Message ?? "operation failed"));

        var state = Proxy.GetState();
        var stateName = state.Success ? state.Value.ToString() : ProxyServiceState.Unknown.ToString();
        return IpcSerializer.SerializePayload(
            Result<ServiceLifecycleResponse>.Ok(new ServiceLifecycleResponse(stateName)));
    }
}

public sealed class StartProxyHandler : ProxyLifecycleHandlerBase
{
    public StartProxyHandler(IProxyServiceController proxy) : base(proxy) { }
    public override IpcCommandType Command => IpcCommandType.StartProxy;
    protected override PlatformResult Execute() => Proxy.Start();
}

public sealed class StopProxyHandler : ProxyLifecycleHandlerBase
{
    public StopProxyHandler(IProxyServiceController proxy) : base(proxy) { }
    public override IpcCommandType Command => IpcCommandType.StopProxy;
    protected override PlatformResult Execute() => Proxy.Stop();
}

public sealed class RestartProxyHandler : ProxyLifecycleHandlerBase
{
    public RestartProxyHandler(IProxyServiceController proxy) : base(proxy) { }
    public override IpcCommandType Command => IpcCommandType.RestartProxy;
    protected override PlatformResult Execute() => Proxy.Restart();
}

public sealed class InstallProxyServiceHandler : ProxyLifecycleHandlerBase
{
    public InstallProxyServiceHandler(IProxyServiceController proxy) : base(proxy) { }
    public override IpcCommandType Command => IpcCommandType.InstallProxyService;
    protected override PlatformResult Execute() => Proxy.Install();
}

public sealed class UninstallProxyServiceHandler : ProxyLifecycleHandlerBase
{
    public UninstallProxyServiceHandler(IProxyServiceController proxy) : base(proxy) { }
    public override IpcCommandType Command => IpcCommandType.UninstallProxyService;
    protected override PlatformResult Execute() => Proxy.Uninstall();
}
