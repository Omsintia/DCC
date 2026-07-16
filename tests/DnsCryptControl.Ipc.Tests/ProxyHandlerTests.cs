using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Tests;

public class ProxyHandlerTests
{
    private sealed class FakeKillSwitch : IFirewallKillSwitch
    {
        public bool Active { get; set; }
        public PlatformResult SetKillSwitch(bool enable) =>
            PlatformResult.Ok();
        public bool IsKillSwitchActive() => Active;
    }

    private sealed class FakeLeak : ILeakMitigationPolicy
    {
        public bool Enabled { get; set; }
        public PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable) =>
            PlatformResult<RebootAdvisory>.Ok(RebootAdvisory.None);
        public bool AreLeakMitigationsEnabled() => Enabled;
    }

    [Fact]
    public void Status_reportsRunning_whenProxyRunning()
    {
        var proxy = new FakeProxyServiceController { State = ProxyServiceState.Running };
        var handler = new StatusHandler(proxy, new FakeKillSwitch(), new FakeLeak());
        var json = handler.Handle(new IpcRequest(IpcCommandType.GetStatus, null));
        var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(result.Value!.ProxyRunning);
        Assert.False(result.Value.KillSwitchEnabled);          // fakes default to false
        Assert.False(result.Value.LeakMitigationsEnabled);     // fakes default to false
    }

    [Fact]
    public void Status_failsClosed_whenStateQueryFails()
    {
        var proxy = new FakeProxyServiceController { FailGetState = true };
        var json = new StatusHandler(proxy, new FakeKillSwitch(), new FakeLeak())
            .Handle(new IpcRequest(IpcCommandType.GetStatus, null));
        var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(json);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
    }

    [Fact]
    public void Status_populatesKillSwitchAndLeakMitigationState()
    {
        var proxy = new FakeProxyServiceController { State = ProxyServiceState.Running };
        var killSwitch = new FakeKillSwitch { Active = true };
        var leak = new FakeLeak { Enabled = true };
        var handler = new StatusHandler(proxy, killSwitch, leak);
        var json = handler.Handle(new IpcRequest(IpcCommandType.GetStatus, null));
        var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(result.Value!.ProxyRunning);
        Assert.True(result.Value.KillSwitchEnabled);
        Assert.True(result.Value.LeakMitigationsEnabled);
        Assert.Null(result.Value.ActiveResolver);   // stays null until Phase 5
    }

    [Fact]
    public void Status_reports_protocol_version_and_helper_build()
    {
        var proxy = new FakeProxyServiceController { State = ProxyServiceState.Running };
        var handler = new StatusHandler(proxy, new FakeKillSwitch(), new FakeLeak());
        var result = IpcSerializer.DeserializePayload<Result<StatusResponse>>(
            handler.Handle(new IpcRequest(IpcCommandType.GetStatus, null)));

        Assert.NotNull(result);
        Assert.Equal(IpcProtocol.Version, result!.Value!.ProtocolVersion);
        Assert.False(string.IsNullOrWhiteSpace(result.Value.HelperBuild));
    }

    [Fact]
    public void Start_callsStart_andReturnsRunningState()
    {
        var proxy = new FakeProxyServiceController { State = ProxyServiceState.Stopped };
        var json = new StartProxyHandler(proxy).Handle(new IpcRequest(IpcCommandType.StartProxy, null));
        var result = IpcSerializer.DeserializePayload<Result<ServiceLifecycleResponse>>(json);

        Assert.Contains("Start", proxy.Calls);
        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal("Running", result.Value!.State);
    }

    [Fact]
    public void Start_mapsPlatformFailure_toIpcErrorCode()
    {
        var proxy = new FakeProxyServiceController { FailWith = PlatformErrorKind.NotFound };
        var json = new StartProxyHandler(proxy).Handle(new IpcRequest(IpcCommandType.StartProxy, null));
        var result = IpcSerializer.DeserializePayload<Result<ServiceLifecycleResponse>>(json);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.NotFound, result.Code);
    }

    [Theory]
    [InlineData(typeof(StopProxyHandler), "Stop")]
    [InlineData(typeof(RestartProxyHandler), "Restart")]
    [InlineData(typeof(InstallProxyServiceHandler), "Install")]
    [InlineData(typeof(UninstallProxyServiceHandler), "Uninstall")]
    public void LifecycleHandlers_invokeTheirOperation(System.Type handlerType, string expectedCall)
    {
        var proxy = new FakeProxyServiceController();
        var handler = (DnsCryptControl.Ipc.Dispatch.ICommandHandler)System.Activator.CreateInstance(handlerType, proxy)!;
        var json = handler.Handle(new IpcRequest(handler.Command, null));
        var result = IpcSerializer.DeserializePayload<Result<ServiceLifecycleResponse>>(json);
        Assert.Contains(expectedCall, proxy.Calls);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }
}
