using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class ProtectionHandlerTests
{
    private sealed class FakeProtectionOrchestrator : IProtectionOrchestrator
    {
        public bool? LastWithKillSwitch { get; private set; }
        public int EnableCallCount { get; private set; }
        public int DisableCallCount { get; private set; }
        public PlatformResult<ProtectionOutcome> EnableResult { get; set; } =
            PlatformResult<ProtectionOutcome>.Ok(new ProtectionOutcome(false, false, false, null));
        public PlatformResult DisableResult { get; set; } = PlatformResult.Ok();

        public PlatformResult<ProtectionOutcome> EnableProtection(bool withKillSwitch)
        {
            EnableCallCount++;
            LastWithKillSwitch = withKillSwitch;
            return EnableResult;
        }

        public PlatformResult DisableProtection()
        {
            DisableCallCount++;
            return DisableResult;
        }
    }

    [Fact]
    public void Enable_withPayload_mapsOutcomeToOk()
    {
        var orchestrator = new FakeProtectionOrchestrator
        {
            EnableResult = PlatformResult<ProtectionOutcome>.Ok(
                new ProtectionOutcome(
                    KillSwitchEnabled: true,
                    LeakMitigationsEnabled: true,
                    RebootRecommended: true,
                    KillSwitchAdvisory: "advisory text")),
        };
        var handler = new EnableProtectionHandler(orchestrator);
        var req = new IpcRequest(
            IpcCommandType.EnableProtection,
            IpcSerializer.SerializePayload(new EnableProtectionPayload(WithKillSwitch: true)));

        var json = handler.Handle(req);
        var result = IpcSerializer.DeserializePayload<Result<ProtectionResponse>>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.NotNull(result.Value);
        Assert.True(result.Value!.ProtectionEnabled);
        Assert.True(result.Value.KillSwitchEnabled);
        Assert.True(result.Value.LeakMitigationsEnabled);
        Assert.True(result.Value.RebootRecommended);
        Assert.Equal("advisory text", result.Value.KillSwitchAdvisory);
        Assert.Equal(true, orchestrator.LastWithKillSwitch);
        Assert.Equal(1, orchestrator.EnableCallCount);
    }

    [Fact]
    public void Enable_missingPayload_returnsValidationFailed_andNeverCallsOrchestrator()
    {
        var orchestrator = new FakeProtectionOrchestrator();
        var handler = new EnableProtectionHandler(orchestrator);

        var json = handler.Handle(new IpcRequest(IpcCommandType.EnableProtection, null));
        var result = IpcSerializer.DeserializePayload<Result<ProtectionResponse>>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Equal(0, orchestrator.EnableCallCount);
    }

    [Fact]
    public void Enable_orchestratorFailure_mapsViaPlatformResultMapping()
    {
        var orchestrator = new FakeProtectionOrchestrator
        {
            EnableResult = PlatformResult<ProtectionOutcome>.Fail(
                PlatformErrorKind.OperationFailed, "proxy start failed"),
        };
        var handler = new EnableProtectionHandler(orchestrator);
        var req = new IpcRequest(
            IpcCommandType.EnableProtection,
            IpcSerializer.SerializePayload(new EnableProtectionPayload(WithKillSwitch: false)));

        var json = handler.Handle(req);
        var result = IpcSerializer.DeserializePayload<Result<ProtectionResponse>>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("proxy start failed", result.Message);
    }

    [Fact]
    public void Disable_noPayload_mapsResult()
    {
        var orchestrator = new FakeProtectionOrchestrator { DisableResult = PlatformResult.Ok() };
        var handler = new DisableProtectionHandler(orchestrator);

        var json = handler.Handle(new IpcRequest(IpcCommandType.DisableProtection, null));
        var result = IpcSerializer.DeserializePayload<Result<ProtectionResponse>>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.NotNull(result.Value);
        Assert.False(result.Value!.ProtectionEnabled);
        Assert.False(result.Value.KillSwitchEnabled);
        Assert.False(result.Value.LeakMitigationsEnabled);
        Assert.False(result.Value.RebootRecommended);
        Assert.Null(result.Value.KillSwitchAdvisory);
        Assert.Equal(1, orchestrator.DisableCallCount);
    }

    [Fact]
    public void Disable_orchestratorFailure_mapsViaPlatformResultMapping()
    {
        var orchestrator = new FakeProtectionOrchestrator
        {
            DisableResult = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "teardown failed"),
        };
        var handler = new DisableProtectionHandler(orchestrator);

        var json = handler.Handle(new IpcRequest(IpcCommandType.DisableProtection, null));
        var result = IpcSerializer.DeserializePayload<Result<ProtectionResponse>>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("teardown failed", result.Message);
    }

    [Fact]
    public void EnableHandler_neverThrows_onBadInput()
    {
        var orchestrator = new FakeProtectionOrchestrator();
        var handler = new EnableProtectionHandler(orchestrator);
        var ex = Record.Exception(() => handler.Handle(new IpcRequest(IpcCommandType.EnableProtection, "not-json")));
        Assert.Null(ex);
        Assert.Equal(0, orchestrator.EnableCallCount);
    }

    [Fact]
    public void DisableHandler_neverThrows_onBadInput()
    {
        var orchestrator = new FakeProtectionOrchestrator();
        var handler = new DisableProtectionHandler(orchestrator);
        var ex = Record.Exception(() => handler.Handle(new IpcRequest(IpcCommandType.DisableProtection, "not-json")));
        Assert.Null(ex);
    }

    [Fact]
    public void Ctor_rejectsNullOrchestrator()
    {
        Assert.Throws<System.ArgumentNullException>(() => new EnableProtectionHandler(null!));
        Assert.Throws<System.ArgumentNullException>(() => new DisableProtectionHandler(null!));
    }
}
