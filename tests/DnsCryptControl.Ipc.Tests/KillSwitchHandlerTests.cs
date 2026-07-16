using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class KillSwitchHandlerTests
{
    private sealed class FakeKillSwitch : IFirewallKillSwitch
    {
        public bool? LastEnable { get; private set; }
        public bool Active { get; set; }
        public PlatformResult NextResult { get; set; } = PlatformResult.Ok();

        public PlatformResult SetKillSwitch(bool enable)
        {
            LastEnable = enable;
            if (NextResult.Success) Active = enable;
            return NextResult;
        }

        public bool IsKillSwitchActive() => Active;
    }

    private static IpcRequest Req(bool enable) =>
        new(IpcCommandType.SetKillSwitch, IpcSerializer.SerializePayload(new SetTogglePayload(enable)));

    [Fact]
    public void Command_isSetKillSwitch()
    {
        Assert.Equal(IpcCommandType.SetKillSwitch, new KillSwitchHandler(new FakeKillSwitch(), new FakeProtectionStateWriter()).Command);
    }

    [Fact]
    public void Enable_callsSetKillSwitchTrue_andReturnsOk()
    {
        var ks = new FakeKillSwitch();
        var writer = new FakeProtectionStateWriter();
        var json = new KillSwitchHandler(ks, writer).Handle(Req(true));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(true, ks.LastEnable);
        Assert.True(ks.Active);
        Assert.Equal(true, writer.LastKillSwitch);
        Assert.Contains(nameof(IProtectionStateWriter.SetKillSwitchEnabled), writer.Calls);
    }

    [Fact]
    public void Disable_callsSetKillSwitchFalse_andReturnsOk()
    {
        var ks = new FakeKillSwitch { Active = true };
        var writer = new FakeProtectionStateWriter();
        var json = new KillSwitchHandler(ks, writer).Handle(Req(false));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.True(result!.Success);
        Assert.Equal(false, ks.LastEnable);
        Assert.False(ks.Active);
        Assert.Equal(false, writer.LastKillSwitch);
    }

    [Fact]
    public void MissingPayload_isRejected_withoutCallingSubsystem()
    {
        var ks = new FakeKillSwitch();
        var writer = new FakeProtectionStateWriter();
        var json = new KillSwitchHandler(ks, writer).Handle(new IpcRequest(IpcCommandType.SetKillSwitch, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Null(ks.LastEnable); // subsystem never invoked on a rejected payload
        Assert.Empty(writer.Calls);  // writer never invoked either
    }

    [Fact]
    public void SubsystemFailure_mapsToOperationFailed()
    {
        var ks = new FakeKillSwitch { NextResult = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "MpsSvc stopped") };
        var writer = new FakeProtectionStateWriter();
        var json = new KillSwitchHandler(ks, writer).Handle(Req(true));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("MpsSvc stopped", result.Message);
        Assert.Empty(writer.Calls); // writer not called when subsystem fails
    }

    [Fact]
    public void Handler_neverThrows_onRejectablePayload()
    {
        var ks = new FakeKillSwitch();
        var ex = Record.Exception(() => new KillSwitchHandler(ks, new FakeProtectionStateWriter()).Handle(new IpcRequest(IpcCommandType.SetKillSwitch, "not-json")));
        Assert.Null(ex);
    }

    /// <summary>
    /// IC-4 guard-rejection path: when the active proxy config still bootstraps on plaintext :53,
    /// SetKillSwitch(true) returns PlatformResult.Fail(InvalidArgument, reason).
    /// PlatformResultMapping maps InvalidArgument → IpcErrorCode.ValidationFailed.
    /// The handler must surface a clear "can't enable, config unsafe" message to the UI.
    /// </summary>
    [Fact]
    public void InvalidArgument_fromSubsystem_mapsToValidationFailed_andPreservesMessage()
    {
        const string reason = "Active proxy config bootstraps on plaintext :53 — kill-switch unsafe";
        var ks = new FakeKillSwitch
        {
            NextResult = PlatformResult.Fail(PlatformErrorKind.InvalidArgument, reason)
        };
        var writer = new FakeProtectionStateWriter();
        var json = new KillSwitchHandler(ks, writer).Handle(Req(true));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Equal(reason, result.Message);
        Assert.Equal(true, ks.LastEnable); // subsystem was called — it rejected, not the handler
        Assert.Empty(writer.Calls);        // writer not called when subsystem fails
    }

    [Fact]
    public void Ctor_rejectsNullWriter()
    {
        Assert.Throws<System.ArgumentNullException>(() => new KillSwitchHandler(new FakeKillSwitch(), null!));
    }

    /// <summary>Subsystem OK but intent persist fails → return Fail.</summary>
    [Fact]
    public void IntentPersistFailure_returnsFail()
    {
        var ks = new FakeKillSwitch();
        var writer = new FakeProtectionStateWriter { FailKillSwitch = PlatformErrorKind.OperationFailed };
        var json = new KillSwitchHandler(ks, writer).Handle(Req(true));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.False(result!.Success);
        Assert.Contains(nameof(IProtectionStateWriter.SetKillSwitchEnabled), writer.Calls);
    }
}
