using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class LeakMitigationHandlerTests
{
    [Fact]
    public void LeakMitigationResponse_roundTripsThroughSourceGenSerializer()
    {
        var payload = new LeakMitigationResponse(Enabled: true, RebootRecommended: true);
        var json = IpcSerializer.SerializePayload(Result<LeakMitigationResponse>.Ok(payload));

        var back = IpcSerializer.DeserializePayload<Result<LeakMitigationResponse>>(json);

        Assert.NotNull(back);
        Assert.True(back!.Success);
        Assert.True(back.Value!.Enabled);
        Assert.True(back.Value.RebootRecommended);
    }

    private static string Handle(FakeLeakMitigationPolicy policy, bool enable,
        FakeProtectionStateWriter? writer = null)
    {
        var w = writer ?? new FakeProtectionStateWriter();
        var handler = new DnsCryptControl.Ipc.Dispatch.Handlers.LeakMitigationHandler(policy, w);
        var payloadJson = IpcSerializer.SerializePayload(new SetTogglePayload(enable));
        return handler.Handle(new IpcRequest(IpcCommandType.SetLeakMitigations, payloadJson));
    }

    [Fact]
    public void Handler_servesSetLeakMitigationsCommand()
    {
        var handler = new DnsCryptControl.Ipc.Dispatch.Handlers.LeakMitigationHandler(
            new FakeLeakMitigationPolicy(), new FakeProtectionStateWriter());
        Assert.Equal(IpcCommandType.SetLeakMitigations, handler.Command);
    }

    [Fact]
    public void Enable_success_withReboot_mapsRebootRecommendedTrue()
    {
        var policy = new FakeLeakMitigationPolicy { AdvisoryToReturn = RebootAdvisory.Recommended };
        var writer = new FakeProtectionStateWriter();
        var result = IpcSerializer.DeserializePayload<Result<LeakMitigationResponse>>(Handle(policy, enable: true, writer));

        Assert.Equal(true, policy.LastEnableArg);
        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(result.Value!.Enabled);
        Assert.True(result.Value.RebootRecommended);
        Assert.Contains(nameof(IProtectionStateWriter.SetLeakMitigationsEnabled), writer.Calls);
        Assert.Equal(true, writer.LastLeak);
    }

    [Fact]
    public void Enable_success_noReboot_mapsRebootRecommendedFalse()
    {
        var policy = new FakeLeakMitigationPolicy { AdvisoryToReturn = RebootAdvisory.None };
        var result = IpcSerializer.DeserializePayload<Result<LeakMitigationResponse>>(Handle(policy, enable: true));

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(result.Value!.Enabled);
        Assert.False(result.Value.RebootRecommended);
    }

    [Fact]
    public void Disable_success_reportsEnabledFalse()
    {
        var policy = new FakeLeakMitigationPolicy { Enabled = true };
        var writer = new FakeProtectionStateWriter();
        var result = IpcSerializer.DeserializePayload<Result<LeakMitigationResponse>>(Handle(policy, enable: false, writer));

        Assert.Equal(false, policy.LastEnableArg);
        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.False(result.Value!.Enabled);
        Assert.False(result.Value.RebootRecommended);
        Assert.Equal(false, writer.LastLeak);
    }

    [Fact]
    public void Failure_mapsPlatformErrorKind_toIpcErrorCode()
    {
        var policy = new FakeLeakMitigationPolicy { FailWith = PlatformErrorKind.OperationFailed };
        var result = IpcSerializer.DeserializePayload<Result<LeakMitigationResponse>>(Handle(policy, enable: true));

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
    }

    [Fact]
    public void MissingPayload_isRejected_asValidationFailed_withoutCallingPolicy()
    {
        var policy = new FakeLeakMitigationPolicy();
        var writer = new FakeProtectionStateWriter();
        var handler = new DnsCryptControl.Ipc.Dispatch.Handlers.LeakMitigationHandler(policy, writer);
        var json = handler.Handle(new IpcRequest(IpcCommandType.SetLeakMitigations, null));
        var result = IpcSerializer.DeserializePayload<Result<LeakMitigationResponse>>(json);

        Assert.Null(policy.LastEnableArg); // policy never invoked
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Empty(writer.Calls); // writer also never invoked
    }

    [Fact]
    public void Ctor_rejectsNullWriter()
    {
        Assert.Throws<System.ArgumentNullException>(() =>
            new DnsCryptControl.Ipc.Dispatch.Handlers.LeakMitigationHandler(new FakeLeakMitigationPolicy(), null!));
    }

    /// <summary>Subsystem fails → writer not called.</summary>
    [Fact]
    public void SubsystemFailure_writerNotCalled()
    {
        var policy = new FakeLeakMitigationPolicy { FailWith = PlatformErrorKind.OperationFailed };
        var writer = new FakeProtectionStateWriter();
        Handle(policy, enable: true, writer);

        Assert.Empty(writer.Calls);
    }

    /// <summary>Subsystem OK but intent persist fails → return Fail (not the success response).</summary>
    [Fact]
    public void IntentPersistFailure_returnsFail()
    {
        var policy = new FakeLeakMitigationPolicy { AdvisoryToReturn = RebootAdvisory.None };
        var writer = new FakeProtectionStateWriter { FailLeak = PlatformErrorKind.OperationFailed };
        var json = Handle(policy, enable: true, writer);
        var result = IpcSerializer.DeserializePayload<Result<LeakMitigationResponse>>(json);

        Assert.False(result!.Success);
        Assert.Contains(nameof(IProtectionStateWriter.SetLeakMitigationsEnabled), writer.Calls);
    }
}
