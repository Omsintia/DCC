using System;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>VerifyResolution (protocol v4, FIX #1): handler behavior + the source-gen wire
/// round-trip for <see cref="ResolveVerification"/> — omission from IpcJsonContext would be a
/// SILENT serialize failure, so the round-trip tests are the registration's regression guard.
/// Mirrors <see cref="RunDiagnosticsHandlerTests"/>.</summary>
public class VerifyResolutionHandlerTests
{
    private sealed class FakeProbe : IDiagnosticsProbe
    {
        public PlatformResult<ResolveVerification>? Override { get; init; }
        public int VerifyCalls { get; private set; }

        public PlatformResult<DiagnosticsSnapshot> Run() =>
            PlatformResult<DiagnosticsSnapshot>.Fail(PlatformErrorKind.OperationFailed, "wrong method — handler must call VerifyUpstreamResolution");

        public PlatformResult<ResolveVerification> VerifyUpstreamResolution()
        {
            VerifyCalls++;
            return Override ?? PlatformResult<ResolveVerification>.Ok(new ResolveVerification(true, 120, "RCODE=3, ancount=0"));
        }
    }

    [Fact]
    public void Verification_roundTripsThroughSourceGenSerializer()
    {
        var json = IpcSerializer.SerializePayload(new ResolveVerification(true, 87, "RCODE=0, ancount=1"));
        var back = IpcSerializer.DeserializePayload<ResolveVerification>(json);

        Assert.NotNull(back);
        Assert.True(back!.Resolved);
        Assert.Equal(87, back.ElapsedMs);
        Assert.Equal("RCODE=0, ancount=1", back.Detail);
    }

    [Fact]
    public void ResultOfVerification_roundTripsThroughSourceGenSerializer()
    {
        var json = IpcSerializer.SerializePayload(
            Result<ResolveVerification>.Ok(new ResolveVerification(false, 5000, "timeout")));
        var back = IpcSerializer.DeserializePayload<Result<ResolveVerification>>(json);

        Assert.NotNull(back);
        Assert.True(back!.Success);
        Assert.NotNull(back.Value);
        Assert.False(back.Value!.Resolved);
        Assert.Equal("timeout", back.Value.Detail);
    }

    [Fact]
    public void Command_isVerifyResolution()
    {
        Assert.Equal(IpcCommandType.VerifyResolution, new VerifyResolutionHandler(new FakeProbe()).Command);
    }

    [Fact]
    public void Ctor_rejectsNullProbe()
    {
        Assert.Throws<ArgumentNullException>(() => new VerifyResolutionHandler(null!));
    }

    [Fact]
    public void Success_returnsTheVerification_andCallsTheVerifySeamNotRun()
    {
        var probe = new FakeProbe();
        var handler = new VerifyResolutionHandler(probe);
        var json = handler.Handle(new IpcRequest(IpcCommandType.VerifyResolution, null));
        var result = IpcSerializer.DeserializePayload<Result<ResolveVerification>>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(IpcErrorCode.None, result.Code);
        Assert.True(result.Value!.Resolved);
        Assert.Equal(1, probe.VerifyCalls);
    }

    [Fact]
    public void DeadRoute_isASuccessResult_withResolvedFalse()
    {
        // The contract the UI depends on: a dead route is Success=true + Resolved=false (the probe
        // RAN and its answer is "no"), never a failed Result — Fail is reserved for a probe that
        // could not run, which the UI maps to the softer "couldn't verify" copy.
        var probe = new FakeProbe
        {
            Override = PlatformResult<ResolveVerification>.Ok(new ResolveVerification(false, 5000, "timeout")),
        };
        var handler = new VerifyResolutionHandler(probe);
        var json = handler.Handle(new IpcRequest(IpcCommandType.VerifyResolution, null));
        var result = IpcSerializer.DeserializePayload<Result<ResolveVerification>>(json);

        Assert.True(result!.Success);
        Assert.False(result.Value!.Resolved);
    }

    [Fact]
    public void IgnoresPayload_verifyIsReadOnlyAndTakesNoArgs()
    {
        var handler = new VerifyResolutionHandler(new FakeProbe());
        var json = handler.Handle(new IpcRequest(IpcCommandType.VerifyResolution, "{\"junk\":true}"));
        var result = IpcSerializer.DeserializePayload<Result<ResolveVerification>>(json);

        Assert.True(result!.Success);
        Assert.NotNull(result.Value);
    }

    [Fact]
    public void ProbeFailure_mapsErrorKindToIpcCode()
    {
        var failing = new FakeProbe
        {
            Override = PlatformResult<ResolveVerification>.Fail(PlatformErrorKind.OperationFailed, "probe blew up"),
        };
        var handler = new VerifyResolutionHandler(failing);
        var json = handler.Handle(new IpcRequest(IpcCommandType.VerifyResolution, null));
        var result = IpcSerializer.DeserializePayload<Result<ResolveVerification>>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("probe blew up", result.Message);
        Assert.Null(result.Value);
    }

    [Fact]
    public void ProbeFailure_withNullMessage_usesFallbackMessage()
    {
        var failing = new FakeProbe
        {
            Override = new PlatformResult<ResolveVerification>(false, null, PlatformErrorKind.Timeout, null),
        };
        var handler = new VerifyResolutionHandler(failing);
        var json = handler.Handle(new IpcRequest(IpcCommandType.VerifyResolution, null));
        var result = IpcSerializer.DeserializePayload<Result<ResolveVerification>>(json);

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code); // Timeout maps to OperationFailed
        Assert.Equal("resolve verification failed", result.Message);
    }
}
