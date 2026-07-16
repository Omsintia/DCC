using System;
using System.Collections.Generic;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class RunDiagnosticsHandlerTests
{
    private static DiagnosticsSnapshot Sample() => new(
        TakenUtc: new DateTimeOffset(2026, 6, 29, 0, 0, 0, TimeSpan.Zero),
        Overall: HealthState.Pass,
        Listeners: new ListenerCheck(HealthState.Pass, true, true, false, false, new[] { "127.0.0.1:53" }),
        ActiveResolve: new ActiveResolveCheck(HealthState.Pass, "selfcheck.test", true, 8, "RCODE=0"),
        ActiveResolveV6: new ActiveResolveCheck(HealthState.Pass, "selfcheck.test", true, 9, "RCODE=0"),
        AdapterDns: new AdapterDnsCheck(HealthState.Pass, true,
            new[] { new AdapterDnsEntry("Ethernet", "Intel", "Up", new[] { "127.0.0.1" }, true) }),
        Hardening: new HardeningCheck(HealthState.Pass, true, true, true, true, new[] { "ok" }));

    [Fact]
    public void Snapshot_roundTripsThroughSourceGenSerializer()
    {
        var json = IpcSerializer.SerializePayload(Sample());
        var back = IpcSerializer.DeserializePayload<DiagnosticsSnapshot>(json);

        Assert.NotNull(back);
        Assert.Equal(HealthState.Pass, back!.Overall);
        Assert.True(back.Listeners.Udp_127_0_0_1_53);
        Assert.Equal(new[] { "127.0.0.1:53" }, back.Listeners.ObservedPort53Listeners);
        Assert.Single(back.AdapterDns.Adapters);
        // Fix 3: the new ActiveResolveV6 field is reached transitively from the registered
        // DiagnosticsSnapshot root and must survive the source-gen round-trip.
        Assert.NotNull(back.ActiveResolveV6);
        Assert.True(back.ActiveResolveV6.ProxyAnswered);
        Assert.Equal(HealthState.Pass, back.ActiveResolveV6.State);
    }

    [Fact]
    public void ResultOfSnapshot_roundTripsThroughSourceGenSerializer()
    {
        var json = IpcSerializer.SerializePayload(Result<DiagnosticsSnapshot>.Ok(Sample()));
        var back = IpcSerializer.DeserializePayload<Result<DiagnosticsSnapshot>>(json);

        Assert.NotNull(back);
        Assert.True(back!.Success);
        Assert.NotNull(back.Value);
        Assert.Equal(HealthState.Pass, back.Value!.Overall);
    }

    private sealed class FakeProbe : IDiagnosticsProbe
    {
        public PlatformResult<DiagnosticsSnapshot>? Override { get; init; }
        public PlatformResult<DiagnosticsSnapshot> Run() =>
            Override ?? PlatformResult<DiagnosticsSnapshot>.Ok(Sample());

        public PlatformResult<ResolveVerification> VerifyUpstreamResolution() =>
            PlatformResult<ResolveVerification>.Ok(new ResolveVerification(true, 5, "RCODE=0"));
    }

    [Fact]
    public void Command_isRunDiagnostics()
    {
        Assert.Equal(IpcCommandType.RunDiagnostics, new RunDiagnosticsHandler(new FakeProbe()).Command);
    }

    [Fact]
    public void Ctor_rejectsNullProbe()
    {
        Assert.Throws<ArgumentNullException>(() => new RunDiagnosticsHandler(null!));
    }

    [Fact]
    public void Success_returnsSnapshotResult()
    {
        var handler = new RunDiagnosticsHandler(new FakeProbe());
        var json = handler.Handle(new IpcRequest(IpcCommandType.RunDiagnostics, null));
        var result = IpcSerializer.DeserializePayload<Result<DiagnosticsSnapshot>>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(IpcErrorCode.None, result.Code);
        Assert.NotNull(result.Value);
        Assert.Equal(HealthState.Pass, result.Value!.Overall);
    }

    [Fact]
    public void IgnoresPayload_runIsReadOnlyAndTakesNoArgs()
    {
        var handler = new RunDiagnosticsHandler(new FakeProbe());
        // A junk payload must not change behavior — RunDiagnostics has no input.
        var json = handler.Handle(new IpcRequest(IpcCommandType.RunDiagnostics, "{\"junk\":true}"));
        var result = IpcSerializer.DeserializePayload<Result<DiagnosticsSnapshot>>(json);

        Assert.True(result!.Success);
        Assert.NotNull(result.Value);
    }

    [Fact]
    public void ProbeFailure_mapsErrorKindToIpcCode()
    {
        var failing = new FakeProbe
        {
            Override = PlatformResult<DiagnosticsSnapshot>.Fail(PlatformErrorKind.OperationFailed, "probe blew up"),
        };
        var handler = new RunDiagnosticsHandler(failing);
        var json = handler.Handle(new IpcRequest(IpcCommandType.RunDiagnostics, null));
        var result = IpcSerializer.DeserializePayload<Result<DiagnosticsSnapshot>>(json);

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
            Override = new PlatformResult<DiagnosticsSnapshot>(false, null, PlatformErrorKind.NotFound, null),
        };
        var handler = new RunDiagnosticsHandler(failing);
        var json = handler.Handle(new IpcRequest(IpcCommandType.RunDiagnostics, null));
        var result = IpcSerializer.DeserializePayload<Result<DiagnosticsSnapshot>>(json);

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.NotFound, result.Code);
        Assert.Equal("diagnostics probe failed", result.Message);
    }
}
