using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class DnsAdapterHandlerTests
{
    [Fact]
    public void Apply_command_isApplyDnsToAllAdapters()
    {
        var handler = new ApplyDnsToAllAdaptersHandler(new FakeDnsAdapterConfigurator(), new FakeProtectionStateWriter());
        Assert.Equal(IpcCommandType.ApplyDnsToAllAdapters, handler.Command);
    }

    [Fact]
    public void Restore_command_isRestoreDns()
    {
        var handler = new RestoreDnsHandler(new FakeDnsAdapterConfigurator(), new FakeProtectionStateWriter());
        Assert.Equal(IpcCommandType.RestoreDns, handler.Command);
    }

    [Fact]
    public void Apply_invokesConfigurator_andReturnsOk()
    {
        var cfg = new FakeDnsAdapterConfigurator();
        var writer = new FakeProtectionStateWriter();
        var json = new ApplyDnsToAllAdaptersHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.ApplyDnsToAllAdapters, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.Contains(nameof(IDnsAdapterConfigurator.ApplyLoopbackToAllAdapters), cfg.Calls);
        Assert.Contains(nameof(IProtectionStateWriter.EnableProtection), writer.Calls);
        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(IpcErrorCode.None, result.Code);
    }

    [Fact]
    public void Apply_mapsPlatformFailure_toIpcErrorCode()
    {
        var cfg = new FakeDnsAdapterConfigurator { FailApply = PlatformErrorKind.OperationFailed };
        var writer = new FakeProtectionStateWriter();
        var json = new ApplyDnsToAllAdaptersHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.ApplyDnsToAllAdapters, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("apply failed", result.Message);
    }

    [Fact]
    public void Restore_invokesConfigurator_andReturnsOk()
    {
        var cfg = new FakeDnsAdapterConfigurator { Applied = true };
        var writer = new FakeProtectionStateWriter();
        var json = new RestoreDnsHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.RestoreDns, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.Contains(nameof(IDnsAdapterConfigurator.RestoreDns), cfg.Calls);
        Assert.Contains(nameof(IProtectionStateWriter.DisableProtection), writer.Calls);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    [Fact]
    public void Restore_mapsPlatformFailure_toIpcErrorCode()
    {
        var cfg = new FakeDnsAdapterConfigurator { FailRestore = PlatformErrorKind.NotFound };
        var writer = new FakeProtectionStateWriter();
        var json = new RestoreDnsHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.RestoreDns, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.NotFound, result.Code);
        Assert.Equal("restore failed", result.Message);
    }

    [Fact]
    public void Ctor_rejectsNullConfigurator()
    {
        var w = new FakeProtectionStateWriter();
        Assert.Throws<System.ArgumentNullException>(() => new ApplyDnsToAllAdaptersHandler(null!, w));
        Assert.Throws<System.ArgumentNullException>(() => new RestoreDnsHandler(null!, w));
    }

    [Fact]
    public void Ctor_rejectsNullWriter()
    {
        var cfg = new FakeDnsAdapterConfigurator();
        Assert.Throws<System.ArgumentNullException>(() => new ApplyDnsToAllAdaptersHandler(cfg, null!));
        Assert.Throws<System.ArgumentNullException>(() => new RestoreDnsHandler(cfg, null!));
    }

    // ── Fail-closed ordering proofs ────────────────────────────────────────────

    /// <summary>Apply: if EnableProtection fails, the configurator must NOT be called
    /// (deny rather than apply without durable protection).</summary>
    [Fact]
    public void Apply_whenIntentPersistFails_returnsFailAndDoesNotCallConfigurator()
    {
        var cfg = new FakeDnsAdapterConfigurator();
        var writer = new FakeProtectionStateWriter { FailEnable = PlatformErrorKind.OperationFailed };
        var json = new ApplyDnsToAllAdaptersHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.ApplyDnsToAllAdapters, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.False(result!.Success);
        Assert.Empty(cfg.Calls); // configurator never reached
        Assert.Contains(nameof(IProtectionStateWriter.EnableProtection), writer.Calls); // writer was called
    }

    /// <summary>Apply: if the apply fails AFTER intent was persisted, we return Fail but leave
    /// ProtectionEnabled=true (boot re-asserts = fail-closed; do NOT call DisableProtection).</summary>
    [Fact]
    public void Apply_whenConfiguratorFails_returnsFailButDoesNotClearIntent()
    {
        var cfg = new FakeDnsAdapterConfigurator { FailApply = PlatformErrorKind.OperationFailed };
        var writer = new FakeProtectionStateWriter();
        var json = new ApplyDnsToAllAdaptersHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.ApplyDnsToAllAdapters, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.False(result!.Success);
        Assert.Contains(nameof(IProtectionStateWriter.EnableProtection), writer.Calls);
        Assert.DoesNotContain(nameof(IProtectionStateWriter.DisableProtection), writer.Calls);
    }

    /// <summary>Restore: if the restore fails, DisableProtection must NOT be called
    /// (intent stays true → boot re-asserts = fail-closed).</summary>
    [Fact]
    public void Restore_whenRestoreFails_returnsFailAndDoesNotClearIntent()
    {
        var cfg = new FakeDnsAdapterConfigurator { FailRestore = PlatformErrorKind.OperationFailed };
        var writer = new FakeProtectionStateWriter();
        var json = new RestoreDnsHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.RestoreDns, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.False(result!.Success);
        Assert.DoesNotContain(nameof(IProtectionStateWriter.DisableProtection), writer.Calls);
    }

    /// <summary>Restore: if the restore succeeds but DisableProtection fails, we surface the failure
    /// (honest, still fail-closed: boot would re-assert if needed).</summary>
    [Fact]
    public void Restore_whenIntentClearFails_returnsFail()
    {
        var cfg = new FakeDnsAdapterConfigurator { Applied = true };
        var writer = new FakeProtectionStateWriter { FailDisable = PlatformErrorKind.OperationFailed };
        var json = new RestoreDnsHandler(cfg, writer)
            .Handle(new IpcRequest(IpcCommandType.RestoreDns, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.False(result!.Success);
        Assert.Contains(nameof(IDnsAdapterConfigurator.RestoreDns), cfg.Calls); // restore ran
        Assert.Contains(nameof(IProtectionStateWriter.DisableProtection), writer.Calls); // intent clear was attempted
    }
}
