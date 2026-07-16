using System;
using System.IO;
using System.Security.Cryptography;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>
/// G1: the production save path end-to-end — a serialized IpcRequest through the REAL
/// CommandDispatcher over the REAL HandlerRegistry.Build, into the REAL WriteConfigHandler,
/// gated by the REAL ProtectionAwareConfigWritePolicy over a REAL ProtectionStateStore
/// (temp-dir state-file fixture), writing through the REAL FileSystemConfigStore's
/// compare-and-swap (temp-dir config file). Only the seams WriteConfig never touches are
/// stubbed. Pins the trust-boundary behavior the UI relies on (P5b-U1/IC-3/IC-9/IC-10):
/// unsafe candidate while protected → "OPSEC guard: " refusal; guard inert while
/// unprotected; stale sha → Conflict; corrupt protection state fails CLOSED; the on-disk
/// file is provably byte-identical on every refusal.
/// </summary>
public class WriteConfigEndToEndTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "DnsCryptE2E_" + Guid.NewGuid().ToString("N"));
    private readonly ProtectedPaths _paths;
    private readonly FileSystemConfigStore _configStore;
    private readonly ProtectionStateStore _stateStore;
    private readonly CommandDispatcher _dispatcher;

    // Satisfies every OPSEC rule (same fixture as ProtectionAwareConfigWritePolicyTests).
    private const string SafeConfig =
        "netprobe_timeout = 0\n" +
        "ignore_system_dns = true\n" +
        "bootstrap_resolvers = ['9.9.9.11:9953']\n" +
        "listen_addresses = ['127.0.0.1:53']\n";

    // Schema-VALID (correct catalog types) but violates three KillSwitchCritical rules —
    // must sail past ConfigValidator and be stopped by the policy, not before (IC-3).
    private const string UnsafeConfig =
        "netprobe_timeout = 60\n" +
        "ignore_system_dns = false\n" +
        "bootstrap_resolvers = ['8.8.8.8:53']\n";

    public WriteConfigEndToEndTests()
    {
        _paths = new ProtectedPaths(_temp);
        _configStore = new FileSystemConfigStore(_paths);
        _stateStore = new ProtectionStateStore(_paths.ProtectionStateFile);
        var policy = new ProtectionAwareConfigWritePolicy(_stateStore);
        _dispatcher = new CommandDispatcher(HandlerRegistry.Build(
            new StubProxy(),
            _configStore,
            new StubAdapters(),
            new StubLeak(),
            new StubKillSwitch(),
            new StubBrowserDoh(),
            new StubFlusher(),
            new StubDiagnostics(),
            new StubProtectionWriter(),
            new StubBinaryInstaller(),
            new StubOrchestrator(),
            policy));
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_temp)) Directory.Delete(_temp, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    // ---- fixture helpers ----

    /// <summary>Writes the initial on-disk config and returns its load-time base sha
    /// (IC-9: lowercase hex SHA-256 of the exact on-disk bytes).</summary>
    private string SeedConfig(string text)
    {
        Assert.True(_configStore.WriteConfig(text).Success);
        return Sha256OfConfigFile();
    }

    private string Sha256OfConfigFile() =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(_paths.ConfigFile))).ToLowerInvariant();

    private void SetProtection(bool enabled) =>
        _stateStore.Save(new ProtectionState(ProtectionEnabled: enabled, KillSwitchEnabled: enabled, LeakMitigationsEnabled: false));

    private Result DispatchWriteConfig(string toml, string baseSha256)
    {
        var payload = IpcSerializer.SerializePayload(new WriteConfigPayload(toml, baseSha256));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(_dispatcher.Dispatch(req));
        Assert.NotNull(result);
        return result!;
    }

    // ---- the G1 scenarios ----

    [Fact]
    public void WhileProtected_unsafeCandidate_isRefusedWithOpsecGuard_fileByteIdentical()
    {
        var sha = SeedConfig(SafeConfig);
        SetProtection(true);
        var before = File.ReadAllBytes(_paths.ConfigFile);

        var result = DispatchWriteConfig(UnsafeConfig, sha);

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code); // InvalidArgument → ValidationFailed
        Assert.StartsWith("OPSEC guard: ", result.Message, StringComparison.Ordinal); // IC-10
        Assert.Contains("netprobe_timeout", result.Message, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllBytes(_paths.ConfigFile)); // refusal never touched the file
    }

    [Fact]
    public void WhileProtected_safeCandidate_writes_andBacksUpPrior()
    {
        var sha = SeedConfig(SafeConfig);
        SetProtection(true);
        var newText = SafeConfig + "max_clients = 250\n";

        var result = DispatchWriteConfig(newText, sha);

        Assert.True(result.Success);
        Assert.Equal(newText, File.ReadAllText(_paths.ConfigFile));
        Assert.Contains(Directory.GetFiles(_paths.BackupsDir), b => File.ReadAllText(b) == SafeConfig);
    }

    [Fact]
    public void WhileUnprotected_unsafeCandidate_isAllowed()
    {
        // P5b-U1: the guard blocks only WHILE protected — unprotected saves of off-spec
        // configs are the user's prerogative (the editor still warns, but never blocks).
        var sha = SeedConfig(SafeConfig);
        SetProtection(false);

        var result = DispatchWriteConfig(UnsafeConfig, sha);

        Assert.True(result.Success);
        Assert.Equal(UnsafeConfig, File.ReadAllText(_paths.ConfigFile));
    }

    [Fact]
    public void StaleBaseSha_afterExternalEdit_isConflict_fileUntouched()
    {
        // The editor loaded the file (sha captured), then an external writer (admin in
        // notepad) changed it. The CAS must surface Conflict (IC-2/IC-9) with the IC-10
        // message and leave the external edit intact.
        var sha = SeedConfig(SafeConfig);
        File.WriteAllText(_paths.ConfigFile, SafeConfig + "# edited externally\n");

        var result = DispatchWriteConfig(SafeConfig + "max_clients = 250\n", sha);

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.Conflict, result.Code);
        Assert.Equal("config file changed on disk since it was loaded — reload before saving", result.Message);
        Assert.Equal(SafeConfig + "# edited externally\n", File.ReadAllText(_paths.ConfigFile));
    }

    [Fact]
    public void CorruptProtectionState_unsafeCandidate_isRefused_failClosed()
    {
        // The pre-flight critical, pinned end-to-end: a PRESENT-but-corrupt state file must
        // be treated as PROTECTED (TryLoad == false → fail-closed), so the unsafe save is
        // refused even though Load() alone would have defaulted to unprotected.
        var sha = SeedConfig(SafeConfig);
        Directory.CreateDirectory(_paths.StateDir);
        File.WriteAllText(_paths.ProtectionStateFile, "{ not valid json");
        var before = File.ReadAllBytes(_paths.ConfigFile);

        var result = DispatchWriteConfig(UnsafeConfig, sha);

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.StartsWith("OPSEC guard: ", result.Message, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllBytes(_paths.ConfigFile));
    }

    // ---- minimal stubs for the seams WriteConfig never touches (Service.Tests convention:
    // private nested fakes per file; every method is an inert Ok/false) ----

    private sealed class StubProxy : IProxyServiceController
    {
        public PlatformResult<ProxyServiceState> GetState() => PlatformResult<ProxyServiceState>.Ok(ProxyServiceState.Running);
        public PlatformResult Install() => PlatformResult.Ok();
        public PlatformResult Uninstall() => PlatformResult.Ok();
        public PlatformResult Start() => PlatformResult.Ok();
        public PlatformResult Stop() => PlatformResult.Ok();
        public PlatformResult Restart() => PlatformResult.Ok();
    }

    private sealed class StubAdapters : IDnsAdapterConfigurator
    {
        public PlatformResult ApplyLoopbackToAllAdapters() => PlatformResult.Ok();
        public PlatformResult ReassertLoopback() => PlatformResult.Ok();
        public PlatformResult RestoreDns() => PlatformResult.Ok();
        public bool IsLoopbackApplied() => false;
    }

    private sealed class StubLeak : ILeakMitigationPolicy
    {
        public PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable) => PlatformResult<RebootAdvisory>.Ok(RebootAdvisory.None);
        public bool AreLeakMitigationsEnabled() => false;
    }

    private sealed class StubKillSwitch : IFirewallKillSwitch
    {
        public PlatformResult SetKillSwitch(bool enable) => PlatformResult.Ok();
        public bool IsKillSwitchActive() => false;
    }

    private sealed class StubBrowserDoh : IBrowserDohPolicy
    {
        public PlatformResult SetBrowserDohPolicy(bool enable) => PlatformResult.Ok();
        public bool IsBrowserDohPolicyApplied() => false;
    }

    private sealed class StubFlusher : IDnsCacheFlusher
    {
        public PlatformResult Flush() => PlatformResult.Ok();
    }

    private sealed class StubDiagnostics : IDiagnosticsProbe
    {
        public PlatformResult<DiagnosticsSnapshot> Run() =>
            PlatformResult<DiagnosticsSnapshot>.Fail(PlatformErrorKind.OperationFailed, "not run in test");

        public PlatformResult<ResolveVerification> VerifyUpstreamResolution() =>
            PlatformResult<ResolveVerification>.Fail(PlatformErrorKind.OperationFailed, "not run in test");
    }

    private sealed class StubProtectionWriter : IProtectionStateWriter
    {
        public PlatformResult EnableProtection() => PlatformResult.Ok();
        public PlatformResult DisableProtection() => PlatformResult.Ok();
        public PlatformResult SetKillSwitchEnabled(bool enabled) => PlatformResult.Ok();
        public PlatformResult SetLeakMitigationsEnabled(bool enabled) => PlatformResult.Ok();
    }

    private sealed class StubBinaryInstaller : IBinaryVerifyInstaller
    {
        public PlatformResult VerifyAndInstall(string tempZipPath, string expectedTag) => PlatformResult.Ok();
    }

    private sealed class StubOrchestrator : IProtectionOrchestrator
    {
        public PlatformResult<ProtectionOutcome> EnableProtection(bool withKillSwitch) =>
            PlatformResult<ProtectionOutcome>.Ok(new ProtectionOutcome(false, false, false, null));
        public PlatformResult DisableProtection() => PlatformResult.Ok();
    }
}
