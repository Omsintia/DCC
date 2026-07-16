using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Supplychain;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>The single must-have proof: the integrity-gating decorator over IProxyServiceController makes
/// the verified-binary state DOMINATE every launch. A tampered exe (recorded hash != on-disk hash) is
/// NEVER started — Start()/Restart() return Fail and the inner controller's Start/Restart is never called —
/// while Stop/Uninstall/GetState always delegate so a bad binary can still be torn down.</summary>
public class IntegrityGatedProxyServiceControllerTests
{
    private sealed class RecordingProxy : IProxyServiceController
    {
        public List<string> Calls { get; } = new();
        public PlatformResult<ProxyServiceState> GetState() { Calls.Add(nameof(GetState)); return PlatformResult<ProxyServiceState>.Ok(ProxyServiceState.Stopped); }
        public PlatformResult Install() { Calls.Add(nameof(Install)); return PlatformResult.Ok(); }
        public PlatformResult Uninstall() { Calls.Add(nameof(Uninstall)); return PlatformResult.Ok(); }
        public PlatformResult Start() { Calls.Add(nameof(Start)); return PlatformResult.Ok(); }
        public PlatformResult Stop() { Calls.Add(nameof(Stop)); return PlatformResult.Ok(); }
        public PlatformResult Restart() { Calls.Add(nameof(Restart)); return PlatformResult.Ok(); }
    }

    private sealed class SeedRecordingConfigStore : IConfigStore
    {
        public int EnsureCalls { get; private set; }
        public PlatformErrorKind? FailNextEnsure { get; set; }

        public PlatformResult EnsureDefaultSourceCaches()
        {
            EnsureCalls++;
            return FailNextEnsure is { } k
                ? PlatformResult.Fail(k, "default cache seed failed")
                : PlatformResult.Ok();
        }

        // The gate only seeds; the rest of the store surface is out of scope here.
        public PlatformResult<string> ReadConfig() => PlatformResult<string>.Fail(PlatformErrorKind.NotFound, "not used");
        public PlatformResult WriteConfig(string tomlText) => PlatformResult.Ok();
        public PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256) => PlatformResult.Ok();
        public PlatformResult WriteRuleFile(RuleFileKind kind, string content) => PlatformResult.Ok();
        public PlatformResult PlaceOdohSourceCaches() => PlatformResult.Ok();
    }

    private static (ProtectedPaths paths, InstalledBinaryRecordStore record) NewEnv()
    {
        var baseDir = Directory.CreateTempSubdirectory().FullName;
        var paths = new ProtectedPaths(baseDir);
        return (paths, new InstalledBinaryRecordStore(paths.InstalledBinaryRecordFile));
    }

    private static string WriteExe(ProtectedPaths paths, string content)
    {
        Directory.CreateDirectory(paths.BaseDir);
        File.WriteAllText(paths.ProxyExeFile, content);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
    }

    private static IntegrityGatedProxyServiceController Gated(
        IProxyServiceController inner, ProtectedPaths paths, InstalledBinaryRecordStore record,
        IConfigStore? configStore = null) =>
        new(inner, new BinaryIntegrityGate(paths, record), configStore ?? new SeedRecordingConfigStore(),
            NullLogger<IntegrityGatedProxyServiceController>.Instance);

    [Fact]
    public void Start_tamperedExe_returnsFail_andNeverCallsInnerStart()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (paths, record) = NewEnv();
        var hash = WriteExe(paths, "MZ-good");
        record.Record(hash, "2.1.16");
        File.WriteAllText(paths.ProxyExeFile, "MZ-tampered"); // swap AFTER recording -> hash mismatch

        var inner = new RecordingProxy();
        var result = Gated(inner, paths, record).Start();

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
        Assert.DoesNotContain(nameof(IProxyServiceController.Start), inner.Calls); // launch was BLOCKED
    }

    [Fact]
    public void Restart_tamperedExe_returnsFail_andNeverCallsInnerRestart()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (paths, record) = NewEnv();
        var hash = WriteExe(paths, "MZ-good");
        record.Record(hash, "2.1.16");
        File.WriteAllText(paths.ProxyExeFile, "MZ-tampered");

        var inner = new RecordingProxy();
        var result = Gated(inner, paths, record).Restart();

        Assert.False(result.Success);
        Assert.DoesNotContain(nameof(IProxyServiceController.Restart), inner.Calls);
    }

    [Fact]
    public void Start_matchingHash_delegatesToInnerStart()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (paths, record) = NewEnv();
        var hash = WriteExe(paths, "MZ-good");
        record.Record(hash, "2.1.16");

        var inner = new RecordingProxy();
        var result = Gated(inner, paths, record).Start();

        Assert.True(result.Success, result.Message);
        Assert.Contains(nameof(IProxyServiceController.Start), inner.Calls);
    }

    // ── Default-cache seeding at the launch chokepoint (fresh-install brick fix) ──
    // Every consumer's Start/Restart goes through this decorator, so seeding here covers the UI
    // config-apply restart, the dashboard restart, and the installer's post-install start — not
    // just the orchestrated EnableProtection/boot paths.

    [Fact]
    public void Start_matchingHash_seedsTheDefaultCache_beforeDelegating()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (paths, record) = NewEnv();
        record.Record(WriteExe(paths, "MZ-good"), "2.1.16");

        var inner = new RecordingProxy();
        var store = new SeedRecordingConfigStore();
        var result = Gated(inner, paths, record, store).Start();

        Assert.True(result.Success, result.Message);
        Assert.Equal(1, store.EnsureCalls);
        Assert.Contains(nameof(IProxyServiceController.Start), inner.Calls);
    }

    [Fact]
    public void Start_seedFailure_returnsFail_andNeverCallsInnerStart()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (paths, record) = NewEnv();
        record.Record(WriteExe(paths, "MZ-good"), "2.1.16");

        var inner = new RecordingProxy();
        var store = new SeedRecordingConfigStore { FailNextEnsure = PlatformErrorKind.OperationFailed };
        var result = Gated(inner, paths, record, store).Start();

        // Fail-closed: an unseedable cache makes the launch a guaranteed post-start FATAL, so the
        // gate fails fast instead of reporting a start that then dies.
        Assert.False(result.Success);
        Assert.DoesNotContain(nameof(IProxyServiceController.Start), inner.Calls);
    }

    [Fact]
    public void Start_tamperedExe_neverSeeds_theIntegrityGateDominates()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (paths, record) = NewEnv();
        record.Record(WriteExe(paths, "MZ-good"), "2.1.16");
        File.WriteAllText(paths.ProxyExeFile, "MZ-tampered");

        var inner = new RecordingProxy();
        var store = new SeedRecordingConfigStore();
        Assert.False(Gated(inner, paths, record, store).Start().Success);

        Assert.Equal(0, store.EnsureCalls); // integrity verdict comes first; no disk writes for a blocked launch
    }

    [Fact]
    public void Stop_Uninstall_GetState_delegate_evenWhenIntegrityWouldFail()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (paths, record) = NewEnv();
        var hash = WriteExe(paths, "MZ-good");
        record.Record(hash, "2.1.16");
        File.WriteAllText(paths.ProxyExeFile, "MZ-tampered"); // integrity would FAIL

        var inner = new RecordingProxy();
        var gated = Gated(inner, paths, record);

        Assert.True(gated.Stop().Success);
        Assert.True(gated.Uninstall().Success);
        Assert.True(gated.GetState().Success);
        Assert.Contains(nameof(IProxyServiceController.Stop), inner.Calls);
        Assert.Contains(nameof(IProxyServiceController.Uninstall), inner.Calls);
        Assert.Contains(nameof(IProxyServiceController.GetState), inner.Calls);
        // A bad binary must NOT have been started despite tear-down being allowed.
        Assert.DoesNotContain(nameof(IProxyServiceController.Start), inner.Calls);
    }
}
