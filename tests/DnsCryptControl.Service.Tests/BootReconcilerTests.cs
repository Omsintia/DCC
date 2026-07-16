using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Supplychain;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class BootReconcilerTests : IDisposable
{
    private readonly string _temp =
        Path.Combine(Path.GetTempPath(), "DnsCryptCtlBoot_" + Guid.NewGuid().ToString("N"));

    private string StateFile => Path.Combine(_temp, "protection.json");

    public BootReconcilerTests() => Directory.CreateDirectory(_temp);

    public void Dispose()
    {
        try { if (Directory.Exists(_temp)) Directory.Delete(_temp, recursive: true); }
        catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private sealed class FakeAdapters : IDnsAdapterConfigurator
    {
        public List<string> Calls { get; } = new();
        public PlatformErrorKind? FailReassert { get; set; }
        public PlatformResult ApplyLoopbackToAllAdapters() { Calls.Add(nameof(ApplyLoopbackToAllAdapters)); return PlatformResult.Ok(); }
        public PlatformResult ReassertLoopback()
        {
            Calls.Add(nameof(ReassertLoopback));
            return FailReassert is { } k ? PlatformResult.Fail(k, "reassert failed") : PlatformResult.Ok();
        }
        public PlatformResult RestoreDns() { Calls.Add(nameof(RestoreDns)); return PlatformResult.Ok(); }
        public bool IsLoopbackApplied() => true;
    }

    private sealed class FakeKillSwitch : IFirewallKillSwitch
    {
        public List<bool> SetCalls { get; } = new();
        public PlatformResult SetKillSwitch(bool enable) { SetCalls.Add(enable); return PlatformResult.Ok(); }
        public bool IsKillSwitchActive() => false;
    }

    private sealed class FakeLeak : ILeakMitigationPolicy
    {
        public List<bool> SetCalls { get; } = new();
        public PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable)
        {
            SetCalls.Add(enable);
            return PlatformResult<RebootAdvisory>.Ok(RebootAdvisory.None);
        }
        public bool AreLeakMitigationsEnabled() => false;
    }

    private sealed class FakeProxy : IProxyServiceController
    {
        public List<string> Calls { get; } = new();
        public PlatformErrorKind? FailStart { get; set; }
        public PlatformResult<ProxyServiceState> GetState() => PlatformResult<ProxyServiceState>.Ok(ProxyServiceState.Stopped);
        public PlatformResult Install() => PlatformResult.Ok();
        public PlatformResult Uninstall() => PlatformResult.Ok();
        public PlatformResult Start()
        {
            Calls.Add(nameof(Start));
            return FailStart is { } k ? PlatformResult.Fail(k, "start failed") : PlatformResult.Ok();
        }
        public PlatformResult Stop() => PlatformResult.Ok();
        public PlatformResult Restart() => PlatformResult.Ok();
    }

    // In-memory firewall-rule seam that counts Add calls, for the F7 boot-reassert proving test below.
    private sealed class CountingRuleStore : IFirewallRuleStore
    {
        public List<FirewallRuleDescriptor> Rules { get; } = new();
        public int AddCalls { get; private set; }
        public void Add(FirewallRuleDescriptor rule) { AddCalls++; Rules.Add(rule); }
        public void Remove(string name) => Rules.RemoveAll(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        public IReadOnlyCollection<string> ListNames() => Rules.Select(r => r.Name).ToList();
    }

    // A safety check that reports the active proxy config is NOT safe under a port-53 block.
    private sealed class UnsafeConfigCheck : IProxyConfigSafetyCheck
    {
        public (bool Safe, string? Reason) IsSafeUnderPort53Block() => (false, "netprobe_timeout must be 0");
    }

    private sealed class FakeSeedConfigStore : IConfigStore
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

        // Reconcile only seeds; the rest of the store surface is out of scope here.
        public PlatformResult<string> ReadConfig() => PlatformResult<string>.Fail(PlatformErrorKind.NotFound, "not used");
        public PlatformResult WriteConfig(string tomlText) => PlatformResult.Ok();
        public PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256) => PlatformResult.Ok();
        public PlatformResult WriteRuleFile(RuleFileKind kind, string content) => PlatformResult.Ok();
        public PlatformResult PlaceOdohSourceCaches() => PlatformResult.Ok();
    }

    private (BootReconciler r, FakeAdapters a, FakeKillSwitch k, FakeLeak l, FakeProxy p, FakeSeedConfigStore c) Build(ProtectionState saved)
    {
        var store = new ProtectionStateStore(StateFile);
        store.Save(saved);
        var a = new FakeAdapters();
        var k = new FakeKillSwitch();
        var l = new FakeLeak();
        var p = new FakeProxy();
        var c = new FakeSeedConfigStore();
        var r = new BootReconciler(store, a, k, l, p, c, NullLogger<BootReconciler>.Instance);
        return (r, a, k, l, p, c);
    }

    private BootReconciler BuildWithProxy(ProtectionState saved, IProxyServiceController proxy)
    {
        var store = new ProtectionStateStore(StateFile);
        store.Save(saved);
        return new BootReconciler(store, new FakeAdapters(), new FakeKillSwitch(), new FakeLeak(),
            proxy, new FakeSeedConfigStore(), NullLogger<BootReconciler>.Instance);
    }

    [Fact]
    public void Reconcile_protectionOn_withGatedProxy_tamperedExe_doesNotLaunchProxy()
    {
        // The decorated controller is what Reconcile actually holds in production. With a failing
        // integrity gate (tampered exe), the gated Start returns Fail and the REAL inner Start is
        // never invoked — so boot reconciliation cannot launch a tampered SYSTEM DNS proxy.
        if (!OperatingSystem.IsWindows()) return;

        var baseDir = Directory.CreateTempSubdirectory().FullName;
        var paths = new ProtectedPaths(baseDir);
        var record = new InstalledBinaryRecordStore(paths.InstalledBinaryRecordFile);
        Directory.CreateDirectory(paths.BaseDir);
        File.WriteAllText(paths.ProxyExeFile, "MZ-good");
        record.Record(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("MZ-good"))).ToLowerInvariant(), "2.1.16");
        File.WriteAllText(paths.ProxyExeFile, "MZ-tampered"); // swap after recording

        var inner = new FakeProxy();
        var gated = new IntegrityGatedProxyServiceController(
            inner, new BinaryIntegrityGate(paths, record), new FakeSeedConfigStore(),
            NullLogger<IntegrityGatedProxyServiceController>.Instance);

        var r = BuildWithProxy(new ProtectionState(true, false, false), gated);
        var ex = Record.Exception(() => r.Reconcile());

        Assert.Null(ex); // Reconcile never throws; the gated Start failure is logged, not fatal.
        Assert.DoesNotContain(nameof(IProxyServiceController.Start), inner.Calls); // proxy NOT launched
    }

    [Fact]
    public void Reconcile_protectionOff_isNoOp()
    {
        var (r, a, k, l, p, c) = Build(new ProtectionState(false, false, false));
        r.Reconcile();
        Assert.Empty(a.Calls);
        Assert.Empty(k.SetCalls);
        Assert.Empty(l.SetCalls);
        Assert.Empty(p.Calls);
        Assert.Equal(0, c.EnsureCalls); // no seeding when protection is off
    }

    [Fact]
    public void Reconcile_protectionOn_reassertsLoopback_andStartsProxy()
    {
        var (r, a, k, l, p, c) = Build(new ProtectionState(true, false, false));
        r.Reconcile();
        Assert.Contains(nameof(IDnsAdapterConfigurator.ReassertLoopback), a.Calls);
        Assert.Contains(nameof(IProxyServiceController.Start), p.Calls);
        // The default source cache is seeded before the proxy start (fresh-boot brick guard).
        Assert.Equal(1, c.EnsureCalls);
        // Neither killswitch nor leak mitigations were requested, so they are NOT asserted.
        Assert.Empty(k.SetCalls);
        Assert.Empty(l.SetCalls);
        // Never restore ISP/DHCP DNS on a missing proxy (would leak).
        Assert.DoesNotContain(nameof(IDnsAdapterConfigurator.RestoreDns), a.Calls);
    }

    [Fact]
    public void Reconcile_seedFailure_isLogged_proxyStillStarted()
    {
        var (r, _, _, _, p, c) = Build(new ProtectionState(true, false, false));
        c.FailNextEnsure = PlatformErrorKind.OperationFailed;
        var ex = Record.Exception(() => r.Reconcile());
        Assert.Null(ex);                                                  // boot steps never throw
        Assert.Equal(1, c.EnsureCalls);                                   // seed was attempted
        Assert.Contains(nameof(IProxyServiceController.Start), p.Calls);  // best-effort start still runs
    }

    [Fact]
    public void Reconcile_protectionOn_withKillSwitchAndLeak_assertsBoth()
    {
        var (r, a, k, l, p, _) = Build(new ProtectionState(true, true, true));
        r.Reconcile();
        Assert.Contains(nameof(IDnsAdapterConfigurator.ReassertLoopback), a.Calls);
        Assert.Equal(new[] { true }, k.SetCalls);   // SetKillSwitch(true)
        Assert.Equal(new[] { true }, l.SetCalls);   // SetLeakMitigations(true)
        Assert.Contains(nameof(IProxyServiceController.Start), p.Calls);
    }

    [Fact]
    public void Reconcile_proxyStartFailure_isLogged_notFatal()
    {
        var (r, a, _, _, p, _) = Build(new ProtectionState(true, false, false));
        p.FailStart = PlatformErrorKind.OperationFailed;
        var ex = Record.Exception(() => r.Reconcile());
        Assert.Null(ex);                                                  // never throws
        Assert.Contains(nameof(IDnsAdapterConfigurator.ReassertLoopback), a.Calls);
        Assert.Contains(nameof(IProxyServiceController.Start), p.Calls);  // attempt was made
    }

    [Fact]
    public void Reconcile_reassertFailure_isLogged_proxyStillStarted()
    {
        var (r, a, _, _, p, _) = Build(new ProtectionState(true, false, false));
        a.FailReassert = PlatformErrorKind.OperationFailed;
        var ex = Record.Exception(() => r.Reconcile());
        Assert.Null(ex);
        Assert.Contains(nameof(IDnsAdapterConfigurator.ReassertLoopback), a.Calls);
        Assert.Contains(nameof(IProxyServiceController.Start), p.Calls);  // auto-recover still attempted
    }

    // F7 (finding assessed as a NON-ISSUE): boot reconciliation re-asserts the kill switch from persisted
    // state, so the concern was "could it arm the kill switch over a config that has since become UNSAFE
    // under a port-53 block?". It cannot: FirewallKillSwitch.Enable re-runs its IC-4 safety gate on EVERY
    // call (there is no cached "already enabled" fast-path), so the boot/watcher re-assert path is gated
    // exactly like the interactive one. This drives the REAL FirewallKillSwitch through Reconcile() with a
    // tampered ProtectionState(on, killswitch on, leak off) and an unsafe config, and proves ZERO rules are
    // armed and nothing throws. No product change — the gate already covers this path.
    [Fact]
    public void Reconcile_killSwitchOn_butConfigUnsafe_armsNoRules_andDoesNotThrow()
    {
        if (!OperatingSystem.IsWindows()) return;

        var ruleStore = new CountingRuleStore();
        var backup = new DnsBackupStore(Path.Combine(_temp, "backup.json"));
        var realKillSwitch = new FirewallKillSwitch(ruleStore, backup, new UnsafeConfigCheck());

        var store = new ProtectionStateStore(StateFile);
        store.Save(new ProtectionState(ProtectionEnabled: true, KillSwitchEnabled: true, LeakMitigationsEnabled: false));

        var adapters = new FakeAdapters();
        var proxy = new FakeProxy();
        var r = new BootReconciler(store, adapters, realKillSwitch, new FakeLeak(), proxy,
            new FakeSeedConfigStore(), NullLogger<BootReconciler>.Instance);

        var ex = Record.Exception(() => r.Reconcile());

        Assert.Null(ex);                       // never throws
        Assert.Equal(0, ruleStore.AddCalls);   // the IC-4 gate fired before any rule was touched
        Assert.Empty(ruleStore.Rules);         // zero kill-switch rules armed over the unsafe config
        // Reconciliation still keeps DNS on loopback and best-effort restarts the proxy (fail-closed, no leak).
        Assert.Contains(nameof(IDnsAdapterConfigurator.ReassertLoopback), adapters.Calls);
        Assert.Contains(nameof(IProxyServiceController.Start), proxy.Calls);
    }
}
