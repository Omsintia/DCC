using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class FirewallKillSwitchTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    // ---------------------------------------------------------------------------
    // In-memory seam fake: models INetFwRules add/remove/enumerate by Name.
    // ---------------------------------------------------------------------------
    private sealed class FakeRuleStore : IFirewallRuleStore
    {
        public List<FirewallRuleDescriptor> Rules { get; } = new();
        public int AddCalls { get; private set; }
        public int RemoveCalls { get; private set; }
        public bool FailNextAdd { get; set; }

        public void Add(FirewallRuleDescriptor rule)
        {
            AddCalls++;
            if (FailNextAdd) { FailNextAdd = false; throw new InvalidOperationException("simulated COM Add failure"); }
            Rules.RemoveAll(r => string.Equals(r.Name, rule.Name, StringComparison.OrdinalIgnoreCase));
            Rules.Add(rule);
        }

        public void Remove(string name)
        {
            RemoveCalls++;
            Rules.RemoveAll(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        }

        public IReadOnlyCollection<string> ListNames() => Rules.Select(r => r.Name).ToList();
    }

    private sealed class ThrowingRemoveStore : IFirewallRuleStore
    {
        public void Add(FirewallRuleDescriptor rule) { }
        public void Remove(string name) => throw new InvalidOperationException("simulated COM Remove failure");
        public IReadOnlyCollection<string> ListNames() => Array.Empty<string>();
    }

    // ---------------------------------------------------------------------------
    // Fake safety-check seam
    // ---------------------------------------------------------------------------
    private sealed class SafeConfigCheck : IProxyConfigSafetyCheck
    {
        public (bool Safe, string? Reason) IsSafeUnderPort53Block() => (true, null);
    }

    private sealed class UnsafeConfigCheck : IProxyConfigSafetyCheck
    {
        public string Reason { get; }
        public UnsafeConfigCheck(string reason = "netprobe_timeout must be 0") => Reason = reason;
        public (bool Safe, string? Reason) IsSafeUnderPort53Block() => (false, Reason);
    }

    // ---------------------------------------------------------------------------
    // IDisposable: clean up temp files created by TempBackupStore.
    // ---------------------------------------------------------------------------
    public void Dispose()
    {
        foreach (var path in _tempFiles)
        {
            try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        GC.SuppressFinalize(this);
    }

    // ---------------------------------------------------------------------------
    // Helper: a DnsBackupStore backed by a temp file (real object, but in scratch dir).
    // The file path is registered for cleanup on test class disposal.
    // ---------------------------------------------------------------------------
    private DnsBackupStore TempBackupStore()
    {
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        _tempFiles.Add(tmp);
        return new DnsBackupStore(tmp);
    }

    // ---------------------------------------------------------------------------
    // Cycle 1 tests
    // ---------------------------------------------------------------------------

    [Fact]
    public void SetKillSwitch_true_addsExactlyTheThreeBlockRules()
    {
        var store = new FakeRuleStore();
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new SafeConfigCheck());

        var result = ks.SetKillSwitch(true);

        Assert.True(result.Success);
        Assert.Equal(3, store.Rules.Count);
        Assert.Contains(store.Rules, r => r.Name == FirewallKillSwitch.RuleNameUdp53 && r.Protocol == 17 && r.RemotePorts == "53");
        Assert.Contains(store.Rules, r => r.Name == FirewallKillSwitch.RuleNameTcp53 && r.Protocol == 6 && r.RemotePorts == "53");
        Assert.Contains(store.Rules, r => r.Name == FirewallKillSwitch.RuleNameTcp853 && r.Protocol == 6 && r.RemotePorts == "853");
    }

    [Fact]
    public void RuleNames_areTheFixedProductPrefixedDisplayNames()
    {
        Assert.Equal("DnsCryptControl KillSwitch UDP53", FirewallKillSwitch.RuleNameUdp53);
        Assert.Equal("DnsCryptControl KillSwitch TCP53", FirewallKillSwitch.RuleNameTcp53);
        Assert.Equal("DnsCryptControl KillSwitch TCP853", FirewallKillSwitch.RuleNameTcp853);
        Assert.Equal(
            new[] { "DnsCryptControl KillSwitch UDP53", "DnsCryptControl KillSwitch TCP53", "DnsCryptControl KillSwitch TCP853" },
            FirewallKillSwitch.AllRuleNames.ToArray());
    }

    [Fact]
    public void SetKillSwitch_true_isIdempotent_removesBeforeAdd_noDuplicates()
    {
        var store = new FakeRuleStore();
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new SafeConfigCheck());

        ks.SetKillSwitch(true);
        ks.SetKillSwitch(true); // second apply must not duplicate

        Assert.Equal(3, store.Rules.Count);
        // Remove-before-Add: 3 removes per call * 2 calls = 6
        Assert.Equal(6, store.RemoveCalls);
        Assert.Equal(6, store.AddCalls);
    }

    [Fact]
    public void SetKillSwitch_false_removesAllThree_idempotently()
    {
        var store = new FakeRuleStore();
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new SafeConfigCheck());
        ks.SetKillSwitch(true);

        var off = ks.SetKillSwitch(false);
        Assert.True(off.Success);
        Assert.Empty(store.Rules);

        // Calling false again when already absent is a no-op success.
        var offAgain = ks.SetKillSwitch(false);
        Assert.True(offAgain.Success);
        Assert.Empty(store.Rules);
    }

    [Fact]
    public void IsKillSwitchActive_trueOnlyWhenAllThreePresent()
    {
        var store = new FakeRuleStore();
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new SafeConfigCheck());

        Assert.False(ks.IsKillSwitchActive());

        ks.SetKillSwitch(true);
        Assert.True(ks.IsKillSwitchActive());

        store.Remove(FirewallKillSwitch.RuleNameTcp853);
        Assert.False(ks.IsKillSwitchActive());
    }

    [Fact]
    public void SetKillSwitch_true_recordsRuleNamesIntoBackupStore()
    {
        var store = new FakeRuleStore();
        var backup = TempBackupStore();
        var ks = new FirewallKillSwitch(store, backup, new SafeConfigCheck());

        ks.SetKillSwitch(true);

        // Verify the backup slice was written.
        var state = backup.Load();
        Assert.NotNull(state);
        Assert.Equal(
            new[] { "DnsCryptControl KillSwitch UDP53", "DnsCryptControl KillSwitch TCP53", "DnsCryptControl KillSwitch TCP853" },
            state!.AddedFirewallRuleNames.ToArray());
    }

    [Fact]
    public void SetKillSwitch_true_whenStoreThrows_returnsOperationFailed_andRollsBackPartialRules()
    {
        var store = new FakeRuleStore { FailNextAdd = true }; // first Add throws
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new SafeConfigCheck());

        var result = ks.SetKillSwitch(true);

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
        Assert.Empty(store.Rules);
    }

    [Fact]
    public void SetKillSwitch_false_whenStoreThrows_returnsOperationFailed()
    {
        var store = new ThrowingRemoveStore();
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new SafeConfigCheck());

        var result = ks.SetKillSwitch(false);

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
    }

    // ---------------------------------------------------------------------------
    // IC-4: Off-53 safety guard tests
    // ---------------------------------------------------------------------------

    [Fact]
    public void SetKillSwitch_true_whenConfigUnsafe_returnsInvalidArgument_andAddsNoRules()
    {
        var store = new FakeRuleStore();
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new UnsafeConfigCheck("netprobe_timeout must be 0"));

        var result = ks.SetKillSwitch(true);

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.InvalidArgument, result.Error);
        Assert.Contains("netprobe_timeout", result.Message);
        // No rules must have been added.
        Assert.Empty(store.Rules);
    }

    [Fact]
    public void SetKillSwitch_false_whenConfigUnsafe_stillSucceeds_guardDoesNotBlockRemoval()
    {
        // The off-53 guard only blocks ENABLING; removal is always allowed.
        var store = new FakeRuleStore();
        var ks = new FirewallKillSwitch(store, TempBackupStore(), new UnsafeConfigCheck());

        // Manually add rules to the store to simulate partially-enabled state.
        store.Add(new FirewallRuleDescriptor(FirewallKillSwitch.RuleNameUdp53, "d", 17, "53"));
        store.Add(new FirewallRuleDescriptor(FirewallKillSwitch.RuleNameTcp53, "d", 6, "53"));
        store.Add(new FirewallRuleDescriptor(FirewallKillSwitch.RuleNameTcp853, "d", 6, "853"));

        var result = ks.SetKillSwitch(false);

        Assert.True(result.Success);
        Assert.Empty(store.Rules);
    }

    // ---------------------------------------------------------------------------
    // IC-6: Backup is captured only once (idempotent via CaptureFirewallRulesIfAbsent)
    // ---------------------------------------------------------------------------

    [Fact]
    public void SetKillSwitch_true_calledTwice_backupSliceNotOverwritten()
    {
        var store = new FakeRuleStore();
        var backup = TempBackupStore();
        var ks = new FirewallKillSwitch(store, backup, new SafeConfigCheck());

        ks.SetKillSwitch(true);
        // Disable then re-enable — the backup slice must NOT be overwritten.
        ks.SetKillSwitch(false);
        ks.SetKillSwitch(true);

        var state = backup.Load();
        Assert.NotNull(state);
        // Still the original three rule names — not duplicated or re-written.
        Assert.Equal(3, state!.AddedFirewallRuleNames.Count);
    }

    // ---------------------------------------------------------------------------
    // ManualIntegration: COM round-trip (live firewall; elevation required).
    // ---------------------------------------------------------------------------

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void Com_endToEnd_killSwitch_addsDetectsRemoves_onLiveFirewall()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Requires elevation + Windows Firewall service (MpsSvc) running. The ManualIntegration
        // trait keeps this out of CI (Category!=ManualIntegration); run it explicitly as Administrator.
        var ks = new FirewallKillSwitch(new ComFirewallRuleStore(), TempBackupStore(), new SafeConfigCheck());
        Assert.True(ks.SetKillSwitch(true).Success);
        Assert.True(ks.IsKillSwitchActive());
        Assert.True(ks.SetKillSwitch(false).Success);
        Assert.False(ks.IsKillSwitchActive());
    }
}
