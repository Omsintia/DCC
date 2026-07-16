using System;
using System.Linq;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class NetshFirewallRuleStoreTests
{
    [Fact]
    public void BuildNetshCommand_usesAbsoluteSystem32Path_argumentList_noShell()
    {
        if (!OperatingSystem.IsWindows()) return;

        var psi = NetshFirewallRuleStore.BuildNetshCommand(
            "advfirewall", "firewall", "add", "rule",
            "name=DnsCryptControl KillSwitch UDP53",
            "dir=out", "action=block", "protocol=UDP", "remoteport=53",
            "profile=any", "enable=yes");

        var expectedNetsh = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");

        Assert.Equal(expectedNetsh, psi.FileName);
        Assert.True(System.IO.Path.IsPathFullyQualified(psi.FileName));
        Assert.False(psi.UseShellExecute);
        Assert.True(psi.CreateNoWindow);
        Assert.Empty(psi.Arguments); // never the concatenated form (CWE-78)
        // The space-containing "name=..." token is one verbatim ArgumentList element (no manual quoting).
        Assert.Contains("name=DnsCryptControl KillSwitch UDP53", psi.ArgumentList.ToArray());
        Assert.Equal("advfirewall", psi.ArgumentList[0]);
    }

    [Fact]
    public void BuildNetshCommand_doesNotRedirectStdoutOrStderr()
    {
        if (!OperatingSystem.IsWindows()) return;

        // The output is never consumed; redirecting without draining the pipes can deadlock the SYSTEM
        // service on the revert path (netsh blocks on a full ~4KB pipe while we block on WaitForExit).
        // CreateNoWindow + UseShellExecute=false already suppress any console window, so no pipe is needed.
        var psi = NetshFirewallRuleStore.BuildNetshCommand(
            "advfirewall", "firewall", "delete", "rule", "name=DnsCryptControl KillSwitch UDP53");

        Assert.False(psi.RedirectStandardOutput);
        Assert.False(psi.RedirectStandardError);
        Assert.False(psi.UseShellExecute);
        Assert.True(psi.CreateNoWindow);
    }

    /// <summary>Always-safe <see cref="IProxyConfigSafetyCheck"/> stub for the live round-trip
    /// (mirrors the private SafeConfigCheck fake in FirewallKillSwitchTests).</summary>
    private sealed class AlwaysSafeConfigCheck : IProxyConfigSafetyCheck
    {
        public (bool Safe, string? Reason) IsSafeUnderPort53Block() => (true, null);
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void Netsh_addRemoveDetect_roundTrip_onLiveFirewall()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Requires elevation + MpsSvc running. The ManualIntegration trait keeps this out of CI
        // (Category!=ManualIntegration); run it explicitly as Administrator.

        var backupFile = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new NetshFirewallRuleStore();
            var backup = new DnsCryptControl.Service.State.DnsBackupStore(backupFile);
            var ks = new FirewallKillSwitch(store, backup, new AlwaysSafeConfigCheck());

            // Step 1: Enable - three rules must be added.
            var enableResult = ks.SetKillSwitch(true);
            Assert.True(enableResult.Success, $"Enable failed: {enableResult.Message}");
            Assert.True(ks.IsKillSwitchActive(), "kill switch should be active after enable");
            var names = store.ListNames();
            Assert.Contains(FirewallKillSwitch.RuleNameUdp53, names);
            Assert.Contains(FirewallKillSwitch.RuleNameTcp53, names);
            Assert.Contains(FirewallKillSwitch.RuleNameTcp853, names);

            // Step 2: Disable - all three rules must be removed.
            var disableResult = ks.SetKillSwitch(false);
            Assert.True(disableResult.Success, $"Disable failed: {disableResult.Message}");
            Assert.False(ks.IsKillSwitchActive(), "kill switch should be inactive after disable");
            var namesAfter = store.ListNames();
            Assert.DoesNotContain(FirewallKillSwitch.RuleNameUdp53, namesAfter);
            Assert.DoesNotContain(FirewallKillSwitch.RuleNameTcp53, namesAfter);
            Assert.DoesNotContain(FirewallKillSwitch.RuleNameTcp853, namesAfter);
        }
        finally
        {
            try { System.IO.File.Delete(backupFile); } catch (System.IO.IOException) { }
        }
    }
}
