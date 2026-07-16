using System;
using System.IO;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using DnsCryptControl.Service.Windows.Registry;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class RegistryLeakMitigationPolicyLiveTests
{
    /// <summary>
    /// End-to-end round-trip test against the real HKLM registry and Dnscache SCM.
    /// Requires elevation (LocalSystem or Administrator) to write HKLM policy +
    /// Dnscache\Parameters. Excluded from the CI gate; run manually to verify the live path.
    /// </summary>
    [Fact]
    [Trait("Category", "ManualIntegration")]
    public void Live_enableThenDisable_roundTripsWithoutThrowing()
    {
        var temp = Path.Combine(
            Path.GetTempPath(), "DnsCryptLeakLive_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var backup = new DnsBackupStore(Path.Combine(temp, "backup.json"));
            var policy = new RegistryLeakMitigationPolicy(
                new Registry64Root(),
                backup,
                RegistryLeakMitigationPolicy.BestEffortRestartDnscache);

            var enable = policy.SetLeakMitigations(true);
            Assert.True(enable.Success);
            Assert.True(policy.AreLeakMitigationsEnabled());
            // Dnscache cannot be stopped at runtime → reboot is the expected advisory on real hardware.
            Assert.Equal(RebootAdvisory.Recommended, enable.Value);

            var disable = policy.SetLeakMitigations(false);
            Assert.True(disable.Success);
            Assert.False(policy.AreLeakMitigationsEnabled());
        }
        finally
        {
            try { if (Directory.Exists(temp)) Directory.Delete(temp, recursive: true); } catch (IOException) { }
        }
    }
}
