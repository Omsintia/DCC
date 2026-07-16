using System;
using System.IO;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using DnsCryptControl.Service.Windows.Registry;
using Xunit;

namespace DnsCryptControl.Service.Tests;

// Touches the real HKLM\SOFTWARE\Policies hive (Registry64 view). Requires Administrator/LocalSystem.
// Excluded from the default run by the Category filter; run manually to verify the live path.
public class BrowserDohPolicyLiveTests
{
    [Fact]
    [Trait("Category", "ManualIntegration")]
    public void Enable_thenRevert_leavesChromeEdgeModeUnset_onLiveRegistry()
    {
        var temp = Path.Combine(Path.GetTempPath(), "DnsCryptCtlDohLive_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var backup = new DnsBackupStore(Path.Combine(temp, "backup.json"));
            var reg = new Registry64Root();
            var policy = new BrowserDohPolicy(reg, backup);

            Assert.True(policy.SetBrowserDohPolicy(true).Success);
            Assert.True(policy.IsBrowserDohPolicyApplied());

            Assert.True(policy.SetBrowserDohPolicy(false).Success);

            // After revert on an otherwise-clean test box, the value we created is gone.
            // Registry64Root is stateless; each OpenSubKey call owns and disposes its base key internally.
            var chromeRoot = new Registry64Root();
            using var chrome = chromeRoot.OpenSubKey(BrowserDohPolicy.ChromeKey, writable: false);
            Assert.Null(chrome?.GetValue("DnsOverHttpsMode"));
        }
        finally
        {
            try { if (Directory.Exists(temp)) Directory.Delete(temp, recursive: true); } catch (IOException) { }
        }
    }
}
