using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class FirewallKillSwitchContractTests
{
    private sealed class StubKillSwitch : IFirewallKillSwitch
    {
        private bool _active;

        public PlatformResult SetKillSwitch(bool enable)
        {
            _active = enable;
            return PlatformResult.Ok();
        }

        public bool IsKillSwitchActive() => _active;
    }

    [Fact]
    public void Interface_isImplementable_andToggleReflectsInDetect()
    {
        IFirewallKillSwitch ks = new StubKillSwitch();

        Assert.False(ks.IsKillSwitchActive());

        var on = ks.SetKillSwitch(true);
        Assert.True(on.Success);
        Assert.True(ks.IsKillSwitchActive());

        var off = ks.SetKillSwitch(false);
        Assert.True(off.Success);
        Assert.False(ks.IsKillSwitchActive());
    }
}
