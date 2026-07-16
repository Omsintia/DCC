using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class BrowserDohPolicyContractTests
{
    private sealed class FakeBrowserDohPolicy : IBrowserDohPolicy
    {
        private bool _applied;

        public PlatformResult SetBrowserDohPolicy(bool enable)
        {
            _applied = enable;
            return PlatformResult.Ok();
        }

        public bool IsBrowserDohPolicyApplied() => _applied;
    }

    [Fact]
    public void Interface_isImplementable_andTogglesAppliedState()
    {
        IBrowserDohPolicy policy = new FakeBrowserDohPolicy();

        Assert.False(policy.IsBrowserDohPolicyApplied());

        var enabled = policy.SetBrowserDohPolicy(true);
        Assert.True(enabled.Success);
        Assert.Equal(PlatformErrorKind.None, enabled.Error);
        Assert.True(policy.IsBrowserDohPolicyApplied());

        var disabled = policy.SetBrowserDohPolicy(false);
        Assert.True(disabled.Success);
        Assert.False(policy.IsBrowserDohPolicyApplied());
    }
}
