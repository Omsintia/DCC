using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class ProxyServiceContractTests
{
    private sealed class StubController : IProxyServiceController
    {
        public PlatformResult<ProxyServiceState> GetState() => PlatformResult<ProxyServiceState>.Ok(ProxyServiceState.Stopped);
        public PlatformResult Install() => PlatformResult.Ok();
        public PlatformResult Uninstall() => PlatformResult.Ok();
        public PlatformResult Start() => PlatformResult.Ok();
        public PlatformResult Stop() => PlatformResult.Ok();
        public PlatformResult Restart() => PlatformResult.Ok();
    }

    [Fact]
    public void Interface_isImplementableAndReturnsExpectedShapes()
    {
        IProxyServiceController c = new StubController();
        Assert.True(c.Install().Success);
        Assert.True(c.Start().Success);
        var state = c.GetState();
        Assert.True(state.Success);
        Assert.Equal(ProxyServiceState.Stopped, state.Value);
    }

    [Fact]
    public void State_enum_hasTheLifecycleMembers()
    {
        foreach (var s in new[]
        {
            ProxyServiceState.NotInstalled, ProxyServiceState.Stopped, ProxyServiceState.StartPending,
            ProxyServiceState.Running, ProxyServiceState.StopPending, ProxyServiceState.Unknown,
        })
        {
            Assert.True(System.Enum.IsDefined(s));
        }
    }
}
