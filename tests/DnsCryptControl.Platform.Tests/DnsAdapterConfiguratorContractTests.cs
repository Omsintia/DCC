using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class DnsAdapterConfiguratorContractTests
{
    private sealed class StubConfigurator : IDnsAdapterConfigurator
    {
        public bool Applied { get; set; }

        public PlatformResult ApplyLoopbackToAllAdapters()
        {
            Applied = true;
            return PlatformResult.Ok();
        }

        public PlatformResult ReassertLoopback() => PlatformResult.Ok();

        public PlatformResult RestoreDns()
        {
            Applied = false;
            return PlatformResult.Ok();
        }

        public bool IsLoopbackApplied() => Applied;
    }

    [Fact]
    public void Interface_isImplementable_andApplyReportsSuccess()
    {
        IDnsAdapterConfigurator c = new StubConfigurator();
        Assert.False(c.IsLoopbackApplied());

        var apply = c.ApplyLoopbackToAllAdapters();
        Assert.True(apply.Success);
        Assert.True(c.IsLoopbackApplied());
    }

    [Fact]
    public void Reassert_and_Restore_returnExpectedShapes()
    {
        IDnsAdapterConfigurator c = new StubConfigurator();
        c.ApplyLoopbackToAllAdapters();

        Assert.True(c.ReassertLoopback().Success);

        var restore = c.RestoreDns();
        Assert.True(restore.Success);
        Assert.False(c.IsLoopbackApplied());
    }
}
