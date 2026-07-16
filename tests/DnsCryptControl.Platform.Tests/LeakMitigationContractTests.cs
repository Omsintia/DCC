using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class LeakMitigationContractTests
{
    private sealed class StubPolicy : ILeakMitigationPolicy
    {
        public bool Enabled { get; set; }
        public RebootAdvisory AdvisoryToReturn { get; set; } = RebootAdvisory.None;

        public PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable)
        {
            Enabled = enable;
            return PlatformResult<RebootAdvisory>.Ok(AdvisoryToReturn);
        }

        public bool AreLeakMitigationsEnabled() => Enabled;
    }

    [Fact]
    public void Interface_isImplementable_andReturnsExpectedShapes()
    {
        ILeakMitigationPolicy p = new StubPolicy { AdvisoryToReturn = RebootAdvisory.Recommended };

        var set = p.SetLeakMitigations(true);

        Assert.True(set.Success);
        Assert.Equal(RebootAdvisory.Recommended, set.Value);
        Assert.True(p.AreLeakMitigationsEnabled());
    }

    [Fact]
    public void SetLeakMitigations_false_disables_andReportsNoRebootByDefault()
    {
        ILeakMitigationPolicy p = new StubPolicy { Enabled = true };

        var set = p.SetLeakMitigations(false);

        Assert.True(set.Success);
        Assert.Equal(RebootAdvisory.None, set.Value);
        Assert.False(p.AreLeakMitigationsEnabled());
    }

    [Fact]
    public void RebootAdvisory_enum_hasNoneAndRecommended()
    {
        Assert.True(System.Enum.IsDefined(RebootAdvisory.None));
        Assert.True(System.Enum.IsDefined(RebootAdvisory.Recommended));
    }
}
