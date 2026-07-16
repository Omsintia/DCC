using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Tests;

internal sealed class FakeLeakMitigationPolicy : ILeakMitigationPolicy
{
    public bool? LastEnableArg { get; private set; }
    public bool Enabled { get; set; }
    public PlatformErrorKind? FailWith { get; set; }
    public RebootAdvisory AdvisoryToReturn { get; set; } = RebootAdvisory.None;

    public PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable)
    {
        LastEnableArg = enable;
        if (FailWith is { } kind)
            return PlatformResult<RebootAdvisory>.Fail(kind, "leak mitigation failed");
        Enabled = enable;
        return PlatformResult<RebootAdvisory>.Ok(AdvisoryToReturn);
    }

    public bool AreLeakMitigationsEnabled() => Enabled;
}
