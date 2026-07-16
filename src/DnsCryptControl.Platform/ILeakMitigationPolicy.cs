namespace DnsCryptControl.Platform;

/// <summary>Writes/clears the SMHNR + parallel-A/AAAA registry leak mitigations (HKLM policy +
/// Dnscache\Parameters). Captures prior values for exact revert. Dnscache cannot be stopped at
/// runtime, so changes take effect on next Dnscache start → may return RebootAdvisory.Recommended.</summary>
public interface ILeakMitigationPolicy
{
    PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable);
    bool AreLeakMitigationsEnabled();
}
