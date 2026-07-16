namespace DnsCryptControl.Platform;

/// <summary>Result of a successful <see cref="IProtectionOrchestrator.EnableProtection"/> call.
/// <paramref name="KillSwitchAdvisory"/> is set (non-null) only when the caller asked for the kill
/// switch but the helper refused it for a benign, non-fatal reason (e.g. something else already
/// owns port 53) — protection stays enabled without the kill switch rather than rolling back.</summary>
public sealed record ProtectionOutcome(
    bool KillSwitchEnabled,
    bool LeakMitigationsEnabled,
    bool RebootRecommended,
    string? KillSwitchAdvisory);
