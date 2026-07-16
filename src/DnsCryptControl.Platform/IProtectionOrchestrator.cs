namespace DnsCryptControl.Platform;

/// <summary>Owns the single atomic enable/disable operation across the proxy, loopback DNS,
/// leak mitigations, kill switch, and the persisted protection intent. Implementations MUST
/// preserve the leak-safe invariants: intent is persisted before any core step runs (so a crash
/// mid-apply still re-asserts loopback on boot), and DNS is only ever restored as part of a full
/// teardown that also stops the proxy — never as a partial rollback that leaves DNS un-loopback
/// while the proxy is still configured.</summary>
public interface IProtectionOrchestrator
{
    /// <summary>Enable protection: start the proxy, pin DNS to loopback, apply leak mitigations,
    /// and (optionally) the firewall kill switch. Rolls back and clears intent on a hard failure
    /// of a core step; a benign kill-switch refusal is reported as success-with-advisory instead.</summary>
    PlatformResult<ProtectionOutcome> EnableProtection(bool withKillSwitch);

    /// <summary>Disable protection: tear down the kill switch, leak mitigations, DNS loopback, and
    /// the proxy, then clear the persisted intent last.</summary>
    PlatformResult DisableProtection();
}
