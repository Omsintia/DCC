namespace DnsCryptControl.Platform;

/// <summary>Records the user's PROTECTION INTENT durably so the privileged host can fail-closed
/// re-assert it after a crash or reboot (consumed by boot reconciliation and the network-change
/// watcher, both of which gate on the persisted <c>ProtectionEnabled</c> flag). The IPC handlers live
/// in the Ipc assembly, which cannot see the Service's state store; this Platform seam lets them record
/// intent without a Service reference. Implementations MUST persist atomically and surface a write
/// failure as a non-success <see cref="PlatformResult"/> so the calling handler can fail closed.</summary>
public interface IProtectionStateWriter
{
    /// <summary>Mark core (loopback-DNS) protection ENABLED. Called BEFORE the loopback apply, so a crash
    /// mid-apply still re-asserts on boot (fail-closed).</summary>
    PlatformResult EnableProtection();

    /// <summary>Mark core protection DISABLED. Called only AFTER a successful RestoreDns, so a crash
    /// mid-restore still re-asserts loopback on boot (fail-closed).</summary>
    PlatformResult DisableProtection();

    /// <summary>Record whether the firewall kill switch is active. Called AFTER a successful
    /// SetKillSwitch so persisted intent matches reality.</summary>
    PlatformResult SetKillSwitchEnabled(bool enabled);

    /// <summary>Record whether registry leak mitigations are active. Called AFTER a successful
    /// SetLeakMitigations so persisted intent matches reality.</summary>
    PlatformResult SetLeakMitigationsEnabled(bool enabled);
}
