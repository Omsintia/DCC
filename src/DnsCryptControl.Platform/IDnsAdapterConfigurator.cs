namespace DnsCryptControl.Platform;

/// <summary>Sets every eligible network interface's DNS to the loopback proxy (IPv4 127.0.0.1 +
/// IPv6 ::1), statically, and restores prior per-interface DNS from the backup. Impl runs as SYSTEM.</summary>
public interface IDnsAdapterConfigurator
{
    /// <summary>Capture prior per-interface DNS into the backup (idempotent), then set loopback DNS
    /// (v4+v6) statically on every eligible adapter. First call writes the backup; later calls do not
    /// overwrite an existing un-restored backup.</summary>
    PlatformResult ApplyLoopbackToAllAdapters();

    /// <summary>Re-assert loopback DNS on every eligible adapter WITHOUT touching the backup. Used by
    /// the network-change watcher and the boot reconciler. Safe to call repeatedly.</summary>
    PlatformResult ReassertLoopback();

    /// <summary>Restore every modified interface from the backup (prior static servers, or revert to
    /// DHCP/automatic if it was DHCP), then clear the interface slice of the backup. Idempotent.</summary>
    PlatformResult RestoreDns();

    /// <summary>True if at least one interface is currently recorded as loopback-locked in the backup.</summary>
    bool IsLoopbackApplied();
}
