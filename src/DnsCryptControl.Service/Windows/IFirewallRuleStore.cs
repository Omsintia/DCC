namespace DnsCryptControl.Service.Windows;

/// <summary>Testable seam over the actual firewall backend (Windows Firewall COM API or netsh).
/// The kill-switch add/remove/detect/idempotency logic is driven entirely through this interface,
/// so it can be unit-tested with an in-memory fake while the live COM/netsh stores are
/// exercised only by ManualIntegration tests.</summary>
internal interface IFirewallRuleStore
{
    /// <summary>Add one outbound BLOCK rule. Implementations Remove the same Name first (idempotent).</summary>
    void Add(FirewallRuleDescriptor rule);

    /// <summary>Remove all rules with this exact Name. No effect if absent (idempotent).</summary>
    void Remove(string name);

    /// <summary>Names of all firewall rules currently present (used for kill-switch detection).</summary>
    IReadOnlyCollection<string> ListNames();
}
