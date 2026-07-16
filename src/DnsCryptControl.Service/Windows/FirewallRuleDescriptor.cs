namespace DnsCryptControl.Service.Windows;

/// <summary>A single outbound BLOCK firewall rule for the DNS kill switch, in store-neutral form.
/// <see cref="Protocol"/> is the IANA protocol number (TCP=6, UDP=17); <see cref="RemotePorts"/>
/// is the destination port list string ("53" / "853").</summary>
public sealed record FirewallRuleDescriptor(string Name, string Description, int Protocol, string RemotePorts);
