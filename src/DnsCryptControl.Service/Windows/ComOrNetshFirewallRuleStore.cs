using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Production <see cref="IFirewallRuleStore"/> composite: the Windows Defender Firewall COM API
/// (<see cref="ComFirewallRuleStore"/>) is the primary backend, with <see cref="NetshFirewallRuleStore"/>
/// as a fallback for the mutating Add/Remove paths when the COM API is unavailable (e.g. MpsSvc not
/// reachable / COM activation fails). This is the composite I3 registers for <see cref="IFirewallKillSwitch"/>.
///
/// <para><b>Add / Remove:</b> attempt the COM backend first; on a COM-activation/invocation failure
/// (<see cref="COMException"/>) retry through netsh. Either backend is idempotent (Remove-before-Add,
/// no effect if absent), so a COM partial failure followed by a netsh retry cannot corrupt state.</para>
///
/// <para><b>ListNames (detection authority):</b> only the COM backend can enumerate rule names; netsh
/// text parsing is intentionally not implemented (<see cref="NetshFirewallRuleStore.ListNames"/> throws).
/// ListNames therefore always goes to COM. <see cref="FirewallKillSwitch.IsKillSwitchActive"/> already
/// treats a COMException from enumeration as "inactive" (fail-safe for status reporting), so a hard
/// COM-unavailable environment degrades to "kill switch reported inactive" rather than throwing.</para>
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ComOrNetshFirewallRuleStore : IFirewallRuleStore
{
    private readonly IFirewallRuleStore _com;
    private readonly IFirewallRuleStore _netsh;

    /// <summary>Production ctor: real COM primary + real netsh fallback.</summary>
    public ComOrNetshFirewallRuleStore()
        : this(new ComFirewallRuleStore(), new NetshFirewallRuleStore())
    {
    }

    /// <summary>Test/seam ctor: inject the two backends to exercise the COM→netsh fallback routing.</summary>
    internal ComOrNetshFirewallRuleStore(IFirewallRuleStore com, IFirewallRuleStore netsh)
    {
        ArgumentNullException.ThrowIfNull(com);
        ArgumentNullException.ThrowIfNull(netsh);
        _com = com;
        _netsh = netsh;
    }

    public void Add(FirewallRuleDescriptor rule)
    {
        try
        {
            _com.Add(rule);
        }
        catch (COMException)
        {
            // COM API unavailable (activation/invocation failure) — fall back to netsh.
            _netsh.Add(rule);
        }
    }

    public void Remove(string name)
    {
        try
        {
            _com.Remove(name);
        }
        catch (COMException)
        {
            _netsh.Remove(name);
        }
    }

    public IReadOnlyCollection<string> ListNames() =>
        // COM is the sole detection authority (netsh cannot enumerate). FirewallKillSwitch wraps
        // this call and maps a COMException to "inactive", so no netsh fallback is meaningful here.
        _com.ListNames();
}
