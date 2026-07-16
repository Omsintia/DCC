using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Live <see cref="IFirewallRuleStore"/> backed by the Windows Defender Firewall COM API, late-bound
/// via ProgIDs (no NetFwTypeLib reference) and driven with <c>dynamic</c> (the COM objects derive
/// from IDispatch). Requires elevation (LocalSystem) and the Windows Firewall service (MpsSvc).
///
/// <para><b>PROPERTY ORDER (mandatory):</b> Protocol MUST be set BEFORE RemotePorts — each property
/// write re-validates the rule and remote ports are invalid without a protocol. Verified order:
/// Name, Description, Direction=2 (OUT), Protocol, RemotePorts, RemoteAddresses="*",
/// Action=0 (BLOCK), Profiles=0x7FFFFFFF (ALL), Enabled=true.</para>
///
/// <para>NOTE: <c>dynamic</c> over COM relies on the DLR (Microsoft.CSharp) and does NOT work under
/// PublishAot/aggressive trimming. The service is a normal JIT CoreCLR publish, so this is fine.</para>
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ComFirewallRuleStore : IFirewallRuleStore
{
    private const int DirectionOutbound = 2;                     // NET_FW_RULE_DIR_OUT
    private const int ActionBlock       = 0;                     // NET_FW_ACTION_BLOCK
    private const int ProfilesAll       = unchecked((int)0x7FFFFFFF); // NET_FW_PROFILE2_ALL

    private static dynamic CreatePolicy()
    {
        var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        return Activator.CreateInstance(t)!;
    }

    public void Add(FirewallRuleDescriptor descriptor)
    {
        dynamic policy = CreatePolicy();
        dynamic rules = policy.Rules;

        // Idempotent: drop any stale same-named rule first (no effect if absent).
        try { rules.Remove(descriptor.Name); }
        catch (COMException) { /* absent */ }

        var rt = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        dynamic rule = Activator.CreateInstance(rt)!;

        // Property order is load-bearing: Protocol MUST precede RemotePorts.
        rule.Name            = descriptor.Name;
        rule.Description     = descriptor.Description;
        rule.Direction       = DirectionOutbound;         // OUT
        rule.Protocol        = descriptor.Protocol;       // MUST be set before RemotePorts
        rule.RemotePorts     = descriptor.RemotePorts;    // after Protocol
        rule.RemoteAddresses = "*";                       // all remote addresses
        rule.Action          = ActionBlock;               // BLOCK
        rule.Profiles        = ProfilesAll;               // all profiles
        rule.Enabled         = true;

        rules.Add(rule);
    }

    public void Remove(string name)
    {
        dynamic policy = CreatePolicy();
        dynamic rules = policy.Rules;
        try { rules.Remove(name); }
        catch (COMException) { /* absent or denied; Remove is a no-op if the rule is missing */ }
    }

    public IReadOnlyCollection<string> ListNames()
    {
        dynamic policy = CreatePolicy();
        dynamic rules = policy.Rules;
        var names = new List<string>();
        foreach (dynamic r in rules)
        {
            string rn;
            try { rn = r.Name; }
            catch (Exception) { continue; } // foreign/corrupt rule throws on property read
            names.Add(rn);
        }
        return names;
    }
}
