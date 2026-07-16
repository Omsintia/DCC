using System.Globalization;
using System.Net;
using DnsCryptControl.Core.Toml;

namespace DnsCryptControl.Core.Validation;

/// <summary>
/// THE single source of the OPSEC-critical dnscrypt-proxy config rules (IC-4 / P5b-E4).
/// Consumers: the Service kill-switch enable gate (<c>TomlProxyConfigSafetyCheck</c>), the
/// helper-side write policy, and the UI editor warnings — sharing this one evaluation is
/// what keeps the guard and the editor from ever diverging.
/// </summary>
public static class OpsecConfigRules
{
    // Stable rule identifiers (consumers key severity/UX decisions off these).
    public const string UnparseableConfigRuleId = "UnparseableConfig";
    public const string NetprobeTimeoutNotZeroRuleId = "NetprobeTimeoutNotZero";
    public const string IgnoreSystemDnsOffRuleId = "IgnoreSystemDnsOff";
    public const string BootstrapResolverOn53RuleId = "BootstrapResolverOn53";
    public const string ListenAddressesOffLoopback53RuleId = "ListenAddressesOffLoopback53";
    public const string NetprobeAddressOn53RuleId = "NetprobeAddressOn53";

    /// <summary>The only safe <c>netprobe_timeout</c>: 0 disables the startup UDP/53 probe entirely.</summary>
    public const long RequiredNetprobeTimeout = 0;

    /// <summary>The only safe <c>ignore_system_dns</c>: true — never fall back to the cleartext OS stub.</summary>
    public const bool RequiredIgnoreSystemDns = true;

    /// <summary>
    /// The listen endpoint protection depends on: the DNS re-point targets loopback:53,
    /// so a PRESENT <c>listen_addresses</c> must include it (absent = dnscrypt-proxy's
    /// own default, which is exactly <c>['127.0.0.1:53']</c>).
    /// </summary>
    public const string RequiredListenAddress = "127.0.0.1:53";

    /// <summary>Suffix marking a plaintext DNS endpoint (host:53) in address-shaped values.</summary>
    private const string PlaintextDnsPortSuffix = ":53";

    /// <summary>
    /// Evaluates every OPSEC rule against <paramref name="doc"/> and returns ALL concerns
    /// found (consumers filter by <see cref="OpsecConcern.Severity"/>). A document with
    /// parse errors yields a single <see cref="OpsecConcernSeverity.KillSwitchCritical"/>
    /// concern — fail-closed: an unparseable config can hide any violation.
    /// </summary>
    public static IReadOnlyList<OpsecConcern> Evaluate(TomlConfigDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);

        if (doc.HasErrors)
        {
            return new[]
            {
                new OpsecConcern(UnparseableConfigRuleId, "(syntax)",
                    $"config has TOML parse errors: {string.Join("; ", doc.Errors)}",
                    OpsecConcernSeverity.KillSwitchCritical),
            };
        }

        var concerns = new List<OpsecConcern>();
        CheckNetprobeTimeout(doc, concerns);
        CheckIgnoreSystemDns(doc, concerns);
        CheckBootstrapResolvers(doc, concerns);
        CheckListenAddresses(doc, concerns);
        CheckNetprobeAddress(doc, concerns);
        return concerns;
    }

    /// <summary>
    /// <c>netprobe_timeout</c> must be present and 0. dnscrypt-proxy's built-in default (60)
    /// sends a cleartext UDP datagram to port 53 at startup, which the kill switch would
    /// block — stranding the proxy. Missing or unreadable (non-integer) values fail closed.
    /// </summary>
    private static void CheckNetprobeTimeout(TomlConfigDocument doc, List<OpsecConcern> concerns)
    {
        if (doc.TryGetLong("netprobe_timeout", out var value) && value == RequiredNetprobeTimeout)
            return;

        var got = doc.TryGetLong("netprobe_timeout", out var v)
            ? v.ToString(CultureInfo.InvariantCulture)
            : "<missing or not an integer>";
        concerns.Add(new OpsecConcern(NetprobeTimeoutNotZeroRuleId, "netprobe_timeout",
            $"netprobe_timeout must be {RequiredNetprobeTimeout} (got {got})",
            OpsecConcernSeverity.KillSwitchCritical));
    }

    /// <summary>
    /// <c>ignore_system_dns</c> must be present and true. dnscrypt-proxy's built-in default
    /// (false) lets the proxy fall back to the NIC's cleartext system DNS stub — a leak
    /// under protection and a strand under the kill switch. Missing or unreadable
    /// (non-boolean) values fail closed.
    /// </summary>
    private static void CheckIgnoreSystemDns(TomlConfigDocument doc, List<OpsecConcern> concerns)
    {
        if (doc.TryGetBool("ignore_system_dns", out var value) && value == RequiredIgnoreSystemDns)
            return;

        var got = doc.TryGetBool("ignore_system_dns", out var v)
            ? v.ToString()
            : "<missing or not a boolean>";
        concerns.Add(new OpsecConcern(IgnoreSystemDnsOffRuleId, "ignore_system_dns",
            $"ignore_system_dns must be true (got {got})",
            OpsecConcernSeverity.KillSwitchCritical));
    }

    /// <summary>
    /// No <c>bootstrap_resolvers</c> entry may end in :53 (plaintext bootstrap — blocked by
    /// the kill switch, stranding resolver-list refreshes). An ABSENT key is safe: with no
    /// bootstrap configured, IP-embedded stamps and cached lists cover startup.
    /// DELIBERATE TIGHTENING (A3, documented in the phase-5b plan): a key that is PRESENT
    /// but not a clean string array (wrong type or mixed element types) is a
    /// KillSwitchCritical "malformed" concern. The pre-5b guard silently SKIPPED that case
    /// (TryGetStringArray returned false and the check passed) — but an unreadable value
    /// can hide a plaintext :53 bootstrap, so it now fails closed.
    /// </summary>
    private static void CheckBootstrapResolvers(TomlConfigDocument doc, List<OpsecConcern> concerns)
    {
        if (doc.GetRaw("bootstrap_resolvers") is null)
            return; // absent = safe

        if (!doc.TryGetStringArray("bootstrap_resolvers", out var resolvers))
        {
            concerns.Add(new OpsecConcern(BootstrapResolverOn53RuleId, "bootstrap_resolvers",
                "bootstrap_resolvers is malformed (expected an array of strings) — unreadable values fail closed",
                OpsecConcernSeverity.KillSwitchCritical));
            return;
        }

        foreach (var entry in resolvers)
        {
            // A :53 entry is a plaintext-DNS leak ONLY when it targets a REMOTE host. A LOOPBACK :53 entry
            // ('127.0.0.1:53', '[::1]:53') is safe — and is the whole point of the kill-switch-safe ODoH
            // bootstrap: the query goes to the proxy's OWN loopback listener and is re-encrypted upstream
            // (DNSCrypt/ODoH on :443); Windows Firewall exempts loopback, so the kill switch never blocks it
            // (proven end-to-end behind an ARMED kill switch — M102/N41). Exempt loopback; flag only remote :53.
            if (entry.EndsWith(PlaintextDnsPortSuffix, StringComparison.Ordinal) && !IsLoopbackEndpoint(entry))
            {
                concerns.Add(new OpsecConcern(BootstrapResolverOn53RuleId, "bootstrap_resolvers",
                    $"bootstrap_resolvers contains a plaintext port-53 entry: '{entry}'",
                    OpsecConcernSeverity.KillSwitchCritical));
            }
        }
    }

    /// <summary>
    /// True when <paramref name="endpoint"/> ("host:port"; IPv6 bracketed as "[::1]:53") has a LOOPBACK
    /// host (127.0.0.0/8 or ::1). A loopback address on :53 is NOT a plaintext-DNS leak: loopback never
    /// leaves the machine (Windows Firewall exempts it, so the kill switch cannot block it) and a query to
    /// the proxy's own loopback listener is re-encrypted upstream. This is exactly what lets a hostname-based
    /// resolver (ODoH) bootstrap behind the armed kill switch. Fail-closed toward FLAGGING: a non-loopback or
    /// unparseable host is NOT exempt, so a real remote :53 leak (even one sitting next to a loopback entry)
    /// still trips the rule.
    /// </summary>
    private static bool IsLoopbackEndpoint(string endpoint)
    {
        var host = endpoint;
        var lastColon = host.LastIndexOf(':');
        if (lastColon > 0)
            host = host[..lastColon]; // strip the trailing ":port"
        host = host.Trim();
        if (host.Length >= 2 && host[0] == '[' && host[^1] == ']')
            host = host[1..^1]; // unwrap "[ipv6]"
        return IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip);
    }

    /// <summary>
    /// A PRESENT <c>listen_addresses</c> must include <see cref="RequiredListenAddress"/>:
    /// protection re-points system DNS at loopback:53, so a proxy not listening there
    /// breaks resolution while protected (the kill switch itself is unaffected —
    /// severity is ProtectionCritical, not KillSwitchCritical). An ABSENT key is safe:
    /// dnscrypt-proxy's built-in default is exactly ['127.0.0.1:53']. A present-but-
    /// unreadable value (wrong type / mixed elements) fails closed as ProtectionCritical.
    /// </summary>
    private static void CheckListenAddresses(TomlConfigDocument doc, List<OpsecConcern> concerns)
    {
        if (doc.GetRaw("listen_addresses") is null)
            return; // absent = safe (default is ['127.0.0.1:53'])

        if (!doc.TryGetStringArray("listen_addresses", out var addresses))
        {
            concerns.Add(new OpsecConcern(ListenAddressesOffLoopback53RuleId, "listen_addresses",
                "listen_addresses is malformed (expected an array of strings) — unreadable values fail closed",
                OpsecConcernSeverity.ProtectionCritical));
            return;
        }

        if (!addresses.Contains(RequiredListenAddress, StringComparer.Ordinal))
        {
            concerns.Add(new OpsecConcern(ListenAddressesOffLoopback53RuleId, "listen_addresses",
                $"listen_addresses does not include '{RequiredListenAddress}' — protection points system DNS at loopback:53, so the proxy must listen there",
                OpsecConcernSeverity.ProtectionCritical));
        }
    }

    /// <summary>
    /// Advisory only: with <c>netprobe_timeout = 0</c> the probe never fires, but a
    /// <c>netprobe_address</c> ending :53 is a landmine if the probe is ever re-enabled.
    /// A non-string value cannot end in :53 and its wrong TYPE is a schema Error
    /// (<c>ConfigValidator</c> flags known-key type mismatches) — no advisory duplicated here.
    /// </summary>
    private static void CheckNetprobeAddress(TomlConfigDocument doc, List<OpsecConcern> concerns)
    {
        if (!doc.TryGetString("netprobe_address", out var address) || address is null)
            return;

        // Same loopback exemption as bootstrap_resolvers: a loopback :53 netprobe_address ('127.0.0.1:53')
        // never leaves the machine even if the probe re-enables, so it is not a plaintext-leak landmine.
        if (address.EndsWith(PlaintextDnsPortSuffix, StringComparison.Ordinal) && !IsLoopbackEndpoint(address))
        {
            concerns.Add(new OpsecConcern(NetprobeAddressOn53RuleId, "netprobe_address",
                $"netprobe_address targets port 53 ('{address}') — if the netprobe is ever re-enabled it would probe over plaintext DNS",
                OpsecConcernSeverity.Advisory));
        }
    }
}
