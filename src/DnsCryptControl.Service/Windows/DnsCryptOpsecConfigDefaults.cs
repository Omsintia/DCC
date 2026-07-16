namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Documented dnscrypt-proxy config values that make a global outbound-53 BLOCK kill switch safe.
/// Because Windows Firewall evaluates an explicit BLOCK before any per-app ALLOW, the proxy CANNOT
/// be firewall-exempted on 53 — it must instead run entirely OFF port 53:
/// <list type="bullet">
///   <item><description><c>netprobe_timeout = 0</c> — disables the startup probe that otherwise sends
///   one UDP datagram to 9.9.9.9:53 on Windows at boot.</description></item>
///   <item><description><c>ignore_system_dns = true</c> — the proxy never falls back to the NIC's
///   cleartext system DNS stub.</description></item>
///   <item><description><c>netprobe_address</c> off 53 — if netprobe is ever re-enabled, its address
///   must not target :53 (discard port :9 is safe).</description></item>
/// </list>
/// Encrypted upstreams (DNSCrypt stamp port, commonly 443; DoH = TCP/443) never use 53, and
/// IP-embedded server stamps + cached resolver lists remove any need for plaintext-53 bootstrap.
///
/// These constants are DOCUMENTATION ONLY — the enforcement criteria live in Core's
/// OpsecConfigRules (IC-4), and DnsCryptOpsecConfigDefaultsTests pins these values against that
/// gate so the documented defaults and the gate never diverge. Writing dnscrypt-proxy.toml is
/// Phase 2's WriteConfig responsibility; this type does not emit TOML. The
/// <see cref="TomlProxyConfigSafetyCheck"/> enforces these values as the acceptance criteria for
/// enabling the kill switch.
/// </summary>
public static class DnsCryptOpsecConfigDefaults
{
    /// <summary>dnscrypt-proxy <c>netprobe_timeout</c>: 0 disables the startup connectivity probe entirely.</summary>
    public const int NetprobeTimeout = 0;

    /// <summary>dnscrypt-proxy <c>ignore_system_dns</c>: true so the proxy never emits cleartext queries via the OS stub.</summary>
    public const bool IgnoreSystemDns = true;

    /// <summary>dnscrypt-proxy <c>netprobe_address</c>: off port 53 (discard port :9) in case netprobe is re-enabled.</summary>
    public const string NetprobeAddress = "9.9.9.9:9";
}
