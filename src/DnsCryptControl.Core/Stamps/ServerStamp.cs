namespace DnsCryptControl.Core.Stamps;

/// <summary>
/// A decoded DNS Stamp (<c>sdns://…</c>). Fields not carried by a given protocol are
/// null/empty. Parsing is fail-closed and never throws on hostile input — see
/// <see cref="ServerStampParser"/>. This is a pure data record; no I/O.
/// </summary>
/// <param name="Protocol">The stamp protocol (first decoded byte).</param>
/// <param name="Props">
/// Raw 64-bit informal-properties bitfield (0 for <see cref="StampProtocol.DnsCryptRelay"/>,
/// which has no props field). Bits 3..63 are preserved verbatim.
/// </param>
/// <param name="AddressIp">
/// The IP literal to connect to (for latency probing — IC-15), or null when the stamp is
/// hostname-only (all ODoH targets; empty-addr DoH/DoT/DoQ/ODoH relays). Never a hostname.
/// </param>
/// <param name="Port">The effective endpoint port (per-type default applied) — drives kill-switch classification.</param>
/// <param name="PublicKey">The DNSCrypt provider public key (exactly 32 bytes), else null.</param>
/// <param name="ProviderName">The DNSCrypt provider name, else null.</param>
/// <param name="Hashes">TLS certificate hashes (DoH/DoT/DoQ/ODoH relay); each is 32 bytes.</param>
/// <param name="Hostname">The server hostname (DoH/DoT/DoQ/ODoH), used as SNI; display only, never a probe target.</param>
/// <param name="Path">The URL path (DoH/ODoH), else null.</param>
/// <param name="BootstrapIps">Bootstrap resolver IP strings (DoH/DoT/DoQ/ODoH relay), else empty.</param>
/// <param name="MasterStrictWarning">
/// True when the stamp is legal under the shipped dnscrypt-proxy 2.1.16 parser but would be
/// rejected by the stricter upstream master parser (advisory — not a rejection).
/// </param>
public sealed record ServerStamp(
    StampProtocol Protocol,
    ulong Props,
    string? AddressIp,
    int Port,
    byte[]? PublicKey,
    string? ProviderName,
    IReadOnlyList<byte[]> Hashes,
    string? Hostname,
    string? Path,
    IReadOnlyList<string> BootstrapIps,
    bool MasterStrictWarning)
{
    /// <summary>Property bit 0: the server supports DNSSEC.</summary>
    public bool Dnssec => (Props & 1) != 0;

    /// <summary>Property bit 1: the server does not keep logs.</summary>
    public bool NoLog => (Props & 2) != 0;

    /// <summary>Property bit 2: the server does not intentionally block domains.</summary>
    public bool NoFilter => (Props & 4) != 0;

    /// <summary>True for the relay protocols (0x81, 0x85) — routed via, never used as an upstream.</summary>
    public bool IsRelay => Protocol is StampProtocol.DnsCryptRelay or StampProtocol.ODoHRelay;

    /// <summary>True when this stamp carries an IP literal that a latency probe may target (IC-15).</summary>
    public bool IsProbeable => AddressIp is not null;
}
