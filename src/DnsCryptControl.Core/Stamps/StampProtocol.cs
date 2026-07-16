namespace DnsCryptControl.Core.Stamps;

/// <summary>
/// DNS Stamp protocol identifier (the first decoded byte of an <c>sdns://</c> payload).
/// Values are the wire constants from the DNS Stamps specification
/// (https://dnscrypt.info/stamps-specifications/); do not renumber.
/// </summary>
public enum StampProtocol : byte
{
    /// <summary>0x00 — plain (unencrypted) DNS.</summary>
    PlainDns = 0x00,

    /// <summary>0x01 — DNSCrypt.</summary>
    DnsCrypt = 0x01,

    /// <summary>0x02 — DNS-over-HTTPS.</summary>
    DoH = 0x02,

    /// <summary>0x03 — DNS-over-TLS.</summary>
    DoT = 0x03,

    /// <summary>0x04 — DNS-over-QUIC.</summary>
    DoQ = 0x04,

    /// <summary>0x05 — Oblivious DoH target.</summary>
    ODoHTarget = 0x05,

    /// <summary>0x81 — anonymized-DNSCrypt relay (NO props field on the wire).</summary>
    DnsCryptRelay = 0x81,

    /// <summary>0x85 — Oblivious DoH relay.</summary>
    ODoHRelay = 0x85,
}
