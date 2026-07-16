using System.Net;
using CsCheck;
using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Structural fuzz properties for accepted <c>sdns://</c> stamps - the tier beyond the totality
/// oracle in <see cref="ServerStampParserProperties"/>. Totality proves TryParse never throws;
/// THIS file proves that WHEN TryParse returns true (accepts a hostile-but-well-framed stamp) the
/// decoded <see cref="ServerStamp"/> satisfies every documented per-field guarantee, so no downstream
/// consumer (the latency prober, the kill-switch classifier, the TOML writer, the UI) can be handed a
/// value that violates its own precondition:
/// <list type="bullet">
///   <item>AddressIp, when present, is the EXACT canonical IP literal the IC-15 prober will dial -
///     <see cref="IPAddress.TryParse"/> succeeds and its ToString round-trips to the same string
///     (never a hostname, never a leading-zero / short-dotted / integer / scoped form).</item>
///   <item>Port is always in 1..65535 (a per-type default is applied, but is itself in range).</item>
///   <item>A DNSCrypt PublicKey is null or EXACTLY 32 bytes; every Hashes element is EXACTLY 32 bytes -
///     a hostile length would crash the proxy at load (the reference Fatalf's later).</item>
///   <item>Every string field (ProviderName / Hostname / Path / each BootstrapIp) is control-character
///     free - a <c>\n[sources]</c> payload must never reach the TOML writer or the UI.</item>
/// </list>
/// Generators reach accepted stamps two ways: valid base64url over random bytes (broad, hostile
/// framing) and hand-framed byte layouts probing 32-byte length games plus non-canonical IPs.
/// See the fuzzing design notes.
/// </summary>
public class ServerStampStructureProperties
{
    // Every recognized protocol id (byte 0). Hoisted to satisfy CA1861 (no inline constant arrays)
    // and reused by the framed-layout generator so the dispatch table is exercised uniformly.
    private static readonly byte[] ProtocolBytes =
    {
        (byte)StampProtocol.PlainDns, (byte)StampProtocol.DnsCrypt, (byte)StampProtocol.DoH,
        (byte)StampProtocol.DoT, (byte)StampProtocol.DoQ, (byte)StampProtocol.ODoHTarget,
        (byte)StampProtocol.DnsCryptRelay, (byte)StampProtocol.ODoHRelay,
    };

    // ------------------------------------------------------------------ broad base64url fuzz

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Accepted_stamps_from_random_bytes_satisfy_all_structural_invariants() =>
        // Valid base64url over random bytes: most are rejected, but the ones that ARE accepted
        // arrive with arbitrary props/addr/hashes/framing - exactly the accepted set whose fields
        // must hold every guarantee. Rejection is a valid outcome; only an accepted-yet-invalid
        // stamp (or a throw) fails the property.
        Gen.Byte.Array.Select(b => "sdns://" + Base64Url(b))
            .Sample(AcceptedStampIsStructurallySound, iter: Fuzz.Iter);

    // ------------------------------------------------------------------ hand-framed layouts

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Accepted_framed_stamps_satisfy_all_structural_invariants() =>
        // Deliberately well-framed layouts: a chosen protocol byte, a length-prefixed address drawn
        // from a pool that mixes canonical and NON-canonical IP literals (leading-zero, short-dotted,
        // integer, hostname, scoped, bracketed), and a public-key / hash region whose length is chosen
        // AROUND the 32-byte boundary (31/32/33). This concentrates draws on the exact acceptance edges
        // the broad fuzz reaches only rarely, so the canonical-IP and 32-byte oracles get real pressure.
        FramedStampGen.Select(Base64Url).Select(b64 => "sdns://" + b64)
            .Sample(AcceptedStampIsStructurallySound, iter: Fuzz.Iter);

    // ------------------------------------------------------------------ the oracle

    /// <summary>The structural oracle. Folds the TryParse bool in (CA1806: never discard a Try* result):
    /// a rejected stamp passes vacuously (rejection is the fail-closed outcome for hostile input); an
    /// ACCEPTED stamp must be non-null and satisfy every documented field guarantee - any violation
    /// makes this return false and CsCheck shrinks the reproducer.</summary>
    private static bool AcceptedStampIsStructurallySound(string input)
    {
        if (!ServerStampParser.TryParse(input, out var stamp, out _))
            return true; // rejected: nothing to check (totality is asserted elsewhere)
        return stamp is not null && StampIsSound(stamp);
    }

    private static bool StampIsSound(ServerStamp s) =>
        AddressIpIsCanonicalOrNull(s.AddressIp)
        && s.Port is >= 1 and <= 65535
        && PublicKeyIsNullOrExactly32(s.PublicKey)
        && AllHashesAreExactly32(s.Hashes)
        && NoControlChars(s.ProviderName)
        && NoControlChars(s.Hostname)
        && NoControlChars(s.Path)
        && AllBootstrapIpsAreControlCharFree(s.BootstrapIps);

    /// <summary>AddressIp is either null (hostname-only) or the exact canonical IP literal the prober
    /// dials: it parses as an IPAddress AND round-trips through ToString to the identical string. This
    /// rejects every leniency IPAddress.TryParse allows on its own (1.2, 010.0.0.1, 2130706433, %zone).</summary>
    private static bool AddressIpIsCanonicalOrNull(string? ip)
    {
        if (ip is null) return true;
        return IPAddress.TryParse(ip, out var parsed)
            && parsed.ToString().Equals(ip, StringComparison.Ordinal);
    }

    private static bool PublicKeyIsNullOrExactly32(byte[]? pk) => pk is null || pk.Length == 32;

    private static bool AllHashesAreExactly32(IReadOnlyList<byte[]> hashes)
    {
        foreach (var h in hashes)
            if (h.Length != 32) return false;
        return true;
    }

    private static bool AllBootstrapIpsAreControlCharFree(IReadOnlyList<string> ips)
    {
        foreach (var ip in ips)
            if (!NoControlChars(ip)) return false;
        return true;
    }

    /// <summary>A decoded string field must carry no control characters - the parser's TryDecodeString
    /// enforces valid UTF-8 with no control chars precisely so a hostile <c>\n[sources]</c> provider
    /// name can never reach the TOML writer or the UI. Null (field absent) trivially holds.</summary>
    private static bool NoControlChars(string? value)
    {
        if (value is null) return true;
        foreach (var c in value)
            if (char.IsControl(c)) return false;
        return true;
    }

    // ------------------------------------------------------------------ regression anchors

    [Theory]
    // A DoH stamp whose addr is a 32-byte-looking but non-canonical literal must be rejected, so no
    // accepted stamp can carry it; but where a canonical IP survives, AddressIp must equal it exactly.
    [InlineData("sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", "1.0.0.1")]
    [InlineData("sdns://AAEAAAAAAAAABzguOC44Ljg", "8.8.8.8")]                 // plain DNS, canonical v4
    [InlineData("sdns://gR9bMjYwNDo5YTAwOjIwMTA6YTBiYjo2Ojo1M106NDQz", "2604:9a00:2010:a0bb:6::53")] // relay, canonical v6
    public void Accepted_stamp_addressIp_is_canonical_and_round_trips(string stampStr, string expectedIp)
    {
        Assert.True(ServerStampParser.TryParse(stampStr, out var s, out var err), err.ToString());
        Assert.NotNull(s);
        Assert.Equal(expectedIp, s!.AddressIp);
        Assert.True(AddressIpIsCanonicalOrNull(s.AddressIp));
        // The stored literal is EXACTLY what IPAddress round-trips to - what the prober dials.
        Assert.Equal(IPAddress.Parse(s.AddressIp!).ToString(), s.AddressIp);
    }

    [Theory]
    // DNSCrypt public key is exactly 32 bytes; ODoH target carries none (null).
    [InlineData("sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0", 32)]
    [InlineData("sdns://BQcAAAAAAAAAF29kb2guY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk", 0)] // ODoH target: PublicKey null
    public void Accepted_dnscrypt_publicKey_is_exactly_32_bytes_or_null(string stampStr, int expectedLen)
    {
        Assert.True(ServerStampParser.TryParse(stampStr, out var s, out var err), err.ToString());
        Assert.NotNull(s);
        Assert.True(PublicKeyIsNullOrExactly32(s!.PublicKey));
        if (expectedLen == 0) Assert.Null(s.PublicKey);
        else Assert.Equal(expectedLen, s.PublicKey!.Length);
    }

    [Fact]
    public void Accepted_doh_certHash_is_exactly_32_bytes()
    {
        Assert.True(ServerStampParser.TryParse(
            "sdns://AgUAAAAAAAAABzguOC44LjggsKKKE4EwvtIbNjGjagI2607EdKSVHowYZtyvD9iPrkkHOC44LjguOAovZG5zLXF1ZXJ5",
            out var s, out var err), err.ToString());
        Assert.NotNull(s);
        Assert.True(AllHashesAreExactly32(s!.Hashes));
        var hash = Assert.Single(s.Hashes);
        Assert.Equal(32, hash.Length);
    }

    // ------------------------------------------------------------------ generators

    /// <summary>Random dotted-quad-ish and hostile address literals paired around canonical vs not.
    /// Hoisted (CA1861) and drawn by <see cref="FramedStampGen"/> to load the addr field with values
    /// that sit on both sides of the canonical-IP acceptance boundary.</summary>
    private static readonly string[] AddressPool =
    {
        "1.2.3.4",            // canonical v4
        "8.8.8.8:443",        // canonical v4 with port
        "010.0.0.1",          // leading zero -> non-canonical (IPAddress.TryParse would accept, parser rejects)
        "1.2",                // short form -> non-canonical
        "2130706433",         // integer form -> non-canonical
        "0x7f.0.0.1",         // hex octet -> non-canonical
        "[2001:db8::1]",      // bracketed v6 (canonical)
        "2001:db8::1",        // bare v6 -> rejected (reference requires brackets)
        "[fe80::1%eth0]",     // scoped -> rejected
        "not-an-ip",          // hostname -> rejected (AddressIp must never be a hostname)
        "",                   // empty addr (hostname-only path for HTTP-like)
        "1.2.3.4:0",          // port 0 -> rejected
        "1.2.3.4:99999",      // port overflow -> rejected
    };

    // Defined BEFORE FramedStampGen: static field initializers run top-to-bottom, and FramedStampGen
    // captures this generator - a later definition would bind null here (a real init-order defect the
    // nullable analyzer flags as CS8604).
    private static readonly Gen<byte> ProtocolByteGen =
        Gen.Int[0, ProtocolBytes.Length - 1].Select(i => ProtocolBytes[i]);

    /// <summary>Builds a well-framed stamp body: [protocol][8 props][LP addr][LP key-region] where the
    /// key region length is chosen AROUND 32 (28..36) so the 32-byte DNSCrypt-key / hash boundary is hit
    /// often. The layout is only fully valid for DNSCrypt (0x01: props|addr|pk|provider), so most draws
    /// are rejected - but the ones that ARE accepted (canonical addr + 32-byte key + clean provider)
    /// exercise exactly the structural guarantees, and the rejected ones still prove totality.</summary>
    private static readonly Gen<byte[]> FramedStampGen =
        Gen.Select(
            ProtocolByteGen,
            Gen.Int[0, AddressPool.Length - 1],
            Gen.Int[28, 36],
            Gen.Byte.Array[0, 40],
            (proto, addrIdx, keyLen, providerBytes) =>
                FrameDnsCryptLike(proto, AddressPool[addrIdx], keyLen, providerBytes));

    /// <summary>Frames proto | 8 zero props | LP(addr) | LP(key of keyLen zero bytes) | LP(provider).
    /// A structural skeleton: for 0x01 this is the exact DNSCrypt layout, so a canonical addr + 32-byte
    /// key + control-char-free provider is accepted; every other combination is rejected fail-closed.</summary>
    private static byte[] FrameDnsCryptLike(byte proto, string addr, int keyLen, byte[] provider)
    {
        var addrBytes = System.Text.Encoding.UTF8.GetBytes(addr);
        var key = new byte[keyLen];
        // Length prefixes are single bytes; every segment here is < 256, safe to cast.
        var body = new List<byte> { proto };
        for (var i = 0; i < 8; i++) body.Add(0); // props (ignored by relay protocols, which read byte 1 as addr len)
        body.Add((byte)addrBytes.Length);
        body.AddRange(addrBytes);
        body.Add((byte)key.Length);
        body.AddRange(key);
        body.Add((byte)provider.Length);
        body.AddRange(provider);
        return body.ToArray();
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
