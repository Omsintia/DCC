using System.Text;
using DnsCryptControl.Core.Stamps;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A2: <see cref="ServerStampParser"/>. Golden vectors were independently re-decoded by two
/// separate implementations (15/15 match — research/phase5c/verified-surfaces-open-items.md)
/// and are frozen here. Adversarial classes pin the fail-closed contract: hostile input
/// yields a typed error, never a throw and never a silent misparse.
/// </summary>
public class ServerStampParserTests
{
    // ------------------------------------------------------------------ golden corpus

    public static IEnumerable<object[]> GoldenVectors() => new[]
    {
        new object[] { "cloudflare", "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", StampProtocol.DoH },
        new object[] { "cloudflare-ipv6", "sdns://AgcAAAAAAAAAFlsyNjA2OjQ3MDA6NDcwMDo6MTExMV0AGlsyNjA2OjQ3MDA6NDcwMDo6MTExMV06NDQzCi9kbnMtcXVlcnk", StampProtocol.DoH },
        new object[] { "google", "sdns://AgUAAAAAAAAABzguOC44LjggsKKKE4EwvtIbNjGjagI2607EdKSVHowYZtyvD9iPrkkHOC44LjguOAovZG5zLXF1ZXJ5", StampProtocol.DoH },
        new object[] { "quad9-dnscrypt", "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0", StampProtocol.DnsCrypt },
        new object[] { "anon-cs-de", "sdns://gQ8xNDYuNzAuODIuMzo0NDM", StampProtocol.DnsCryptRelay },
        new object[] { "anon-kama", "sdns://gQ4xMzcuNzQuMjIzLjIzNA", StampProtocol.DnsCryptRelay },
        new object[] { "anon-cs-dc6", "sdns://gR9bMjYwNDo5YTAwOjIwMTA6YTBiYjo2Ojo1M106NDQz", StampProtocol.DnsCryptRelay },
        new object[] { "odoh-cloudflare", "sdns://BQcAAAAAAAAAF29kb2guY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk", StampProtocol.ODoHTarget },
        new object[] { "odoh-crypto-sx", "sdns://BQcAAAAAAAAADm9kb2guY3J5cHRvLnN4Ci9kbnMtcXVlcnk", StampProtocol.ODoHTarget },
        new object[] { "odohrelay-edgecompute", "sdns://hQcAAAAAAAAAAAAab2RvaC1yZWxheS5lZGdlY29tcHV0ZS5hcHABLw", StampProtocol.ODoHRelay },
        new object[] { "odohrelay-numa", "sdns://hQcAAAAAAAAAAAASb2RvaC1yZWxheS5udW1hLnJzBi9yZWxheQ", StampProtocol.ODoHRelay },
        new object[] { "odoh-tiar", "sdns://BQMAAAAAAAAADGRvaC50aWFyLmFwcAUvb2RvaA", StampProtocol.ODoHTarget },
        new object[] { "plain-8.8.8.8", "sdns://AAEAAAAAAAAABzguOC44Ljg", StampProtocol.PlainDns },
        new object[] { "dot-quad9", "sdns://AwcAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQ", StampProtocol.DoT },
        new object[] { "doq-adguard", "sdns://BAUAAAAAAAAADDk0LjE0MC4xNC4xNAAPZG5zLmFkZ3VhcmQuY29t", StampProtocol.DoQ },
    };

    [Theory]
    [MemberData(nameof(GoldenVectors))]
    public void TryParse_goldenVectors_parseWithExpectedProtocol(string name, string stampStr, StampProtocol expected)
    {
        Assert.True(ServerStampParser.TryParse(stampStr, out var stamp, out var error), $"{name}: {error}");
        Assert.False(error.IsError);
        Assert.NotNull(stamp);
        Assert.Equal(expected, stamp!.Protocol);
    }

    [Fact]
    public void TryParse_cloudflareDoH_decodesEveryField()
    {
        Assert.True(ServerStampParser.TryParse(
            "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", out var s, out _));
        Assert.Equal(StampProtocol.DoH, s!.Protocol);
        Assert.True(s.Dnssec);
        Assert.True(s.NoLog);
        Assert.True(s.NoFilter);
        Assert.Equal("1.0.0.1", s.AddressIp);
        Assert.Empty(s.Hashes);
        Assert.Equal("dns.cloudflare.com", s.Hostname);
        Assert.Equal("/dns-query", s.Path);
        Assert.True(s.IsProbeable);
    }

    [Fact]
    public void TryParse_googleDoH_decodesTheCertHash_andPropsWithoutNoLog()
    {
        Assert.True(ServerStampParser.TryParse(
            "sdns://AgUAAAAAAAAABzguOC44LjggsKKKE4EwvtIbNjGjagI2607EdKSVHowYZtyvD9iPrkkHOC44LjguOAovZG5zLXF1ZXJ5", out var s, out _));
        Assert.True(s!.Dnssec);
        Assert.False(s.NoLog);   // props = 5 (bit 1 clear)
        Assert.True(s.NoFilter);
        Assert.Equal("8.8.8.8", s.AddressIp);
        var hash = Assert.Single(s.Hashes);
        Assert.Equal("b0a28a138130bed21b3631a36a0236eb4ec474a4951e8c1866dcaf0fd88fae49", Hex(hash));
    }

    [Fact]
    public void TryParse_quad9DnsCrypt_decodesKeyProviderAndPort()
    {
        Assert.True(ServerStampParser.TryParse(
            "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0", out var s, out _));
        Assert.Equal(StampProtocol.DnsCrypt, s!.Protocol);
        Assert.True(s.Dnssec);
        Assert.True(s.NoLog);
        Assert.False(s.NoFilter);   // props = 3
        Assert.Equal("9.9.9.9", s.AddressIp);
        Assert.Equal(8443, s.Port);
        Assert.NotNull(s.PublicKey);
        Assert.Equal(32, s.PublicKey!.Length);
        Assert.Equal("67c847b8c8758cd120245543be756746df34df1d84c00b8c470368df821d863e", Hex(s.PublicKey));
        Assert.Equal("2.dnscrypt-cert.quad9.net", s.ProviderName);
    }

    [Fact]
    public void TryParse_relay_hasNoPropsField_andParsesAddress()
    {
        // 0x81's byte 1 is the addr length, NOT the first of 8 props bytes — a parser that
        // skips 8 props on a relay misframes every entry in relays.md.
        Assert.True(ServerStampParser.TryParse("sdns://gQ8xNDYuNzAuODIuMzo0NDM", out var s, out _));
        Assert.Equal(StampProtocol.DnsCryptRelay, s!.Protocol);
        Assert.True(s.IsRelay);
        Assert.Equal(0UL, s.Props);
        Assert.False(s.Dnssec);
        Assert.Equal("146.70.82.3", s.AddressIp);
        Assert.Equal(443, s.Port);
    }

    [Fact]
    public void TryParse_relayPortless_appliesDefaultPort()
    {
        Assert.True(ServerStampParser.TryParse("sdns://gQ4xMzcuNzQuMjIzLjIzNA", out var s, out _));
        Assert.Equal("137.74.223.234", s!.AddressIp);
        Assert.Equal(443, s.Port);
    }

    [Fact]
    public void TryParse_relayIpv6_stripsBrackets()
    {
        Assert.True(ServerStampParser.TryParse("sdns://gR9bMjYwNDo5YTAwOjIwMTA6YTBiYjo2Ojo1M106NDQz", out var s, out _));
        Assert.Equal("2604:9a00:2010:a0bb:6::53", s!.AddressIp);
        Assert.Equal(443, s.Port);
    }

    [Fact]
    public void TryParse_odohTarget_hasHostnameAndPath_noIp()
    {
        Assert.True(ServerStampParser.TryParse("sdns://BQcAAAAAAAAAF29kb2guY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk", out var s, out _));
        Assert.Equal(StampProtocol.ODoHTarget, s!.Protocol);
        Assert.Null(s.AddressIp);        // hostname-only — not probeable (IC-15)
        Assert.False(s.IsProbeable);
        Assert.Equal("odoh.cloudflare-dns.com", s.Hostname);
        Assert.Equal("/dns-query", s.Path);
    }

    [Fact]
    public void TryParse_odohRelay_emptyAddr_isNotProbeable()
    {
        Assert.True(ServerStampParser.TryParse("sdns://hQcAAAAAAAAAAAAab2RvaC1yZWxheS5lZGdlY29tcHV0ZS5hcHABLw", out var s, out _));
        Assert.Equal(StampProtocol.ODoHRelay, s!.Protocol);
        Assert.True(s.IsRelay);
        Assert.Null(s.AddressIp);
        Assert.Equal("odoh-relay.edgecompute.app", s.Hostname);
        Assert.Equal("/", s.Path);
    }

    [Fact]
    public void TryParse_plainDns_defaultsToPort53()
    {
        Assert.True(ServerStampParser.TryParse("sdns://AAEAAAAAAAAABzguOC44Ljg", out var s, out _));
        Assert.Equal(StampProtocol.PlainDns, s!.Protocol);
        Assert.True(s.Dnssec);   // props = 1
        Assert.Equal("8.8.8.8", s.AddressIp);
        Assert.Equal(53, s.Port);
    }

    [Fact]
    public void TryParse_dot_defaultsToPort853()
    {
        Assert.True(ServerStampParser.TryParse("sdns://AwcAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQ", out var s, out _));
        Assert.Equal(StampProtocol.DoT, s!.Protocol);
        Assert.Equal("9.9.9.9", s.AddressIp);
        Assert.Equal(853, s.Port);
        Assert.Equal("dns.quad9.net", s.Hostname);
    }

    [Fact]
    public void TryParse_sdnsWithoutSlashes_isAccepted()
    {
        // Reference accepts "sdns:" without "//".
        Assert.True(ServerStampParser.TryParse("sdns:AAEAAAAAAAAABzguOC44Ljg", out var s, out _));
        Assert.Equal(StampProtocol.PlainDns, s!.Protocol);
    }

    // ------------------------------------------------------------------ adversarial

    [Theory]
    [InlineData(null, StampParseErrorKind.NotAStamp)]
    [InlineData("", StampParseErrorKind.NotAStamp)]
    [InlineData("http://example.com", StampParseErrorKind.NotAStamp)]
    [InlineData("SDNS://AAE", StampParseErrorKind.NotAStamp)]           // case-sensitive prefix
    [InlineData("sdns://", StampParseErrorKind.Empty)]                  // zero bytes
    [InlineData("sdns://AA==", StampParseErrorKind.InvalidBase64)]      // padding rejected
    [InlineData("sdns://AA+/", StampParseErrorKind.InvalidBase64)]      // + and / are not base64url
    [InlineData("sdns://!!!!", StampParseErrorKind.InvalidBase64)]      // outside alphabet
    public void TryParse_malformedEnvelope_returnsTypedError(string? input, StampParseErrorKind expected)
    {
        Assert.False(ServerStampParser.TryParse(input, out var stamp, out var error));
        Assert.Null(stamp);
        Assert.Equal(expected, error.Kind);
    }

    [Fact]
    public void TryParse_oversizeInput_isRejected()
    {
        var big = "sdns://" + new string('A', ServerStampParser.MaxInputLength + 1);
        Assert.False(ServerStampParser.TryParse(big, out _, out var error));
        Assert.Equal(StampParseErrorKind.TooLarge, error.Kind);
    }

    [Fact]
    public void TryParse_unknownProtocol_isSurfacedNotDropped()
    {
        Assert.False(ServerStampParser.TryParse(Enc(0x06), out _, out var error)); // 0x06 = "Bg"
        Assert.Equal(StampParseErrorKind.UnknownProtocol, error.Kind);
    }

    [Fact]
    public void TryParse_trailingGarbage_isRejected()
    {
        // valid relay (0x81 + LP("1.2.3.4")) then one extra byte.
        var bytes = Concat(new byte[] { 0x81 }, Lp("1.2.3.4"), new byte[] { 0xFF });
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.TrailingGarbage, error.Kind);
    }

    [Fact]
    public void TryParse_truncatedLengthPrefix_isRejected()
    {
        // 0x00 plain, props(8), then a length byte claiming 8 addr bytes with none present.
        var bytes = Concat(new byte[] { 0x00 }, Props(1), new byte[] { 0x08 });
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.Truncated, error.Kind);
    }

    [Fact]
    public void TryParse_dnsCryptPublicKeyNot32Bytes_isRejected()
    {
        // The reference stamp layer accepts any pk length then Fatalf's later — we refuse it.
        var pk31 = new byte[31];
        var bytes = Concat(new byte[] { 0x01 }, Props(1), Lp("1.2.3.4"), LpBytes(pk31), Lp("2.dnscrypt-cert.x"));
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidPublicKeyLength, error.Kind);
    }

    [Fact]
    public void TryParse_certHashNot32Bytes_isRejected()
    {
        // DoH: props, LP(addr=""), VLP(single 31-byte hash), LP(hostname), LP(path).
        var hash31 = new byte[31];
        var bytes = Concat(new byte[] { 0x02 }, Props(1), Lp(""), Vlp(hash31), Lp("h.example"), Lp("/dns-query"));
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidHashLength, error.Kind);
    }

    [Fact]
    public void TryParse_controlCharInStringField_isRejected()
    {
        // 0x05 oDoH target, hostname containing a NUL — a TOML/UI injection surface.
        var bytes = Concat(new byte[] { 0x05 }, Props(1), Lp("host\0name"), Lp("/path"));
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidString, error.Kind);
    }

    [Theory]
    [InlineData("1.2.3.4:0")]        // port 0
    [InlineData("1.2.3.4:65536")]    // port out of range
    [InlineData("1.2.3.4:")]         // empty port
    public void TryParse_badPort_isRejected(string addr)
    {
        var bytes = Concat(new byte[] { 0x00 }, Props(1), Lp(addr));
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidPort, error.Kind);
    }

    [Fact]
    public void TryParse_nonIpAddressForPlainDns_isRejected()
    {
        var bytes = Concat(new byte[] { 0x00 }, Props(1), Lp("not-an-ip"));
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidAddress, error.Kind);
    }

    [Fact]
    public void TryParse_neverThrows_onArbitraryBytes()
    {
        // Fuzz-lite: a spread of hostile shapes must all return false, never throw.
        string[] inputs =
        {
            "sdns://" + new string('A', 3), "sdns://B", "sdns://AAAAAAAAAAAA",
            Enc(0x02, 0xFF), Enc(0x81, 0x80), Enc(0x00), Enc(0x01),
        };
        foreach (var i in inputs)
            Assert.False(ServerStampParser.TryParse(i, out _, out _));
    }

    // ------------------------------------------------------------------ core-review regressions

    [Fact]
    public void TryParse_danglingBootstrapContinuationBit_isRejectedNotCrashed()
    {
        // Core review CRITICAL: a bootstrap VLP whose continuation bit runs to end-of-buffer must
        // return Truncated, never throw IndexOutOfRange (a fail-closed / list-load-DoS violation).
        // DoT: proto, props(8), LP("9.9.9.9"), empty-hash VLP (0x00), LP("h"), bootstrap 0x80 (dangling).
        var bytes = Concat(new byte[] { 0x03 }, Props(0), Lp("9.9.9.9"), new byte[] { 0x00 }, Lp("h"), new byte[] { 0x80 });
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.Truncated, error.Kind);
    }

    [Theory]
    [InlineData("1.2")]            // IPAddress.TryParse would expand to 1.0.0.2 — not canonical
    [InlineData("010.0.0.1")]      // octal reinterpretation -> 8.0.0.1
    [InlineData("2130706433")]     // integer form -> 127.0.0.1
    [InlineData("0x7f.0.0.1")]     // hex octet
    [InlineData("127.1")]          // short form
    [InlineData("2001:db8::1")]    // bare (unbracketed) IPv6 — reference requires brackets
    public void TryParse_nonCanonicalAddress_isRejected(string addr)
    {
        var bytes = Concat(new byte[] { 0x00 }, Props(1), Lp(addr));
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidAddress, error.Kind);
    }

    [Fact]
    public void TryParse_scopedIpv6Address_isRejected()
    {
        var bytes = Concat(new byte[] { 0x00 }, Props(1), Lp("[fe80::1%eth0]"));
        Assert.False(ServerStampParser.TryParse(EncBytes(bytes), out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidAddress, error.Kind);
    }

    [Fact]
    public void TryParse_storedAddressIp_equalsWhatWillBeDialed()
    {
        // The stored AddressIp must be exactly the canonical literal IC-15's probe dials.
        Assert.True(ServerStampParser.TryParse("sdns://gR9bMjYwNDo5YTAwOjIwMTA6YTBiYjo2Ojo1M106NDQz", out var s, out _));
        Assert.Equal("2604:9a00:2010:a0bb:6::53", s!.AddressIp);
        Assert.Equal(System.Net.IPAddress.Parse(s.AddressIp!).ToString(), s.AddressIp); // round-trips canonically
    }

    // ------------------------------------------------------------------ composite form

    [Fact]
    public void TryParseComposite_relaySlashServer_returnsBoth()
    {
        // anon-cs-de relay (0x81) / quad9 DNSCrypt server (0x01), joined by '/'.
        const string composite =
            "sdns://gQ8xNDYuNzAuODIuMzo0NDM/AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0";

        Assert.True(ServerStampParser.TryParseComposite(composite, out var relay, out var server, out var error), error.ToString());
        Assert.Equal(StampProtocol.DnsCryptRelay, relay!.Protocol);
        Assert.Equal("146.70.82.3", relay.AddressIp);
        Assert.Equal(StampProtocol.DnsCrypt, server!.Protocol);
        Assert.Equal("2.dnscrypt-cert.quad9.net", server.ProviderName);
    }

    [Fact]
    public void TryParseComposite_serverFirst_isRejected()
    {
        // Two server stamps (no relay first) must be refused.
        const string bad =
            "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0/gQ8xNDYuNzAuODIuMzo0NDM";
        Assert.False(ServerStampParser.TryParseComposite(bad, out _, out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidComposite, error.Kind);
    }

    [Theory]
    [InlineData("sdns://gQ8xNDYuNzAuODIuMzo0NDM")]                    // single stamp, no '/'
    [InlineData("sdns://a/b/c")]                                     // too many parts
    public void TryParseComposite_malformed_isRejected(string input)
    {
        Assert.False(ServerStampParser.TryParseComposite(input, out _, out _, out var error));
        Assert.Equal(StampParseErrorKind.InvalidComposite, error.Kind);
    }

    // ------------------------------------------------------------------ byte builders

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static string Enc(params byte[] bytes) => EncBytes(bytes);

    private static string EncBytes(byte[] bytes) => "sdns://" + Base64Url(bytes);

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Props(ulong p)
    {
        var b = new byte[8];
        for (var i = 0; i < 8; i++) b[i] = (byte)(p >> (i * 8)); // little-endian
        return b;
    }

    private static byte[] Lp(string s) => LpBytes(Encoding.UTF8.GetBytes(s));

    private static byte[] LpBytes(byte[] payload)
    {
        var b = new byte[payload.Length + 1];
        b[0] = (byte)payload.Length;
        Array.Copy(payload, 0, b, 1, payload.Length);
        return b;
    }

    private static byte[] Vlp(byte[] singleElement)
    {
        // VLP with one element == LP(element) (high bit only set on non-final elements).
        return LpBytes(singleElement);
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var result = new byte[total];
        var offset = 0;
        foreach (var p in parts) { Array.Copy(p, 0, result, offset, p.Length); offset += p.Length; }
        return result;
    }
}
