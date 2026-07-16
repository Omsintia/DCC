using System.Net;
using CsCheck;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for <see cref="ProbeTargetPolicy.IsProbableResolverEndpoint"/> - the fix for
/// the prober-egress SSRF/beacon finding (2026-07-08): a latency probe must dial ONLY global-unicast public
/// addresses, so a hostile sdns:// stamp cannot aim the "test latency" click at loopback / private /
/// link-local space (an internal connect-only port-scan or out-of-band beacon). Oracles: over the FULL IPv4
/// space the policy matches the public/non-public ground truth exactly; it never throws for any address or
/// port; and it refuses the boundary shapes (whole 127/8, IPv4-mapped loopback/private, IPv6 ULA/link-local,
/// out-of-range ports). See the fuzzing design notes.
/// </summary>
public class ProbeTargetPolicyProperties
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void Matches_public_ground_truth_across_the_ipv4_space() =>
        Gen.Select(Gen.Int[0, 255], Gen.Int[0, 255], Gen.Int[0, 255], Gen.Int[0, 255], Gen.Int[1, 65535],
            (a, b, c, d, port) => (a, b, c, d, port)).Sample(t =>
        {
            var ip = new IPAddress(new[] { (byte)t.a, (byte)t.b, (byte)t.c, (byte)t.d });
            // Ground truth (independently computed): a public IPv4 is none of loopback(127/8), 10/8, 0/8,
            // multicast+reserved(>=224), 172.16/12, 192.168/16, CGNAT(100.64/10), link-local(169.254/16),
            // or the documentation/benchmarking/protocol ranges no resolver advertises.
            var isPublic = !(t.a == 127 || t.a == 10 || t.a == 0 || t.a >= 224
                || (t.a == 172 && t.b >= 16 && t.b <= 31)
                || (t.a == 192 && t.b == 168)
                || (t.a == 100 && t.b >= 64 && t.b <= 127)
                || (t.a == 169 && t.b == 254)
                || (t.a == 192 && t.b == 0 && (t.c == 0 || t.c == 2))
                || (t.a == 198 && t.b == 51 && t.c == 100)
                || (t.a == 203 && t.b == 0 && t.c == 113)
                || (t.a == 198 && (t.b == 18 || t.b == 19))
                || (t.a == 192 && t.b == 88 && t.c == 99));
            return ProbeTargetPolicy.IsProbableResolverEndpoint(ip, t.port) == isPublic;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Never_throws_over_arbitrary_ipv6_and_ports() =>
        Gen.Select(Gen.Byte.Array[16], Gen.Int[-2, 70000], (bytes, port) => (bytes, port)).Sample(t =>
        {
            var ip = new IPAddress(t.bytes);
            // A throw would fail the property; the result is also deterministic.
            var a = ProbeTargetPolicy.IsProbableResolverEndpoint(ip, t.port);
            var b = ProbeTargetPolicy.IsProbableResolverEndpoint(ip, t.port);
            return a == b;
        }, iter: Fuzz.Iter);

    [Theory]
    [InlineData("9.9.9.9", 443, true)]                    // public IPv4
    [InlineData("1.1.1.1", 853, true)]                    // public IPv4
    [InlineData("2001:4860:4860::8888", 443, true)]       // public IPv6
    [InlineData("127.0.0.1", 443, false)]                 // loopback
    [InlineData("127.0.0.53", 443, false)]                // whole 127/8, not just .1
    [InlineData("127.255.255.254", 443, false)]           // top of 127/8
    [InlineData("10.0.0.1", 443, false)]                  // 10/8 private
    [InlineData("172.16.0.1", 443, false)]                // 172.16/12 private (low edge)
    [InlineData("172.31.255.255", 443, false)]            // 172.16/12 private (high edge)
    [InlineData("172.15.0.1", 443, true)]                 // just below 172.16/12 -> public
    [InlineData("172.32.0.1", 443, true)]                 // just above 172.16/12 -> public
    [InlineData("192.168.1.1", 443, false)]               // 192.168/16 private
    [InlineData("169.254.1.1", 443, false)]               // link-local
    [InlineData("0.0.0.0", 443, false)]                   // unspecified
    [InlineData("224.0.0.1", 443, false)]                 // multicast
    [InlineData("100.64.0.1", 443, false)]                // CGNAT 100.64/10 (low edge)
    [InlineData("100.127.255.255", 443, false)]           // CGNAT 100.64/10 (high edge)
    [InlineData("100.63.255.255", 443, true)]             // just below CGNAT -> public
    [InlineData("100.128.0.1", 443, true)]                // just above CGNAT -> public
    [InlineData("192.0.2.5", 443, false)]                 // TEST-NET-1
    [InlineData("192.0.0.5", 443, false)]                 // 192.0.0/24 IETF protocol assignments
    [InlineData("192.0.1.5", 443, true)]                  // 192.0.1/24 is NOT reserved -> public
    [InlineData("198.51.100.5", 443, false)]              // TEST-NET-2
    [InlineData("203.0.113.5", 443, false)]               // TEST-NET-3
    [InlineData("198.18.0.1", 443, false)]                // benchmarking 198.18/15 (low edge)
    [InlineData("198.19.255.255", 443, false)]            // benchmarking 198.18/15 (high edge)
    [InlineData("198.20.0.1", 443, true)]                 // just above benchmarking -> public
    [InlineData("192.88.99.1", 443, false)]               // 6to4 relay anycast (deprecated)
    [InlineData("::1", 443, false)]                       // IPv6 loopback
    [InlineData("fe80::1", 443, false)]                   // IPv6 link-local
    [InlineData("fc00::1", 443, false)]                   // IPv6 unique-local
    [InlineData("ff02::1", 443, false)]                   // IPv6 multicast
    [InlineData("2002:0a00:0001::1", 443, false)]         // 6to4 wrapping internal 10.0.0.1 (smuggling refused)
    [InlineData("2001:0:1234::1", 443, false)]            // Teredo 2001:0::/32
    [InlineData("64:ff9b::0a00:0001", 443, false)]        // NAT64 wrapping internal 10.0.0.1 (outside 2000::/3)
    [InlineData("2001:db8::1", 443, false)]               // documentation 2001:db8::/32
    [InlineData("2606:4700:4700::1111", 443, true)]       // public IPv6 (Cloudflare)
    [InlineData("2620:fe::fe", 443, true)]                // public IPv6 (Quad9)
    [InlineData("::ffff:127.0.0.1", 443, false)]          // IPv4-mapped loopback (not smuggled)
    [InlineData("::ffff:10.0.0.1", 443, false)]           // IPv4-mapped private (not smuggled)
    [InlineData("::ffff:100.64.0.1", 443, false)]         // IPv4-mapped CGNAT (not smuggled)
    [InlineData("9.9.9.9", 0, false)]                     // port out of range (low)
    [InlineData("9.9.9.9", 70000, false)]                 // port out of range (high)
    public void Boundary_examples(string address, int port, bool expected) =>
        Assert.Equal(expected, ProbeTargetPolicy.IsProbableResolverEndpoint(IPAddress.Parse(address), port));
}
