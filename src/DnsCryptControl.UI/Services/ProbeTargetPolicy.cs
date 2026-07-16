using System.Net;
using System.Net.Sockets;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Decides whether an sdns:// stamp's (address, port) is a plausible PUBLIC resolver endpoint the latency
/// prober may dial. The address and port come from an UNTRUSTED remote resolver list, and the prober opens
/// a real outbound TCP connect; without this gate a hostile stamp could aim the user's "test latency" click
/// at an internal host - RFC1918, loopback, or link-local space, on any port - turning the probe into a
/// connect-only port-scan / out-of-band beacon of the user's own network (finding 2026-07-08). A resolver
/// has no legitimate reason to advertise a non-global-unicast address, so ONLY global-unicast public
/// addresses are dialable. Pure, total (never throws), and free of banned APIs (classification only, no I/O).
/// </summary>
public static class ProbeTargetPolicy
{
    /// <summary>True only when <paramref name="address"/> is a global-unicast public address and
    /// <paramref name="port"/> is in [1,65535]. Refused: loopback, unspecified, multicast/reserved, IPv4
    /// private (10/8, 172.16/12, 192.168/16), CGNAT/shared (100.64/10), link-local (169.254/16), and the
    /// documentation/benchmarking/protocol ranges no resolver advertises (192.0.0/24, 192.0.2/24,
    /// 198.51.100/24, 203.0.113/24, 198.18/15, 192.88.99/24). IPv6 is an allowlist of 2000::/3 minus 6to4
    /// (2002::/16), Teredo (2001:0::/32) and documentation (2001:db8::/32) - so link-local, ULA, NAT64,
    /// and IPv4-compatible forms are all refused. An IPv4-mapped IPv6 form is unwrapped first so a mapped
    /// non-public address cannot be smuggled past the IPv6 checks, and 6to4/NAT64 (which embed an arbitrary
    /// IPv4, including internal space, that the mapped-unwrap does not cover) are refused explicitly.</summary>
    public static bool IsProbableResolverEndpoint(IPAddress? address, int port)
    {
        if (address is null || port < 1 || port > 65535)
        {
            return false;
        }

        var addr = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        if (IPAddress.IsLoopback(addr))
        {
            return false; // 127/8, ::1
        }

        if (addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any))
        {
            return false; // 0.0.0.0, ::
        }

        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes(); // exactly 4 bytes
            if (b[0] == 10) return false;                              // 10/8 private
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false; // 172.16/12 private
            if (b[0] == 192 && b[1] == 168) return false;             // 192.168/16 private
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false; // 100.64/10 CGNAT/shared address space (RFC 6598)
            if (b[0] == 169 && b[1] == 254) return false;             // 169.254/16 link-local
            if (b[0] == 0) return false;                              // 0/8 "this network"
            if (b[0] >= 224) return false;                            // 224/4 multicast + 240/4 reserved + 255.255.255.255
            // Reserved documentation / benchmarking / protocol ranges no real resolver advertises
            // (RFC 5737 / 2544 / 6890 / 3068) - a stamp using one is hostile, never a legitimate target.
            if (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) return false; // 192.0.0/24 IETF, 192.0.2/24 TEST-NET-1
            if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false; // 198.51.100/24 TEST-NET-2
            if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;  // 203.0.113/24 TEST-NET-3
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false; // 198.18/15 benchmarking
            if (b[0] == 192 && b[1] == 88 && b[2] == 99) return false;   // 192.88.99/24 6to4 relay anycast (deprecated)
            return true;                                              // global-unicast IPv4
        }

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var v6 = addr.GetAddressBytes(); // exactly 16 bytes
            // Public IPv6 unicast lives ONLY in 2000::/3 (top 3 bits = 001). Treat it as an allowlist:
            // everything outside - loopback, ::/96 IPv4-compatible, 64:ff9b::/96 NAT64, 100::/64 discard,
            // fc00::/7 ULA, fe80::/10 link-local, ff00::/8 multicast - is refused. This also closes the
            // transition-range smuggling the old category checks missed: an IPv4-compatible or NAT64
            // address embeds an arbitrary IPv4 (incl. internal space) that the ::ffff: mapped-unwrap above
            // does NOT cover, so it would otherwise reach internal targets via the v6 path.
            if ((v6[0] & 0xE0) != 0x20) return false;
            // Within 2000::/3, still refuse 6to4 (wraps an arbitrary IPv4) + Teredo + documentation.
            if (v6[0] == 0x20 && v6[1] == 0x02) return false;                                   // 2002::/16 6to4
            if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x00) return false; // 2001:0::/32 Teredo
            if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8) return false; // 2001:db8::/32 documentation
            return true; // global-unicast IPv6
        }

        return false; // unknown address family -> refuse
    }
}
