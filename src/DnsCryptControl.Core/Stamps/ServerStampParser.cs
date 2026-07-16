using System.Net;
using System.Text;

namespace DnsCryptControl.Core.Stamps;

/// <summary>
/// Parses <c>sdns://</c> DNS Stamps. Fail-closed: never throws on hostile input — every
/// malformed/unsupported case returns a typed <see cref="StampParseError"/>. Targets the
/// dnscrypt-proxy 2.1.16 vendored parser semantics (the version this app ships), with
/// deliberate hardening divergences documented per field:
/// <list type="bullet">
///   <item>base64url is strict — padding, whitespace, non-url alphabet, and non-canonical
///     trailing bits are all rejected (Go's decoder tolerates embedded CR/LF; we do not).</item>
///   <item>a DNSCrypt public key MUST be exactly 32 bytes — the reference accepts any length
///     at the stamp layer then <c>dlog.Fatalf</c>s later, so a hostile stamp is a DoS.</item>
///   <item>string fields (hostname/path/provider/bootstrap) must be valid UTF-8 with no
///     control characters — a hostile <c>providerName</c> containing <c>\n[sources]</c> must
///     never reach the TOML writer or the UI.</item>
///   <item>unknown protocol ids are surfaced (<see cref="StampParseErrorKind.UnknownProtocol"/>),
///     never silently dropped.</item>
/// </list>
/// The 8-byte props bitfield is preserved verbatim (unknown bits 3..63 tolerated). Relay
/// stamps (0x81) carry NO props field — byte 1 is the address length.
/// </summary>
public static class ServerStampParser
{
    /// <summary>Reject inputs longer than this (the longest real stamp is ~200 chars).</summary>
    public const int MaxInputLength = 2048;

    private const string Prefix = "sdns:";
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Parses a single <c>sdns://</c> stamp. Returns false with a typed
    /// <paramref name="error"/> on any malformed/unsupported input.
    /// </summary>
    public static bool TryParse(string? input, out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;

        if (string.IsNullOrEmpty(input) || !input.StartsWith(Prefix, StringComparison.Ordinal))
        {
            error = new StampParseError(StampParseErrorKind.NotAStamp, "missing 'sdns:' prefix");
            return false;
        }
        if (input.Length > MaxInputLength)
        {
            error = new StampParseError(StampParseErrorKind.TooLarge, $"stamp exceeds {MaxInputLength} characters");
            return false;
        }

        var body = input[Prefix.Length..];
        if (body.StartsWith("//", StringComparison.Ordinal)) body = body[2..]; // "sdns://" and "sdns:" both accepted

        if (!TryDecodeBase64Url(body, out var bytes, out error)) return false;
        if (bytes.Length == 0)
        {
            error = new StampParseError(StampParseErrorKind.Empty, "no bytes after decode");
            return false;
        }

        var protocolByte = bytes[0];
        if (!Enum.IsDefined(typeof(StampProtocol), protocolByte))
        {
            error = new StampParseError(StampParseErrorKind.UnknownProtocol, $"unsupported stamp protocol 0x{protocolByte:x2}");
            return false;
        }
        var protocol = (StampProtocol)protocolByte;

        var reader = new StampReader(bytes, 1); // byte 0 is the protocol id
        return protocol switch
        {
            StampProtocol.PlainDns => ParsePlainDns(reader, out stamp, out error),
            StampProtocol.DnsCrypt => ParseDnsCrypt(reader, out stamp, out error),
            StampProtocol.DoH => ParseHttpLike(reader, protocol, out stamp, out error),
            StampProtocol.DoT => ParseTlsLike(reader, protocol, out stamp, out error),
            StampProtocol.DoQ => ParseTlsLike(reader, protocol, out stamp, out error),
            StampProtocol.ODoHTarget => ParseODoHTarget(reader, out stamp, out error),
            StampProtocol.DnsCryptRelay => ParseRelay(reader, out stamp, out error),
            StampProtocol.ODoHRelay => ParseHttpLike(reader, protocol, out stamp, out error),
            _ => Fail(StampParseErrorKind.UnknownProtocol, "unreachable", out error),
        };
    }

    /// <summary>
    /// Parses the composite <c>sdns://&lt;relay&gt;/&lt;server&gt;</c> form: a relay stamp and a
    /// server stamp joined by '/'. Both are returned on success.
    /// </summary>
    public static bool TryParseComposite(string? input, out ServerStamp? relay, out ServerStamp? server, out StampParseError error)
    {
        relay = null;
        server = null;

        if (string.IsNullOrEmpty(input) || !input.StartsWith("sdns://", StringComparison.Ordinal))
        {
            error = new StampParseError(StampParseErrorKind.InvalidComposite, "composite stamps require the 'sdns://' form");
            return false;
        }
        if (input.Length > MaxInputLength * 2)
        {
            error = new StampParseError(StampParseErrorKind.TooLarge, "composite stamp too large");
            return false;
        }

        var parts = input["sdns://".Length..].Split('/'); // '/' is not in the base64url alphabet
        if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0)
        {
            error = new StampParseError(StampParseErrorKind.InvalidComposite, "expected exactly two '/'-separated stamps");
            return false;
        }

        if (!TryParse("sdns://" + parts[0], out relay, out error)) return false;
        if (relay is null || !relay.IsRelay)
        {
            relay = null;
            error = new StampParseError(StampParseErrorKind.InvalidComposite, "first stamp is not a relay");
            return false;
        }
        if (!TryParse("sdns://" + parts[1], out server, out error)) { relay = null; return false; }
        if (server is null || server.IsRelay)
        {
            relay = null;
            server = null;
            error = new StampParseError(StampParseErrorKind.InvalidComposite, "second stamp is a relay, expected a server");
            return false;
        }
        error = StampParseError.None;
        return true;
    }

    // ---------------------------------------------------------------- per-protocol

    // 0x00: props(8) | LP(addr[:port]) [to end]. Default port 53.
    private static bool ParsePlainDns(StampReader r, out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;
        if (!r.TryReadProps(out var props, out error)) return false;
        if (!r.TryReadLp(LpBound.Final, out var addrBytes, out error)) return false;
        if (!TryDecodeString(addrBytes, out var addr, out error)) return false;
        if (!TryNormalizeAddress(addr, 53, allowEmptyHost: false, out var ip, out var port, out _, out error)) return false;
        if (!r.AtEnd) return Fail(StampParseErrorKind.TrailingGarbage, "bytes after plain-DNS address", out error);
        stamp = Build(StampProtocol.PlainDns, props, ip, port);
        return true;
    }

    // 0x81: LP(addr[:port]) — NO props. Default port 443.
    private static bool ParseRelay(StampReader r, out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;
        if (!r.TryReadLp(LpBound.Final, out var addrBytes, out error)) return false;
        if (!TryDecodeString(addrBytes, out var addr, out error)) return false;
        if (!TryNormalizeAddress(addr, 443, allowEmptyHost: false, out var ip, out var port, out _, out error)) return false;
        if (!r.AtEnd) return Fail(StampParseErrorKind.TrailingGarbage, "bytes after relay address", out error);
        stamp = Build(StampProtocol.DnsCryptRelay, props: 0, ip, port);
        return true;
    }

    // 0x01: props(8) | LP(addr) | LP(pk[32]) | LP(providerName). Default port 443.
    private static bool ParseDnsCrypt(StampReader r, out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;
        if (!r.TryReadProps(out var props, out error)) return false;
        if (!r.TryReadLp(LpBound.Mid, out var addrBytes, out error)) return false;
        if (!r.TryReadLp(LpBound.Mid, out var pk, out error)) return false;
        if (!r.TryReadLp(LpBound.Final, out var providerBytes, out error)) return false;

        if (pk.Length != 32)
            return Fail(StampParseErrorKind.InvalidPublicKeyLength, $"DNSCrypt public key is {pk.Length} bytes, expected 32", out error);
        if (!TryDecodeString(addrBytes, out var addr, out error)) return false;
        if (!TryNormalizeAddress(addr, 443, allowEmptyHost: false, out var ip, out var port, out _, out error)) return false;
        if (!TryDecodeString(providerBytes, out var provider, out error)) return false;
        if (!r.AtEnd) return Fail(StampParseErrorKind.TrailingGarbage, "bytes after DNSCrypt provider name", out error);

        stamp = Build(StampProtocol.DnsCrypt, props, ip, port, publicKey: pk, providerName: provider);
        return true;
    }

    // 0x02 DoH / 0x85 ODoH relay: props | LP(addr) | VLP(hashes) | LP(hostname) | LP(path) [| VLP(bootstrap)].
    private static bool ParseHttpLike(StampReader r, StampProtocol protocol, out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;
        if (!r.TryReadProps(out var props, out error)) return false;
        if (!r.TryReadLp(LpBound.Mid, out var addrBytes, out error)) return false;
        if (!r.TryReadHashes(out var hashes, out error)) return false;
        if (!r.TryReadLp(LpBound.Mid, out var hostBytes, out error)) return false;
        if (!r.TryReadLp(LpBound.Final, out var pathBytes, out error)) return false;
        if (!r.TryReadBootstrap(out var bootstrap, out error)) return false;
        if (!r.AtEnd) return Fail(StampParseErrorKind.TrailingGarbage, "bytes after HTTP-like stamp", out error);

        return BuildHttpLike(protocol, props, addrBytes, hostBytes, pathBytes, hashes, bootstrap, 443, out stamp, out error);
    }

    // 0x03 DoT / 0x04 DoQ: props | LP(addr) | VLP(hashes) | LP(hostname) [| VLP(bootstrap)]. Default 853.
    private static bool ParseTlsLike(StampReader r, StampProtocol protocol, out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;
        if (!r.TryReadProps(out var props, out error)) return false;
        if (!r.TryReadLp(LpBound.Mid, out var addrBytes, out error)) return false;
        if (!r.TryReadHashes(out var hashes, out error)) return false;
        if (!r.TryReadLp(LpBound.Final, out var hostBytes, out error)) return false;
        if (!r.TryReadBootstrap(out var bootstrap, out error)) return false;
        if (!r.AtEnd) return Fail(StampParseErrorKind.TrailingGarbage, "bytes after TLS-like stamp", out error);

        return BuildHttpLike(protocol, props, addrBytes, hostBytes, null, hashes, bootstrap, 853, out stamp, out error);
    }

    // 0x05 ODoH target: props | LP(hostname) | LP(path). No addr/hashes/bootstrap. Default 443.
    private static bool ParseODoHTarget(StampReader r, out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;
        if (!r.TryReadProps(out var props, out error)) return false;
        if (!r.TryReadLp(LpBound.Mid, out var hostBytes, out error)) return false;
        if (!r.TryReadLp(LpBound.Final, out var pathBytes, out error)) return false;
        if (!r.AtEnd) return Fail(StampParseErrorKind.TrailingGarbage, "bytes after ODoH target", out error);

        if (!TryDecodeString(hostBytes, out var hostname, out error)) return false;
        if (!TryDecodeString(pathBytes, out var path, out error)) return false;
        stamp = Build(StampProtocol.ODoHTarget, props, addressIp: null, port: HostnamePort(hostname, 443),
            hostname: hostname, path: path);
        return true;
    }

    // Shared builder for DoH/DoT/DoQ/ODoH-relay: addr may be empty (hostname-only, not probeable).
    private static bool BuildHttpLike(
        StampProtocol protocol, ulong props, byte[] addrBytes, byte[] hostBytes, byte[]? pathBytes,
        IReadOnlyList<byte[]> hashes, IReadOnlyList<string> bootstrap, int defaultPort,
        out ServerStamp? stamp, out StampParseError error)
    {
        stamp = null;
        if (!TryDecodeString(addrBytes, out var addr, out error)) return false;
        if (!TryDecodeString(hostBytes, out var hostname, out error)) return false;
        string? path = null;
        if (pathBytes is not null && !TryDecodeString(pathBytes, out path, out error)) return false;

        string? ip;
        int port;
        var masterStrict = false;
        if (addr.Length == 0)
        {
            // hostname-only: no probe IP; the effective port comes from the hostname.
            ip = null;
            port = HostnamePort(hostname, defaultPort);
        }
        else
        {
            if (!TryNormalizeAddress(addr, defaultPort, allowEmptyHost: protocol is StampProtocol.DoT or StampProtocol.DoQ,
                    out ip, out port, out var addrHadPort, out error))
                return false;
            // master requires a bare IP (no port) in the addr for HTTP/TLS-like stamps; 2.1.16 allows it.
            if (addrHadPort) masterStrict = true;
        }

        stamp = Build(protocol, props, ip, port, hashes: hashes, hostname: hostname, path: path,
            bootstrapIps: bootstrap, masterStrict: masterStrict);
        return true;
    }

    // ---------------------------------------------------------------- helpers

    private static ServerStamp Build(
        StampProtocol protocol, ulong props, string? addressIp, int port,
        byte[]? publicKey = null, string? providerName = null,
        IReadOnlyList<byte[]>? hashes = null, string? hostname = null, string? path = null,
        IReadOnlyList<string>? bootstrapIps = null, bool masterStrict = false)
        => new(protocol, props, addressIp, port, publicKey, providerName,
            hashes ?? Array.Empty<byte[]>(), hostname, path,
            bootstrapIps ?? Array.Empty<string>(), masterStrict);

    private static bool Fail(StampParseErrorKind kind, string detail, out StampParseError error)
    {
        error = new StampParseError(kind, detail);
        return false;
    }

    private static bool TryDecodeString(byte[] raw, out string value, out StampParseError error)
    {
        value = "";
        try { value = StrictUtf8.GetString(raw); }
        catch (DecoderFallbackException) { return Fail(StampParseErrorKind.InvalidString, "invalid UTF-8 in string field", out error); }
        foreach (var c in value)
            if (char.IsControl(c)) return Fail(StampParseErrorKind.InvalidString, "control character in string field", out error);
        error = StampParseError.None;
        return true;
    }

    /// <summary>Splits an <c>addr[:port]</c> (bracketed IPv6 supported), validates the host as an IP, applies the default port.</summary>
    private static bool TryNormalizeAddress(
        string addr, int defaultPort, bool allowEmptyHost,
        out string? ip, out int port, out bool hadPort, out StampParseError error)
    {
        ip = null;
        port = defaultPort;
        hadPort = false;
        string host;
        string? portStr = null;
        var wasBracketed = false;

        if (addr.StartsWith('['))
        {
            wasBracketed = true;
            var close = addr.IndexOf(']');
            if (close < 0) return Fail(StampParseErrorKind.InvalidAddress, "unterminated IPv6 bracket", out error);
            host = addr[1..close];
            var rest = addr[(close + 1)..];
            if (rest.Length > 0)
            {
                if (rest[0] != ':') return Fail(StampParseErrorKind.InvalidAddress, "malformed IPv6 address", out error);
                portStr = rest[1..];
            }
        }
        else
        {
            var first = addr.IndexOf(':');
            var last = addr.LastIndexOf(':');
            if (last >= 0 && last == first)
            {
                host = addr[..last];
                portStr = addr[(last + 1)..];
            }
            else
            {
                host = addr; // zero colons, or bare IPv6 with several colons (no port)
            }
        }

        if (portStr is not null)
        {
            if (!TryParsePort(portStr, out port))
                return Fail(StampParseErrorKind.InvalidPort, $"invalid port '{portStr}'", out error);
            hadPort = true;
        }

        if (host.Length == 0)
        {
            if (allowEmptyHost && hadPort) { ip = null; error = StampParseError.None; return true; } // DoT/DoQ ":port" quirk
            return Fail(StampParseErrorKind.InvalidAddress, "empty address host", out error);
        }

        // Hardening beyond IPAddress.TryParse's leniency (which accepts "1.2", "010.0.0.1",
        // "0x7f.0.0.1", "2130706433", "%zone"): require the stored AddressIp to be EXACTLY the
        // canonical literal that IC-15's probe will dial, and enforce bracket <=> IPv6 (matching
        // the reference, which brackets IPv6 and rejects bare IPv6 / scoped addresses).
        if (host.Contains('%', StringComparison.Ordinal))
            return Fail(StampParseErrorKind.InvalidAddress, "scoped IP address not allowed", out error);
        if (!IPAddress.TryParse(host, out var parsed))
            return Fail(StampParseErrorKind.InvalidAddress, $"'{host}' is not a valid IP literal", out error);
        if (!parsed.ToString().Equals(host, StringComparison.Ordinal))
            return Fail(StampParseErrorKind.InvalidAddress, $"'{host}' is not a canonical IP literal", out error);
        var isIpv6 = parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        if (wasBracketed != isIpv6)
            return Fail(StampParseErrorKind.InvalidAddress,
                wasBracketed ? "bracketed address is not IPv6" : "unbracketed IPv6 address", out error);

        ip = host;
        error = StampParseError.None;
        return true;
    }

    private static bool TryParsePort(string s, out int port)
    {
        port = 0;
        if (s.Length == 0) return false;
        foreach (var c in s) if (c is < '0' or > '9') return false; // digits only; leading zeros allowed
        if (!int.TryParse(s, out var p)) return false;              // rejects overflow
        if (p is < 1 or > 65535) return false;
        port = p;
        return true;
    }

    /// <summary>Best-effort effective port from a hostname[:port] string (no IP validation — hostnames are display/SNI).</summary>
    private static int HostnamePort(string hostname, int defaultPort)
    {
        if (hostname.StartsWith('['))
        {
            var close = hostname.IndexOf(']');
            if (close >= 0 && close + 1 < hostname.Length && hostname[close + 1] == ':'
                && TryParsePort(hostname[(close + 2)..], out var pv6)) return pv6;
            return defaultPort;
        }
        var first = hostname.IndexOf(':');
        var last = hostname.LastIndexOf(':');
        if (last >= 0 && last == first && TryParsePort(hostname[(last + 1)..], out var p)) return p;
        return defaultPort;
    }

    private static bool TryDecodeBase64Url(string s, out byte[] bytes, out StampParseError error)
    {
        bytes = Array.Empty<byte>();
        error = StampParseError.None;
        if (s.Length == 0) return true; // caller maps 0 bytes -> Empty

        foreach (var c in s)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!ok) return Fail(StampParseErrorKind.InvalidBase64, "character outside the base64url alphabet", out error);
        }
        if (s.Length % 4 == 1)
            return Fail(StampParseErrorKind.InvalidBase64, "invalid base64url length", out error);

        var translated = s.Replace('-', '+').Replace('_', '/');
        translated += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        try { bytes = Convert.FromBase64String(translated); }
        catch (FormatException) { return Fail(StampParseErrorKind.InvalidBase64, "malformed base64", out error); }

        // Canonicality: re-encode and compare (rejects non-canonical trailing bits, matching Go's RawURLEncoding.Strict).
        var reencoded = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (!reencoded.Equals(s, StringComparison.Ordinal))
            return Fail(StampParseErrorKind.InvalidBase64, "non-canonical base64url", out error);
        return true;
    }

    // ---------------------------------------------------------------- reader

    private enum LpBound
    {
        /// <summary>A field followed by ≥1 more mandatory byte: error if <c>1 + length &gt;= rem</c>.</summary>
        Mid,

        /// <summary>The last mandatory field (may consume to the exact end): error if <c>length &gt;= rem</c>.</summary>
        Final,
    }

    /// <summary>A forward-only cursor over the decoded stamp bytes with the reference's exact bounds arithmetic.</summary>
    private sealed class StampReader
    {
        private readonly byte[] _bytes;
        private int _pos;

        public StampReader(byte[] bytes, int start) { _bytes = bytes; _pos = start; }

        private int Remaining => _bytes.Length - _pos;

        public bool AtEnd => _pos == _bytes.Length;

        public bool TryReadProps(out ulong props, out StampParseError error)
        {
            props = 0;
            if (Remaining < 8) return Fail(StampParseErrorKind.Truncated, "truncated props field", out error);
            for (var i = 0; i < 8; i++) props |= (ulong)_bytes[_pos + i] << (i * 8); // little-endian
            _pos += 8;
            error = StampParseError.None;
            return true;
        }

        public bool TryReadLp(LpBound bound, out byte[] value, out StampParseError error)
        {
            value = Array.Empty<byte>();
            if (Remaining < 1) return Fail(StampParseErrorKind.Truncated, "truncated length prefix", out error);
            var rem = Remaining;
            int length = _bytes[_pos];
            var overrun = bound == LpBound.Mid ? 1 + length >= rem : length >= rem;
            if (overrun) return Fail(StampParseErrorKind.Truncated, "length-prefixed field runs past the buffer", out error);
            value = _bytes[(_pos + 1)..(_pos + 1 + length)];
            _pos += 1 + length;
            error = StampParseError.None;
            return true;
        }

        // VLP hashes: each element 0 or 32 bytes; the whole set is followed by ≥1 more byte (a hostname).
        public bool TryReadHashes(out IReadOnlyList<byte[]> hashes, out StampParseError error)
        {
            var result = new List<byte[]>();
            hashes = result;
            while (true)
            {
                if (Remaining < 1) return Fail(StampParseErrorKind.Truncated, "truncated hash VLP", out error);
                var rem = Remaining;
                var vlen = _bytes[_pos];
                int length = vlen & 0x7F;
                if (1 + length >= rem) return Fail(StampParseErrorKind.Truncated, "hash element runs past the buffer", out error);
                if (length is not (0 or 32))
                    return Fail(StampParseErrorKind.InvalidHashLength, $"certificate hash is {length} bytes, expected 0 or 32", out error);
                if (length > 0) result.Add(_bytes[(_pos + 1)..(_pos + 1 + length)]);
                _pos += 1 + length;
                if ((vlen & 0x80) == 0) break; // no continuation bit → last element
            }
            error = StampParseError.None;
            return true;
        }

        // VLP bootstrap IPs (to end, optional): entered only when bytes remain; may consume to the exact end.
        public bool TryReadBootstrap(out IReadOnlyList<string> ips, out StampParseError error)
        {
            var result = new List<string>();
            ips = result;
            error = StampParseError.None;
            if (AtEnd) return true; // bootstrap is optional
            while (true)
            {
                // A dangling continuation bit that runs to end-of-buffer must be rejected as
                // Truncated, never read past the end (fail-closed — see the hashes loop guard).
                if (Remaining < 1) return Fail(StampParseErrorKind.Truncated, "truncated bootstrap VLP", out error);
                var rem = Remaining;
                var vlen = _bytes[_pos];
                int length = vlen & 0x7F;
                if (1 + length > rem) return Fail(StampParseErrorKind.Truncated, "bootstrap element runs past the buffer", out error);
                if (length > 0)
                {
                    if (!TryDecodeString(_bytes[(_pos + 1)..(_pos + 1 + length)], out var ip, out error)) return false;
                    result.Add(ip);
                }
                _pos += 1 + length;
                if ((vlen & 0x80) == 0) break;
            }
            return true;
        }
    }
}
