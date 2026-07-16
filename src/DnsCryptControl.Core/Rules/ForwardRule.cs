using System.Globalization;
using System.Net;

namespace DnsCryptControl.Core.Rules;

/// <summary>
/// One parsed forwarding rule from a forwarding_rules file: a <see cref="Domain"/> (a SUFFIX match,
/// or the root <c>"."</c> catch-all) mapped to an ordered list of <see cref="Servers"/>. The
/// grammar (from <c>parseForwardFile</c> in dnscrypt-proxy 2.1.16's <c>plugin_forward.go</c>)
/// splits each meaningful line on the FIRST whitespace only: the domain, then the ENTIRE trimmed
/// remainder as a comma-separated server list.
/// <para>
/// <see cref="Domain"/> is the NORMALIZED domain (a leading <c>*.</c> cosmetic-stripped, then
/// lowercased — matching is case-insensitive suffix). <see cref="Servers"/> are the CANONICAL
/// resolver forms (<c>ip:port</c> / <c>[ip6]:port</c>, default port 53) plus the exact-uppercase
/// special keywords <c>$BOOTSTRAP</c> / <c>$DHCP</c> / <c>$RESOLVCONF:&lt;path&gt;</c>, preserved in
/// file order (the search sequence is order-preserving). <see cref="RawLine"/> and
/// <see cref="TrailingComment"/> carry round-trip provenance.
/// </para>
/// </summary>
/// <param name="Domain">The normalized domain (leading <c>*.</c> stripped, lowercased), or <c>"."</c>.</param>
/// <param name="Servers">The canonical server list (<c>ip:port</c>/<c>[ip6]:port</c> or an exact-upper keyword), in order.</param>
/// <param name="RawLine">The original raw line (pre comment-strip), for provenance.</param>
/// <param name="TrailingComment">The preserved <c>'#'…</c> inline comment, or <see langword="null"/>.</param>
public sealed record ForwardRule(
    string Domain,
    IReadOnlyList<string> Servers,
    string RawLine,
    string? TrailingComment)
{
    /// <summary>The case-SENSITIVE forward-to-bootstrap-resolvers keyword.</summary>
    public const string Bootstrap = "$BOOTSTRAP";

    /// <summary>The case-SENSITIVE forward-to-DHCP-resolvers keyword.</summary>
    public const string Dhcp = "$DHCP";

    /// <summary>The case-SENSITIVE <c>$RESOLVCONF:&lt;path&gt;</c> keyword prefix (a filesystem-path sink).</summary>
    public const string ResolvConfPrefix = "$RESOLVCONF:";

    /// <summary>
    /// Normalizes and validates the DOMAIN field (the first whitespace-delimited token), replicating
    /// <c>parseForwardFile</c>: a leading <c>*.</c> is cosmetic-stripped (treated as the bare
    /// suffix); ANY OTHER <c>*</c> anywhere is a FATAL syntax error (the proxy's
    /// <c>parseForwardFile</c> returns an error → <c>Init</c> aborts → the proxy won't start); the
    /// result is lowercased. An empty domain (empty token) is also fatal. The root <c>"."</c> is the
    /// catch-all and is valid. Never throws except <see cref="ArgumentNullException"/> for a null
    /// argument.
    /// </summary>
    /// <param name="rawDomain">The first token (already whitespace-trimmed by the caller).</param>
    /// <param name="normalized">On success, the normalized (stripped + lowercased) domain.</param>
    /// <param name="error">On failure, a human-actionable reason; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the domain is valid.</returns>
    public static bool NormalizeDomain(string rawDomain, out string normalized, out string? error)
    {
        ArgumentNullException.ThrowIfNull(rawDomain);

        normalized = rawDomain;
        error = null;

        if (rawDomain.Length == 0)
        {
            error = "forwarding rule has an empty domain";
            return false;
        }

        // Strip a leading '*.' (cosmetic — same as the bare suffix). Only the '*.' prefix; a lone
        // '*' or an interior '*' remains and is caught below.
        var domain = rawDomain;
        if (domain.StartsWith("*.", StringComparison.Ordinal))
        {
            domain = domain[2..];
        }

        // Any remaining '*' is a stray wildcard => FATAL for the whole proxy.
        if (domain.Contains('*', StringComparison.Ordinal))
        {
            error = $"domain '{rawDomain}' has a stray '*' — only a leading '*.' is allowed; any other '*' prevents the proxy from starting";
            return false;
        }

        if (domain.Length == 0)
        {
            // '*.' alone stripped to empty.
            error = $"domain '{rawDomain}' is empty after stripping the leading '*.'";
            return false;
        }

        normalized = domain.ToLowerInvariant();
        return true;
    }

    /// <summary>
    /// Classifies and canonicalizes a single trimmed SERVER token (one comma-split element of the
    /// RHS), replicating <c>parseForwardFile</c>'s per-server handling but with STRICTER lint (the
    /// proxy silently drops a bad server token, leaving the rule short a resolver — a silent
    /// failure). Recognized forms:
    /// <list type="bullet">
    ///   <item>the case-SENSITIVE keywords <c>$BOOTSTRAP</c> / <c>$DHCP</c> (emitted verbatim);</item>
    ///   <item><c>$RESOLVCONF:&lt;path&gt;</c> — a FILESYSTEM-PATH SINK (IC-7): an empty path is an
    ///     ERROR (the proxy skips it); a non-empty path is KEPT but ALWAYS surfaced as a WARNING —
    ///     a relative path (Windows <c>filepath.IsAbs</c> false, e.g. a lone leading <c>/</c>)
    ///     because the proxy warns and resolves it against its CWD, and an absolute path because it
    ///     is a proxy-privileged path sink worth confirming ("surface prominently", IC-7);</item>
    ///   <item>an IP endpoint: bare IPv4 → <c>ip:53</c>, <c>ip:port</c>, bare IPv6 → <c>[ip6]:53</c>,
    ///     bracketed IPv6 <c>[ip6]</c> → <c>[ip6]:53</c>, <c>[ip6]:port</c>. The IP is canonicalized
    ///     via <see cref="IPAddress"/> so round-trip is stable.</item>
    /// </list>
    /// Anything else (a hostname, a wrong-case keyword, an unknown <c>$…</c>, an unparseable
    /// endpoint) is an ERROR. Never throws except <see cref="ArgumentNullException"/> for a null
    /// argument.
    /// </summary>
    /// <param name="token">The trimmed server token.</param>
    /// <param name="canonical">On acceptance, the canonical form (may accompany a Warning that keeps the token).</param>
    /// <param name="severity">On a finding, its severity; otherwise ignored.</param>
    /// <param name="error">On a finding, a human-actionable reason; otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the token is accepted (<paramref name="error"/> may still be
    /// non-null for a Warning that KEEPS the token); <see langword="false"/> when it is rejected.
    /// </returns>
    public static bool ClassifyServer(
        string token,
        out string canonical,
        out RuleLintSeverity severity,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(token);

        canonical = token;
        severity = RuleLintSeverity.Error;
        error = null;

        if (token.Length == 0)
        {
            error = "forwarding rule has an empty server token (a stray comma?) — the proxy would drop it";
            return false;
        }

        // Case-SENSITIVE keyword tokens. $BOOTSTRAP / $DHCP are exact; $RESOLVCONF: carries a path.
        if (token is Bootstrap or Dhcp)
        {
            canonical = token;
            return true;
        }

        if (token.StartsWith(ResolvConfPrefix, StringComparison.Ordinal))
        {
            return ClassifyResolvConf(token, out canonical, out severity, out error);
        }

        // A '$' that is not one of the exact keywords is an unknown/wrong-case keyword. The proxy
        // matches these case-SENSITIVELY and silently drops an unknown '$...' token.
        if (token.StartsWith('$'))
        {
            error = $"'{token}' is not a recognized forwarding keyword — the proxy accepts only $BOOTSTRAP, $DHCP and $RESOLVCONF:<path> (case-sensitive) and silently drops anything else";
            return false;
        }

        return ClassifyEndpoint(token, out canonical, out error);
    }

    private static bool ClassifyResolvConf(
        string token,
        out string canonical,
        out RuleLintSeverity severity,
        out string? error)
    {
        canonical = token;
        severity = RuleLintSeverity.Error;
        error = null;

        var path = token[ResolvConfPrefix.Length..];
        if (path.Length == 0)
        {
            // The proxy: 'File needs to be specified for $RESOLVCONF' => Criticalf + skip the token.
            error = $"'{token}' has no path — $RESOLVCONF:<path> needs a file path or the proxy drops it";
            return false;
        }

        // Path sink (IC-7): ALWAYS surface it. This is a proxy-privileged filesystem-path sink the
        // design record instructs us to "surface prominently" — an arbitrary absolute path (e.g.
        // reading a secret file as a resolv.conf) is the exact case that must be reviewable, not the
        // one that gets zero surface. We DO NOT normalize/rewrite the user's path — it is preserved
        // verbatim for round-trip; the finding is the actionable surface. Both cases KEEP the token.
        canonical = token;
        severity = RuleLintSeverity.Warning;
        if (!IsAbsolutePath(path))
        {
            // Windows filepath.IsAbs: a lone leading '/' is 'rooted but not absolute'; the proxy
            // (dnscrypt-proxy.exe) logs a relative-path warning and resolves it against its CWD.
            error = $"$RESOLVCONF path '{path}' is relative — the proxy reads it with its own privileges; use an absolute path (this is a filesystem-path reference worth reviewing)";
        }
        else
        {
            // Absolute path: the proxy reads it silently, but it is still a proxy-privileged path
            // sink worth confirming it points at a resolv.conf-style file, not a sensitive file.
            error = $"$RESOLVCONF path '{path}' is an absolute filesystem path the proxy reads with its own privileges — confirm it points at a resolv.conf-style file, not a sensitive file";
        }

        return true; // KEEP the token (the proxy accepts both forms; relative gets a warning too).
    }

    /// <summary>
    /// True when <paramref name="path"/> is an absolute filesystem path under Go's WINDOWS
    /// <c>filepath.IsAbs</c> — the OS the deployed proxy (dnscrypt-proxy.exe, win64) runs on. On
    /// Windows only a drive-rooted <c>X:\</c>/<c>X:/</c> or a <c>\\server\share</c> UNC root is
    /// absolute; a lone leading <c>/</c> or <c>\</c> WITHOUT a drive letter is 'rooted but not
    /// absolute', so <c>$RESOLVCONF:/etc/resolv.conf</c> is treated as RELATIVE (matching the
    /// proxy's <c>dlog.Warnf</c>) rather than mis-classified as absolute.
    /// </summary>
    private static bool IsAbsolutePath(string path)
    {
        // Windows: '\\server\share' or '//server/share' (UNC).
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
        {
            return true;
        }

        // 'X:\' / 'X:/' drive-rooted.
        if (path.Length >= 3 &&
            char.IsLetter(path[0]) &&
            path[1] == ':' &&
            (path[2] == '\\' || path[2] == '/'))
        {
            return true;
        }

        return false;
    }

    private static bool ClassifyEndpoint(string token, out string canonical, out string? error)
    {
        canonical = token;
        error = null;

        // Bracketed IPv6 with an optional ':port': '[ip6]' or '[ip6]:port'.
        if (token.StartsWith('['))
        {
            var close = token.IndexOf(']', StringComparison.Ordinal);
            if (close < 0)
            {
                error = $"'{token}' is missing a closing ']' for a bracketed IPv6 address";
                return false;
            }

            var inner = token[1..close];
            var rest = token[(close + 1)..];

            if (!TryCanonicalizeIp(inner, out var ip6) || ip6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                error = $"'{token}' is not a valid bracketed IPv6 address";
                return false;
            }

            string port;
            if (rest.Length == 0)
            {
                port = "53";
            }
            else if (rest.StartsWith(':') && TryParsePort(rest[1..], out var p))
            {
                port = p;
            }
            else
            {
                error = $"'{token}' has an invalid port after the ']'";
                return false;
            }

            canonical = $"[{ip6}]:{port}";
            return true;
        }

        // Bare IPv6 (no brackets, no port): more than one ':' and it parses as IPv6.
        if (token.Count(c => c == ':') > 1)
        {
            if (TryCanonicalizeIp(token, out var bareIp6) &&
                bareIp6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                canonical = $"[{bareIp6}]:53";
                return true;
            }

            error = $"'{token}' is not a valid IPv6 address (bare IPv6 with a port must be bracketed, e.g. [::1]:5353)";
            return false;
        }

        // IPv4 with an optional ':port', or a bare IPv4.
        var colon = token.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            var ipPart = token[..colon];
            var portPart = token[(colon + 1)..];
            if (TryCanonicalizeIp(ipPart, out var ip4) &&
                ip4.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                TryParsePort(portPart, out var port4))
            {
                canonical = $"{ip4}:{port4}";
                return true;
            }

            error = $"'{token}' is not a valid IPv4 address with a port";
            return false;
        }

        if (TryCanonicalizeIp(token, out var bareIp4) &&
            bareIp4.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            canonical = $"{bareIp4}:53";
            return true;
        }

        error = $"'{token}' is not a valid resolver — expected an IP (v4/v6, optional :port) or a $BOOTSTRAP/$DHCP/$RESOLVCONF:<path> keyword";
        return false;
    }

    /// <summary>
    /// Parses <paramref name="text"/> as an IP literal AND requires its canonical
    /// <see cref="IPAddress.ToString"/> to round-trip to the SAME text — matching Go
    /// <c>net.ParseIP</c> (rejecting the leading-zero / short-dotted / zone-id forms .NET's lenient
    /// parser accepts), so we never emit a form the proxy would treat differently. Mirrors the A2/A3
    /// canonical guard.
    /// </summary>
    private static bool TryCanonicalizeIp(string text, out IPAddress ip)
    {
        if (IPAddress.TryParse(text, out var parsed) &&
            string.Equals(text, parsed.ToString(), StringComparison.Ordinal))
        {
            ip = parsed;
            return true;
        }

        ip = IPAddress.None;
        return false;
    }

    private static bool TryParsePort(string text, out string port)
    {
        port = text;
        if (text.Length == 0)
        {
            return false;
        }

        // Digit-only (Go's net.SplitHostPort + strconv-style): no '+', no whitespace, in 0..65535.
        // We VALIDATE via int.TryParse but PRESERVE the original substring verbatim — the proxy's
        // normalizeIPAndOptionalPort canonicalizes only the IP host and re-emits the port string
        // unchanged (fmt.Sprintf("%s:%s", ...)), so a non-minimal port like "053" must stay "053"
        // rather than be renumbered to "53" (editor-only byte drift the proxy never performs).
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) &&
            value is >= 0 and <= 65535)
        {
            port = text;
            return true;
        }

        return false;
    }
}
