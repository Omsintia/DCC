using System.Globalization;
using System.Net;

namespace DnsCryptControl.Core.Rules;

/// <summary>
/// The kind an IP rule (from a blocked_ips / allowed_ips file) is classified into, mirroring
/// dnscrypt-proxy 2.1.16's <c>LoadIPRules</c> / <c>ParseIPRule</c>. The IP taxonomy is exactly
/// three (no substring, no regex, no interior wildcard, no <c>@schedule</c>):
/// </summary>
public enum IpRuleKind
{
    /// <summary>A bare IP literal (no <c>'/'</c>, no trailing <c>'*'</c>) matched by canonical string equality.</summary>
    Exact,

    /// <summary>A trailing-<c>'*'</c> TEXTUAL prefix (e.g. <c>10.*</c>) — a string prefix on the canonical IP, NOT a CIDR range.</summary>
    TextPrefix,

    /// <summary>A <c>'/'</c>-bearing CIDR network (e.g. <c>10.0.0.0/8</c>) — the only true numeric range form.</summary>
    Cidr,
}

/// <summary>
/// One parsed IP rule from a blocked_ips / allowed_ips file. The grammar is ONE token per line —
/// the whole comment-stripped, trimmed line is the rule value (no field splitting, no
/// <c>@schedule</c>). <see cref="Value"/> is the CANONICAL form (exact IP →
/// <see cref="IPAddress.ToString"/>; CIDR → <c>networkAddress/prefix</c>; text prefix → the
/// stripped core WITHOUT the trailing <c>'*'</c>); the serializer re-adds the <c>'*'</c> for a
/// <see cref="IpRuleKind.TextPrefix"/>. <see cref="RawLine"/> and <see cref="TrailingComment"/>
/// carry provenance for round-trip.
/// </summary>
/// <param name="Value">The canonical rule value (see the record summary for the per-kind form).</param>
/// <param name="Kind">The classification per <see cref="Classify"/>.</param>
/// <param name="RawLine">The original raw line (pre comment-strip), for provenance.</param>
/// <param name="TrailingComment">The preserved <c>'#'…</c> inline comment, or <see langword="null"/>.</param>
/// <param name="PrefixSeparator">
/// For a <see cref="IpRuleKind.TextPrefix"/>: the trailing <c>'.'</c> or <c>':'</c> that
/// <see cref="Classify"/> stripped off the core (so the serializer can re-append it BEFORE the
/// <c>'*'</c> and reconstruct a form that re-parses to the same <see cref="Value"/>), or
/// <see langword="null"/> when no separator was stripped. Always <see langword="null"/> for
/// non-prefix kinds. This is provenance for the IC-4 fixed-point round-trip: without it,
/// <c>fe80::*</c> (Value <c>fe80:</c>) would re-emit as <c>fe80:*</c> and silently broaden to
/// <c>fe80</c> on the next parse.
/// </param>
public sealed record IpRule(
    string Value,
    IpRuleKind Kind,
    string RawLine,
    string? TrailingComment,
    char? PrefixSeparator = null)
{
    /// <summary>
    /// Classifies a single comment-stripped, trimmed IP-rule token, replicating dnscrypt-proxy
    /// 2.1.16's <c>LoadIPRules</c> + <c>ParseIPRule</c> shape, but with STRICTER validation than
    /// the proxy (whose skip-and-continue leaves silently-ineffective rules = a fail-open OPSEC
    /// hole). Classification order:
    /// <list type="number">
    ///   <item><b>CIDR</b> — the token contains <c>'/'</c>. Parsed as <c>ip/prefix</c>; the IP is
    ///     masked to its network address; host bits set → a WARNING (canonicalized to the network
    ///     address); a malformed prefix/IP/extra-<c>'/'</c> → an ERROR. A non-canonical <b>IPv4</b>
    ///     base (leading-zero <c>010.0.0.0</c> or short-dotted <c>192.168.1</c>) → an ERROR, mirroring
    ///     Go <c>net.ParseCIDR</c>'s rejection (a non-canonical IPv6 base is still canonicalized,
    ///     matching Go).</item>
    ///   <item><b>TextPrefix</b> — a trailing <c>'*'</c>. The <c>'*'</c> is stripped, then ONE
    ///     trailing <c>'.'</c> or <c>':'</c>. Interior <c>'*'</c>, <c>'@'</c>, brackets, or an
    ///     empty/too-short core → ERROR/WARNING per the proxy's own guards.</item>
    ///   <item><b>Exact</b> — otherwise a bare IP literal. Parsed via <see cref="IPAddress"/>; a
    ///     value whose canonical <see cref="IPAddress.ToString"/> differs from the typed text
    ///     (uncompressed/leading-zero forms) → ERROR (the proxy stores it verbatim and it can
    ///     NEVER match the canonical answer string); <c>'@'</c>, brackets, or an unparseable
    ///     literal → ERROR.</item>
    /// </list>
    /// Never throws except <see cref="ArgumentNullException"/> for a null token.
    /// </summary>
    /// <param name="token">The comment-stripped, trimmed rule text (non-empty; callers filter blanks).</param>
    /// <param name="value">On success, the canonical rule value (see the record summary).</param>
    /// <param name="kind">On success, the classified kind.</param>
    /// <param name="findingSeverity">On any finding, its severity; otherwise ignored.</param>
    /// <param name="message">On a finding, a human-actionable reason; otherwise <see langword="null"/>.</param>
    /// <param name="prefixSeparator">
    /// For an accepted <see cref="IpRuleKind.TextPrefix"/>, the trailing <c>'.'</c>/<c>':'</c>
    /// separator stripped off the core (round-trip provenance; see
    /// <see cref="IpRule.PrefixSeparator"/>), else <see langword="null"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the token is an accepted rule (<paramref name="message"/> may
    /// still be non-null for a Warning that KEEPS the rule); <see langword="false"/> when the token
    /// is rejected (an Error — the caller makes it an <see cref="UnparsedLine"/>).
    /// </returns>
    public static bool Classify(
        string token,
        out string value,
        out IpRuleKind kind,
        out RuleLintSeverity findingSeverity,
        out string? message,
        out char? prefixSeparator)
    {
        ArgumentNullException.ThrowIfNull(token);

        value = token;
        kind = IpRuleKind.Exact;
        findingSeverity = RuleLintSeverity.Error;
        message = null;
        prefixSeparator = null;

        // (1) CIDR: any '/'. The proxy passes the raw trimmed line straight to critbitgo AddCIDR.
        if (token.Contains('/', StringComparison.Ordinal))
        {
            return ClassifyCidr(token, out value, out kind, out findingSeverity, out message);
        }

        // (2) TextPrefix: a trailing '*'.
        if (token.EndsWith('*'))
        {
            return ClassifyTextPrefix(token, out value, out kind, out findingSeverity, out message, out prefixSeparator);
        }

        // (3) Exact IP literal.
        return ClassifyExact(token, out value, out kind, out message);
    }

    private static bool ClassifyExact(
        string token,
        out string value,
        out IpRuleKind kind,
        out string? message)
    {
        value = token;
        kind = IpRuleKind.Exact;
        message = null;

        // Reject '@' up front: IP files have no schedule; the proxy makes 'ip @sched' a dead literal.
        if (token.Contains('@', StringComparison.Ordinal))
        {
            message = $"'{token}' contains '@' — time-based schedules are not supported in blocked_ips/allowed_ips (only in name rules)";
            return false;
        }

        // Reject brackets: response IPs never carry '[' ']'; a bracketed literal is a dead rule.
        if (token.Contains('[', StringComparison.Ordinal) || token.Contains(']', StringComparison.Ordinal))
        {
            message = $"'{token}' has brackets — write an IPv6 address without '[' ']' (e.g. ::1, not [::1])";
            return false;
        }

        // Reject any stray '*' (an interior wildcard reaches here when there is no trailing '*').
        if (token.Contains('*', StringComparison.Ordinal))
        {
            message = $"'{token}' has a '*' that is not a trailing wildcard — '*' may only be the last character of a prefix rule";
            return false;
        }

        if (!IPAddress.TryParse(token, out var ip))
        {
            message = $"'{token}' is not a valid IP address, CIDR, or trailing-'*' prefix";
            return false;
        }

        var canonical = ip.ToString();
        if (!string.Equals(token, canonical, StringComparison.Ordinal))
        {
            // Non-canonical spelling: the proxy stores the verbatim string and matches by canonical
            // string equality, so this rule can NEVER fire (silently ineffective = fail-open).
            message = $"'{token}' is not in canonical form — use '{canonical}' (the proxy matches the canonical spelling and would never match this one)";
            return false;
        }

        value = canonical;
        return true;
    }

    private static bool ClassifyTextPrefix(
        string token,
        out string value,
        out IpRuleKind kind,
        out RuleLintSeverity findingSeverity,
        out string? message,
        out char? prefixSeparator)
    {
        value = token;
        kind = IpRuleKind.TextPrefix;
        findingSeverity = RuleLintSeverity.Error;
        message = null;
        prefixSeparator = null;

        if (token.Contains('@', StringComparison.Ordinal))
        {
            message = $"'{token}' contains '@' — time-based schedules are not supported in blocked_ips/allowed_ips";
            return false;
        }

        if (token.Contains('[', StringComparison.Ordinal) || token.Contains(']', StringComparison.Ordinal))
        {
            message = $"'{token}' has brackets — write a bare IPv6 prefix (e.g. fe80:*)";
            return false;
        }

        // The proxy: len(line) < 2 => 'suspicious IP rule' (so a bare '*' is rejected).
        if (token.Length < 2)
        {
            message = $"'{token}' is too short to be a prefix rule";
            return false;
        }

        // Strip the trailing '*', then ONE trailing '.' or ':' (mirroring ParseIPRule exactly).
        // Remember the stripped separator so the serializer can re-append it BEFORE the '*' and
        // reconstruct a form that re-parses to the same core (IC-4 fixed point). Without this,
        // 'fe80::*' (core 'fe80:') would re-emit as 'fe80:*' and silently broaden to 'fe80'.
        var core = token[..^1];
        if (core.EndsWith('.') || core.EndsWith(':'))
        {
            prefixSeparator = core[^1];
            core = core[..^1];
        }

        if (core.Length == 0)
        {
            message = $"'{token}' is an empty prefix after stripping the wildcard";
            return false;
        }

        // Any remaining '*' is an interior wildcard — the proxy errors ('wildcards can only be
        // used as a suffix') and skips the line.
        if (core.Contains('*', StringComparison.Ordinal))
        {
            message = $"'{token}' has an interior '*' — a wildcard may only be the last character";
            return false;
        }

        value = core;

        // A too-short prefix (from a very short line, e.g. '1*' -> '1') matches broadly and is a
        // footgun; the proxy accepts it, so we KEEP the rule but WARN.
        if (core.Length < 2)
        {
            findingSeverity = RuleLintSeverity.Warning;
            message = $"prefix '{token}' matches very broadly (core '{core}') — consider a more specific prefix or a CIDR";
        }

        return true;
    }

    private static bool ClassifyCidr(
        string token,
        out string value,
        out IpRuleKind kind,
        out RuleLintSeverity findingSeverity,
        out string? message)
    {
        value = token;
        kind = IpRuleKind.Cidr;
        findingSeverity = RuleLintSeverity.Error;
        message = null;

        var slash = token.IndexOf('/', StringComparison.Ordinal);
        var ipPart = token[..slash];
        var prefixPart = token[(slash + 1)..];

        // Exactly one '/', a non-empty IP part, and a numeric prefix.
        if (prefixPart.Contains('/', StringComparison.Ordinal))
        {
            message = $"'{token}' has more than one '/' — a CIDR is 'address/prefix'";
            return false;
        }

        if (!IPAddress.TryParse(ipPart, out var ip))
        {
            message = $"'{token}' has an invalid network address '{ipPart}'";
            return false;
        }

        // Per-family round-trip guard mirroring Go net.ParseCIDR EXACTLY:
        //   - IPv4: Go REJECTS leading-zero / short-dotted forms (010.0.0.0, 1.2.3.04, 192.168.1),
        //     while .NET IPAddress.TryParse silently rewrites them to a DIFFERENT network. Reject
        //     when the typed IPv4 host part is not its own canonical dotted-decimal spelling (the
        //     proxy would drop the rule = fail-open, and we'd otherwise write a wrong network).
        //   - IPv6: Go ACCEPTS leading-zero hextets and canonicalizes them, so we DO NOT guard IPv6
        //     (the Parse_nonCanonicalIpv6CidrBase silent-accept is pinned behavior).
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
            !string.Equals(ipPart, ip.ToString(), StringComparison.Ordinal))
        {
            message = $"'{token}' has a non-canonical IPv4 network address '{ipPart}' (leading-zero or short-dotted forms are rejected by the proxy and the rule would be silently dropped)";
            return false;
        }

        // Parse the prefix STRICTLY (digit-only): NumberStyles.None forbids the leading '+' and
        // leading/trailing whitespace that the default NumberStyles.Integer allows. The proxy's
        // critbitgo AddCIDR wraps Go net.ParseCIDR, whose digit-only prefix scan rejects '+8' and
        // whitespace-bearing prefixes; accepting them here would fail-open (the editor calls the
        // CIDR valid, the proxy silently drops the rule).
        if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
        {
            message = $"'{token}' has a non-numeric prefix length '{prefixPart}'";
            return false;
        }

        var bytes = ip.GetAddressBytes();
        var totalBits = bytes.Length * 8;
        if (prefix < 0 || prefix > totalBits)
        {
            message = $"'{token}' has a prefix length out of range (0..{totalBits} for this address family)";
            return false;
        }

        // Mask to the network address; detect whether any host bits were set.
        var hostBitsSet = false;
        for (var i = 0; i < bytes.Length; i++)
        {
            var bitStart = i * 8;
            var keepInByte = Math.Clamp(prefix - bitStart, 0, 8);
            var mask = keepInByte == 0 ? (byte)0 : (byte)(0xFF << (8 - keepInByte));
            var masked = (byte)(bytes[i] & mask);
            if (masked != bytes[i])
            {
                hostBitsSet = true;
            }

            bytes[i] = masked;
        }

        var network = new IPAddress(bytes);
        value = $"{network}/{prefix}";

        if (hostBitsSet)
        {
            // DOCUMENTED DECISION (pinned by IpRuleFileTests): accept a host-bits-set CIDR,
            // canonicalize to the network address, and WARN.
            findingSeverity = RuleLintSeverity.Warning;
            message = $"'{token}' has host bits set — canonicalized to the network address '{value}'";
        }

        return true;
    }
}
