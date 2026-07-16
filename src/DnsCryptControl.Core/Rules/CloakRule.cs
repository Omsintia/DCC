using System.Net;

namespace DnsCryptControl.Core.Rules;

/// <summary>
/// One parsed cloaking rule from a cloaking_rules file: a <see cref="NamePattern"/> (the shared
/// name-pattern taxonomy, reusing <see cref="NameRule.Classify"/>) mapped to a single
/// <see cref="Target"/> that is either an IP literal (<see cref="IsIp"/> true, decided by an
/// <see cref="IPAddress.TryParse"/> + canonical round-trip test faithful to the proxy's
/// <c>net.ParseIP</c>) or a CNAME domain
/// (<see cref="IsIp"/> false). The grammar is EXACTLY TWO whitespace-separated tokens per
/// meaningful line — multiple IPs for one name are expressed as REPEATED single-target lines
/// (never a comma list or two targets on one line), mirroring dnscrypt-proxy 2.1.16's
/// <c>plugin_cloak.go</c> <c>loadRules</c> (a comma-bearing token fails <c>net.ParseIP</c> and is
/// stored as a bogus CNAME, so our serializer never emits commas).
/// <para>
/// <see cref="NamePattern"/> and <see cref="Target"/> are preserved verbatim (RAW case) for
/// display/round-trip; equality/recursion checks lowercase them (the proxy is fully
/// case-insensitive). <see cref="RawLine"/> and <see cref="TrailingComment"/> carry round-trip
/// provenance.
/// </para>
/// </summary>
/// <param name="NamePattern">The raw name pattern (preserved for display/round-trip, NOT lowercased).</param>
/// <param name="Target">The raw target token (an IP literal or a CNAME domain), preserved verbatim.</param>
/// <param name="IsIp"><see langword="true"/> when <see cref="Target"/> parses as an IP literal.</param>
/// <param name="RawLine">The original raw line (pre comment-strip), for provenance.</param>
/// <param name="TrailingComment">The preserved <c>'#'…</c> inline comment, or <see langword="null"/>.</param>
public sealed record CloakRule(
    string NamePattern,
    string Target,
    bool IsIp,
    string RawLine,
    string? TrailingComment)
{
    /// <summary>
    /// Classifies a comment-stripped, trimmed cloaking line's already-tokenized
    /// <paramref name="name"/> and <paramref name="target"/> (callers do the exactly-two-token
    /// split). Validates the NAME through the shared <see cref="NameRule.Classify"/> — a degenerate
    /// pattern (<c>*</c>, <c>=</c>, <c>.</c>, <c>**</c>, empty-after-strip, a glob
    /// <c>filepath.Match</c> rejects) is a FATAL start-blocker (the proxy's <c>Add</c> propagates
    /// the error → <c>Init</c> aborts) so it becomes an <see cref="RuleLintSeverity.Error"/>. Also
    /// rejects an <c>'@'</c> anywhere (cloaking has NO schedule support; <c>'@'</c> would be a bogus
    /// 3rd token or an invalid target and the line is silently dropped). The target's IP-ness is
    /// decided by <see cref="IsGoParseableIp"/> — an <see cref="IPAddress.TryParse"/> plus a
    /// canonical round-trip that matches Go <c>net.ParseIP</c>, so a non-canonical spelling (e.g.
    /// <c>1.2.3.04</c>, <c>fe80::1%eth0</c>) falls through to CNAME and is recursion-checked instead
    /// of skipped (recursion is checked separately across the whole file). Never throws except
    /// <see cref="ArgumentNullException"/> for a null argument.
    /// </summary>
    /// <param name="name">The first token (the name pattern).</param>
    /// <param name="target">The second token (the IP or CNAME target).</param>
    /// <param name="isIp">On success, whether <paramref name="target"/> is an IP literal.</param>
    /// <param name="error">On failure, a human-actionable reason; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the rule is a valid, non-degenerate cloak rule.</returns>
    public static bool Classify(string name, string target, out bool isIp, out string? error)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(target);

        isIp = false;
        error = null;

        // Cloaking has NO '@schedule' support. A blocklist-style 'name @sched' would make '@sched' a
        // bogus 3rd token OR (as here) an invalid target; the proxy silently drops the line. Reject
        // it explicitly rather than let it be silently discarded.
        if (name.Contains('@', StringComparison.Ordinal) || target.Contains('@', StringComparison.Ordinal))
        {
            error = $"cloaking does not support '@schedule' (in '{name} {target}') — schedules are only valid in blocked_names/allowed_names";
            return false;
        }

        // The NAME is classified through the SHARED taxonomy. A degenerate pattern is FATAL for
        // cloaking (Add's error propagates through Init and the proxy won't start), so Classify's
        // failure is an Error-level blocker, not a warn.
        if (!NameRule.Classify(name, out _, out var nameError))
        {
            error = $"cloak name pattern is invalid and would prevent the proxy from starting: {nameError}";
            return false;
        }

        // IP vs CNAME target: exactly the proxy's net.ParseIP test. A comma-list or any non-IP token
        // is a CNAME (never split — the serializer emits one target per line).
        isIp = IsGoParseableIp(target);
        return true;
    }

    /// <summary>
    /// Returns <see langword="true"/> only when <paramref name="target"/> parses as an IP literal
    /// AND its canonical <see cref="IPAddress.ToString"/> round-trips to the SAME text — matching Go
    /// <c>net.ParseIP</c> (as used by dnscrypt-proxy 2.1.16's <c>plugin_cloak.go</c>) rather than the
    /// more lenient <see cref="IPAddress.TryParse"/>. .NET's parser accepts forms Go returns nil for
    /// (leading-zero octets <c>1.2.3.04</c>/<c>010.0.0.1</c>, short dotted forms <c>1.2.3</c>/<c>1</c>,
    /// <c>0x</c>-hex, and IPv6 zone IDs <c>fe80::1%eth0</c>); those all fail the canonical
    /// round-trip. This fidelity is load-bearing: when the proxy sees <c>net.ParseIP == nil</c> it
    /// treats the token as a CNAME and runs its recursive-cloaking start-blocker check on it, so a
    /// non-canonical target MUST fall through to CNAME (<see langword="false"/> here) to be
    /// recursion-checked instead of skipped. Mirrors the A2 <c>IpRule.ClassifyExact</c> canonical
    /// guard, which the proxy needs for the same reason (it matches canonical string equality).
    /// </summary>
    private static bool IsGoParseableIp(string target) =>
        IPAddress.TryParse(target, out var ip) &&
        string.Equals(target, ip.ToString(), StringComparison.Ordinal);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="candidateName"/> would be matched by this
    /// rule's <see cref="NamePattern"/> under dnscrypt-proxy 2.1.16's runtime match semantics
    /// (<c>PatternMatcher.Eval</c>). Used for recursive-cloaking detection: a <c>=cname</c> target
    /// that matches any cloak name pattern in the file is a FATAL start-blocker. Matching is
    /// case-insensitive (both sides lowercased) and covers all five categories:
    /// <list type="bullet">
    ///   <item><b>Exact</b> (<c>=x</c>): the name equals <c>x</c>.</item>
    ///   <item><b>Suffix</b> (default; strip one <c>*</c> then one <c>.</c>): the name equals the
    ///     suffix, or ends with <c>"." + suffix</c> (a label boundary).</item>
    ///   <item><b>Prefix</b> (<c>x*</c>): the name starts with <c>x</c>.</item>
    ///   <item><b>Substring</b> (<c>*x*</c>): <c>x</c> occurs anywhere in the name.</item>
    ///   <item><b>Glob</b>: Go <c>filepath.Match</c> against the name (reused via
    ///     <see cref="NameRule.MatchesGlob"/>).</item>
    /// </list>
    /// This is a pure structural port used only for the save-time recursion guard; it does not need
    /// the trie's longest-prefix precedence (any category match is enough to flag recursion).
    /// Never throws except <see cref="ArgumentNullException"/> for a null argument.
    /// </summary>
    /// <param name="pattern">The raw cloak name pattern (as stored on a rule).</param>
    /// <param name="candidateName">The candidate name to test (e.g. a CNAME target).</param>
    /// <returns><see langword="true"/> when the pattern matches the candidate.</returns>
    public static bool PatternMatches(string pattern, string candidateName)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(candidateName);

        var p = pattern.ToLowerInvariant();
        var name = candidateName.ToLowerInvariant();

        if (p.Length == 0 || name.Length == 0)
        {
            return false;
        }

        // Classify the pattern the same way the writer/loader does. A pattern that fails to classify
        // never gets Added, so it can never match at runtime.
        if (!NameRule.Classify(p, out var kind, out _))
        {
            return false;
        }

        switch (kind)
        {
            case NamePatternKind.Exact:
                // '=x' -> strip '='.
                return string.Equals(name, p[1..], StringComparison.Ordinal);

            case NamePatternKind.Prefix:
                // 'x*' -> strip trailing '*'.
                return name.StartsWith(p[..^1], StringComparison.Ordinal);

            case NamePatternKind.Substring:
                // '*x*' -> strip both stars.
                return name.Contains(p[1..^1], StringComparison.Ordinal);

            case NamePatternKind.Glob:
                return NameRule.MatchesGlob(p, name);

            case NamePatternKind.Suffix:
            default:
                // Default: strip one leading '*' then one leading '.'. Match on a full name or a
                // '.'-boundary parent (so 'example.com' matches 'example.com' and 'a.example.com').
                var suffix = p;
                if (suffix.StartsWith('*'))
                {
                    suffix = suffix[1..];
                }

                if (suffix.StartsWith('.'))
                {
                    suffix = suffix[1..];
                }

                if (suffix.Length == 0)
                {
                    return false;
                }

                return string.Equals(name, suffix, StringComparison.Ordinal) ||
                       name.EndsWith("." + suffix, StringComparison.Ordinal);
        }
    }
}
