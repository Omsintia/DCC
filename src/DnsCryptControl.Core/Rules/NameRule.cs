namespace DnsCryptControl.Core.Rules;

/// <summary>
/// The write-time pattern category a name rule is classified into, mirroring dnscrypt-proxy
/// 2.1.16's <c>PatternMatcher.Add</c>. The runtime match precedence differs (Exact → Suffix →
/// Prefix → Substring → Glob), but for round-trip/display we only need the write-time category.
/// </summary>
public enum NamePatternKind
{
    /// <summary>A <c>filepath.Match</c> glob: a <c>?</c> or <c>[</c> anywhere, or an interior <c>*</c>.</summary>
    Glob,

    /// <summary>Leading AND trailing <c>*</c> (e.g. <c>*ads*</c>); the stripped core is matched as a substring.</summary>
    Substring,

    /// <summary>Trailing <c>*</c> only (e.g. <c>ads*</c>); a prefix match.</summary>
    Prefix,

    /// <summary>Leading <c>=</c> (e.g. <c>=exact.example.com</c>); an exact-name match.</summary>
    Exact,

    /// <summary>The default: a domain suffix (e.g. <c>*.example.com</c> ≡ <c>.example.com</c> ≡ <c>example.com</c>).</summary>
    Suffix,
}

/// <summary>
/// One parsed name rule from a blocked_names / allowed_names file. The <see cref="Pattern"/> is
/// the RAW pattern text (comment-stripped, schedule-removed) preserved verbatim for round-trip
/// and display; <see cref="Kind"/> is its write-time classification; <see cref="Schedule"/> is
/// the <c>@name</c> (without the <c>@</c>) when present; <see cref="RawLine"/> and
/// <see cref="TrailingComment"/> carry provenance so the serializer can re-attach comments.
/// </summary>
/// <param name="Pattern">The raw rule pattern (preserved for display/round-trip, NOT lowercased).</param>
/// <param name="Kind">The write-time classification per <see cref="Classify"/>.</param>
/// <param name="Schedule">The <c>@schedule</c> name (without <c>@</c>), or <see langword="null"/>.</param>
/// <param name="RawLine">The original raw line (pre comment-strip), for provenance.</param>
/// <param name="TrailingComment">The preserved <c>'#'…</c> inline comment, or <see langword="null"/>.</param>
public sealed record NameRule(
    string Pattern,
    NamePatternKind Kind,
    string? Schedule,
    string RawLine,
    string? TrailingComment)
{
    /// <summary>
    /// Classifies a raw name <paramref name="pattern"/> (already comment-stripped and with any
    /// <c>@schedule</c> removed) into its <see cref="NamePatternKind"/>, replicating
    /// dnscrypt-proxy 2.1.16's <c>PatternMatcher.Add</c> write-time order (first match wins):
    /// <list type="number">
    ///   <item><b>Glob</b> — <c>isGlobCandidate</c>: a <c>?</c> or <c>[</c> anywhere, or a <c>*</c>
    ///     that is interior (not the first and not the last character). Requires the trimmed
    ///     pattern length ≥ 2.</item>
    ///   <item><b>Substring</b> — leading AND trailing <c>*</c>; the FULL pattern must be ≥ 3
    ///     (proxy: <c>len(pattern) &lt; 3</c>, so <c>*a*</c> is accepted).</item>
    ///   <item><b>Prefix</b> — trailing <c>*</c> only; the FULL pattern must be ≥ 2
    ///     (proxy: <c>len(pattern) &lt; 2</c>, so <c>a*</c> is accepted).</item>
    ///   <item><b>Exact</b> — leading <c>=</c>; the FULL pattern must be ≥ 2
    ///     (proxy: <c>len(pattern) &lt; 2</c>, so <c>=a</c> is accepted).</item>
    ///   <item><b>Suffix</b> — the default; strip one leading <c>*</c> then one leading <c>.</c>; the
    ///     core must be non-empty.</item>
    /// </list>
    /// Classification is on the lowercased pattern (matching the proxy), but callers preserve the
    /// raw text elsewhere. A pattern that is empty after its strip, or that fails a minimum-length
    /// guard, is a lint error (the proxy's <c>Add</c> returns a rule-file error → the line is
    /// skipped). Never throws (except <see cref="ArgumentNullException"/> for a null pattern).
    /// </summary>
    /// <param name="pattern">The raw pattern (no <c>@schedule</c>, no comment).</param>
    /// <param name="kind">On success, the classified kind.</param>
    /// <param name="error">On failure, a human-actionable reason; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the pattern is a valid, non-degenerate rule.</returns>
    public static bool Classify(string pattern, out NamePatternKind kind, out string? error)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        kind = NamePatternKind.Suffix;
        error = null;

        // The proxy lowercases inside Add before classifying/keying. Case does not change the
        // structural markers (* ? [ = .), but we mirror it for fidelity.
        var p = pattern.ToLowerInvariant();

        if (p.Length == 0)
        {
            error = "empty name pattern";
            return false;
        }

        // (1) GLOB: '?' or '[' anywhere, or an INTERIOR '*'.
        if (IsGlobCandidate(p))
        {
            if (p.Length < 2)
            {
                error = $"glob pattern '{pattern}' is too short (need at least 2 characters)";
                return false;
            }

            // The proxy validates a glob candidate via filepath.Match(pattern, "example.com"); an
            // ErrBadPattern (an unterminated '[' character class) makes PatternMatcher.Add return a
            // rule-file syntax error, so the line is silently skipped (fatal for cloaking). We must
            // reject it as a lint error, not silently accept a glob the proxy will drop.
            if (!IsValidGlob(p))
            {
                error = $"glob pattern '{pattern}' is malformed (unterminated '[' character class)";
                return false;
            }

            kind = NamePatternKind.Glob;
            return true;
        }

        // (2) SUBSTRING: leading AND trailing '*'. The proxy guards the FULL (pre-strip) pattern
        // length: `if len(pattern) < 3` — so '*a*' (len 3) and '*ab*' (len 4) are ACCEPTED and only
        // '**' (len 2) is rejected. Guarding the stripped core would over-reject by one char.
        if (p.Length >= 2 && p[0] == '*' && p[^1] == '*')
        {
            if (p.Length < 3)
            {
                error = $"substring pattern '{pattern}' is too short (need at least 3 characters total)";
                return false;
            }

            kind = NamePatternKind.Substring;
            return true;
        }

        // (3) PREFIX: trailing '*' only. FULL-pattern guard `if len(pattern) < 2` — so 'a*' (len 2)
        // is ACCEPTED; only a bare '*' (len 1, which reaches SUFFIX below) is rejected.
        if (p[^1] == '*')
        {
            if (p.Length < 2)
            {
                error = $"prefix pattern '{pattern}' is too short (need at least 2 characters total)";
                return false;
            }

            kind = NamePatternKind.Prefix;
            return true;
        }

        // (4) EXACT: leading '='. FULL-pattern guard `if len(pattern) < 2` — so '=a' (len 2) is
        // ACCEPTED; only a bare '=' (len 1) is rejected.
        if (p[0] == '=')
        {
            if (p.Length < 2)
            {
                error = $"exact pattern '{pattern}' is too short (need at least 2 characters total)";
                return false;
            }

            kind = NamePatternKind.Exact;
            return true;
        }

        // (5) SUFFIX (default): strip one leading '*' then one leading '.'.
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
            error = $"pattern '{pattern}' is empty after stripping wildcard/dot";
            return false;
        }

        kind = NamePatternKind.Suffix;
        return true;
    }

    /// <summary>The fixed probe name the proxy passes to <c>filepath.Match</c> when validating a glob.</summary>
    private const string GlobProbeName = "example.com";

    /// <summary>
    /// Returns <see langword="false"/> exactly when the proxy's
    /// <c>filepath.Match(<paramref name="p"/>, "example.com")</c> would return
    /// <c>filepath.ErrBadPattern</c>. Whether a malformed <c>'['</c> class actually surfaces an
    /// error is <b>name-dependent</b>: a <c>'*'</c> earlier in the pattern can let the match fail
    /// (or succeed) BEFORE the bad bracket chunk is ever scanned (verified against real Go: <c>b*[</c>
    /// is fine, <c>e*[</c> errors — because <c>'e'</c> matches the probe's first char and the
    /// trailing <c>[</c> chunk then gets scanned). So this is a faithful port of Go
    /// <c>path/filepath.Match</c>'s scan against the fixed probe name the proxy uses, and we return
    /// its <c>ErrBadPattern</c> verdict — not a standalone syntactic check.
    /// </summary>
    /// <remarks>
    /// Windows semantics: <c>filepath.Separator == '\\'</c>, so <c>'\\'</c> is NOT an escape char
    /// (Go's <c>path/filepath.Match</c> only escapes when <c>Separator != '\\'</c>). Because the
    /// probe name <c>"example.com"</c> contains no separator, the separator special-casing in
    /// <c>*</c>/<c>?</c>/class matching never changes the outcome for it; only <c>ErrBadPattern</c>
    /// from an actually-scanned class matters.
    /// </remarks>
    private static bool IsValidGlob(string p)
    {
        // A glob candidate is VALID exactly when filepath.Match(p, GlobProbeName) does NOT return
        // ErrBadPattern — mirroring the proxy's PatternMatcher.Add glob validation. The match verdict
        // itself is irrelevant to Add; only the bad-pattern verdict matters.
        return !TryMatchGlob(p, GlobProbeName).badPattern;
    }

    /// <summary>
    /// Evaluates Go <c>path/filepath.Match(<paramref name="pattern"/>, <paramref name="name"/>)</c>
    /// as the proxy does for <see cref="NamePatternKind.Glob"/> rules at RUNTIME, returning whether
    /// the pattern matched the name. A pattern that is not a valid glob (an unterminated <c>'['</c>
    /// class, i.e. <c>ErrBadPattern</c>) never matches. This is the same faithful port A1 already
    /// carries (see <see cref="TryMatchGlob"/> / <see cref="MatchChunk"/>); it is exposed so the A3
    /// cloaking recursion guard can test a CNAME target against a glob cloak pattern without
    /// duplicating the matcher. <paramref name="name"/> is compared as-is (callers lowercase both
    /// sides to mirror the proxy's case-insensitivity). Never throws except
    /// <see cref="ArgumentNullException"/> for a null argument.
    /// </summary>
    /// <param name="pattern">The glob pattern (already classified as <see cref="NamePatternKind.Glob"/>).</param>
    /// <param name="name">The candidate name to match.</param>
    /// <returns><see langword="true"/> when the pattern matches (and is not a bad pattern).</returns>
    public static bool MatchesGlob(string pattern, string name)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(name);

        var (matched, badPattern) = TryMatchGlob(pattern, name);
        return matched && !badPattern;
    }

    /// <summary>
    /// Port of Go <c>path/filepath.Match(pattern, name)</c>: returns whether the pattern matched the
    /// name and whether an <c>ErrBadPattern</c> occurred. On Windows <c>filepath.Separator == '\\'</c>
    /// so <c>'\\'</c> is not an escape; the names we test carry no separator, so the separator
    /// special-casing never changes the outcome. This is the single source of both A1's glob
    /// validation (<see cref="IsValidGlob"/>) and A3's glob matching (<see cref="MatchesGlob"/>).
    /// </summary>
    private static (bool matched, bool badPattern) TryMatchGlob(string p, string startName)
    {
        var name = startName;
        var pattern = p;

        while (pattern.Length > 0)
        {
            // scanChunk: split off the leading (up to the next '*') star-free chunk.
            bool star;
            string chunk;
            (star, chunk, pattern) = ScanChunk(pattern);

            if (star && chunk.Length == 0)
            {
                // Trailing '*' matches the rest of the name — always matches, no bad-pattern.
                return (true, false);
            }

            // Look for a match anchoring at the current position (or, under a '*', at any later
            // position). matchChunk is the only place ErrBadPattern can be raised.
            var (t, ok, err) = MatchChunk(chunk, name);
            // ok so long as the remaining name is not too short for the pattern (matchChunk
            // consumed exactly len(chunk) runes of name).
            if (ok && (t.Length == 0 || pattern.Length > 0))
            {
                name = t;
                continue;
            }

            if (err)
            {
                return (false, true); // ErrBadPattern
            }

            if (star)
            {
                // Look for a match skipping i+1 bytes. On Windows '*' cannot match a Separator, but
                // the tested names have none, so we can advance one char at a time over the name.
                for (var i = 0; i < name.Length; i++)
                {
                    var (t2, ok2, err2) = MatchChunk(chunk, name[(i + 1)..]);
                    if (ok2)
                    {
                        // If the pattern is exhausted, require the name to be too.
                        if (pattern.Length == 0 && t2.Length > 0)
                        {
                            continue;
                        }

                        name = t2;
                        goto continueOuter;
                    }

                    if (err2)
                    {
                        return (false, true); // ErrBadPattern
                    }
                }
            }

            // No match and no bad pattern: filepath.Match returns (false, nil).
            return (false, false);

            continueOuter:;
        }

        // Consumed the whole pattern: matched iff the name is also exhausted (Match requires a full
        // name match, not a prefix).
        return (name.Length == 0, false);
    }

    /// <summary>
    /// Port of Go <c>path/filepath.scanChunk</c>: strips leading <c>'*'</c>s (collapsing runs),
    /// then returns the next <c>'*'</c>-free chunk and the remaining pattern. <c>'\\'</c> is not an
    /// escape on Windows, so it is treated as an ordinary chunk byte.
    /// </summary>
    private static (bool star, string chunk, string rest) ScanChunk(string pattern)
    {
        var star = false;
        while (pattern.Length > 0 && pattern[0] == '*')
        {
            pattern = pattern[1..];
            star = true;
        }

        var inrange = false;
        int i;
        for (i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '[')
            {
                inrange = true;
            }
            else if (c == ']')
            {
                inrange = false;
            }
            else if (c == '*')
            {
                if (!inrange)
                {
                    break;
                }
            }
        }

        return (star, pattern[..i], pattern[i..]);
    }

    /// <summary>
    /// Port of Go <c>path/filepath.matchChunk</c> for Windows (<c>'\\'</c> is not an escape).
    /// Returns the unmatched remainder of <paramref name="s"/>, whether the chunk matched a prefix,
    /// and whether an <c>ErrBadPattern</c> occurred. On Windows, <c>'*'</c>/<c>'?'</c>/classes do
    /// not match the path separator <c>'\\'</c>; the probe name has none, so this only ever affects
    /// the error verdict, not correctness for our purpose.
    /// </summary>
    private static (string rest, bool ok, bool err) MatchChunk(string chunk, string s)
    {
        var failed = false;
        var idx = 0;
        while (idx < chunk.Length)
        {
            if (!failed && s.Length == 0)
            {
                failed = true;
            }

            var c = chunk[idx];
            switch (c)
            {
                case '[':
                    // Character class.
                    var r = '\0';
                    if (!failed)
                    {
                        r = s[0];
                        s = s[1..];
                    }

                    idx++; // consume '['

                    // Optional leading '^' negation.
                    var negated = false;
                    if (idx < chunk.Length && chunk[idx] == '^')
                    {
                        negated = true;
                        idx++;
                    }

                    var match = false;
                    var nrange = 0;
                    while (true)
                    {
                        if (idx < chunk.Length && chunk[idx] == ']' && nrange > 0)
                        {
                            idx++; // consume closing ']'
                            break;
                        }

                        if (!GetEsc(chunk, ref idx, out var lo))
                        {
                            return ("", false, true); // ErrBadPattern
                        }

                        var hi = lo;
                        if (idx < chunk.Length && chunk[idx] == '-')
                        {
                            idx++; // consume '-'
                            if (!GetEsc(chunk, ref idx, out hi))
                            {
                                return ("", false, true); // ErrBadPattern
                            }
                        }

                        if (lo <= r && r <= hi)
                        {
                            match = true;
                        }

                        nrange++;
                    }

                    if (match == negated)
                    {
                        failed = true;
                    }

                    break;

                case '?':
                    if (!failed)
                    {
                        // On Windows '?' does not match the separator; probe has none.
                        if (s[0] == '\\')
                        {
                            failed = true;
                        }

                        s = s[1..];
                    }

                    idx++;
                    break;

                default:
                    // Literal char (no '\' escape on Windows).
                    if (!failed)
                    {
                        if (s.Length == 0 || s[0] != c)
                        {
                            failed = true;
                        }
                        else
                        {
                            s = s[1..];
                        }
                    }

                    idx++;
                    break;
            }
        }

        if (failed)
        {
            return ("", false, false);
        }

        return (s, true, false);
    }

    /// <summary>
    /// Port of Go <c>path/filepath.getEsc</c> for Windows (no <c>'\\'</c> escape): reads one class
    /// member char from <paramref name="chunk"/> at <paramref name="idx"/>. Returns
    /// <see langword="false"/> (<c>ErrBadPattern</c>) when the class body is empty or the next char
    /// is <c>'-'</c> or <c>']'</c> — those cannot begin a member.
    /// </summary>
    private static bool GetEsc(string chunk, ref int idx, out char c)
    {
        c = '\0';
        if (idx >= chunk.Length || chunk[idx] == '-' || chunk[idx] == ']')
        {
            return false;
        }

        c = chunk[idx];
        idx++;
        return true;
    }

    /// <summary>
    /// <c>isGlobCandidate</c>: true when the pattern contains a <c>?</c> or <c>[</c> anywhere, or a
    /// <c>*</c> that is interior (not at index 0 and not at the last index). A leading-only or
    /// trailing-only <c>*</c> is NOT a glob.
    /// </summary>
    private static bool IsGlobCandidate(string p)
    {
        for (var i = 0; i < p.Length; i++)
        {
            var c = p[i];
            if (c is '?' or '[')
            {
                return true;
            }

            if (c == '*' && i != 0 && i != p.Length - 1)
            {
                return true;
            }
        }

        return false;
    }
}
