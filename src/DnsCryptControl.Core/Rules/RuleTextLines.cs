namespace DnsCryptControl.Core.Rules;

/// <summary>
/// The shared loader spine for dnscrypt-proxy 2.1.16 rule files (blocked_names, allowed_names,
/// blocked_ips, allowed_ips, cloaking, forwarding). Reimplements <c>common.go</c>'s
/// <c>ProcessConfigLines</c> pre-tokenisation byte-for-byte so the in-app editor and the proxy
/// always agree about which bytes are the rule:
/// <list type="number">
///   <item>one leading UTF-8 BOM (U+FEFF) is stripped;</item>
///   <item>the file is split on <c>'\n'</c> (LF only) — a trailing <c>'\r'</c> from a CRLF file is
///     eaten by the per-line whitespace trim, not by the splitter;</item>
///   <item>each line runs through <see cref="StripInlineComment"/>, the quirky
///     <c>TrimAndStripInlineComments</c> where only the LAST <c>'#'</c> is considered, a line whose
///     FIRST byte is <c>'#'</c> (or whose last <c>'#'</c> is at index 0) is a whole-line comment,
///     and an inline <c>'#'</c> strips only when the character immediately before it is a space or
///     tab.</item>
/// </list>
/// A2/A3/A4 (IP, cloaking, forwarding parsers) reuse these pure static helpers — this is the
/// load-bearing reusable API for the whole Phase 5d rule surface. Fail-closed: never throws.
/// </summary>
public static class RuleTextLines
{
    private const char Bom = '\uFEFF'; // the UTF-8 BOM code point (escape form - a literal is invisible/unreviewable)

    /// <summary>
    /// Splits <paramref name="text"/> into raw lines exactly as the proxy's loader does: strip one
    /// leading UTF-8 BOM, then split on <c>'\n'</c>. Trailing <c>'\r'</c> characters are left on the
    /// returned lines (they are removed later by <see cref="StripInlineComment"/>'s trim, matching
    /// the proxy which TrimSpaces each line). A <see langword="null"/> input yields no lines.
    /// </summary>
    /// <remarks>
    /// The number and order of returned lines is provenance for round-trip: a trailing <c>'\n'</c>
    /// produces a final empty line, mirroring the file's real line count.
    /// </remarks>
    public static IReadOnlyList<string> SplitLines(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return Array.Empty<string>();
        }

        // Strip exactly ONE leading BOM (a second BOM is content).
        if (text[0] == Bom)
        {
            text = text[1..];
        }

        return text.Split('\n');
    }

    /// <summary>
    /// Applies dnscrypt-proxy 2.1.16's <c>TrimAndStripInlineComments</c> to a single raw line and
    /// returns the rule content plus any stripped trailing comment (preserved verbatim for
    /// round-trip). The semantics are byte-exact and deliberately quirky:
    /// <list type="bullet">
    ///   <item>only the <b>last</b> <c>'#'</c> in the line is considered;</item>
    ///   <item>if that <c>'#'</c> is at index 0 <b>OR</b> the line's first byte is <c>'#'</c>, the
    ///     whole line is a comment (<paramref name="content"/> is empty) — so <c>#a b #c</c> is a
    ///     comment despite its later space-preceded <c>'#'</c>, mirroring the proxy's
    ///     <c>idx == 0 || str[0] == '#'</c>;</item>
    ///   <item>if the character immediately before that <c>'#'</c> is a space or tab, the line is
    ///     cut at the <c>'#'</c> — the left part (trimmed) is the content and <c>'#'…</c> is the
    ///     comment;</item>
    ///   <item>otherwise (a non-space char immediately before, e.g. <c>a#b</c>) the <c>'#'</c> is
    ///     literal — the whole line (trimmed) is content and there is no comment.</item>
    /// </list>
    /// In every case the returned <paramref name="content"/> has leading/trailing whitespace
    /// trimmed (this also removes a CRLF's trailing <c>'\r'</c>), matching the proxy's final
    /// <c>TrimSpace</c>. The returned comment is the raw <c>'#'…</c> tail with trailing whitespace
    /// removed (so a CRLF <c>'\r'</c> does not leak into it).
    /// </summary>
    /// <returns>
    /// <c>content</c>: the rule text after comment strip and trim (may be empty).
    /// <c>comment</c>: the preserved <c>'#'…</c> tail, or <see langword="null"/> when the line has
    /// no comment (including the literal-<c>'#'</c> case).
    /// </returns>
    public static (string content, string? comment) StripInlineComment(string line)
    {
        ArgumentNullException.ThrowIfNull(line);

        var hash = line.LastIndexOf('#');
        if (hash < 0)
        {
            // No '#': the whole (trimmed) line is content.
            return (Trim(line), null);
        }

        // The proxy's full-comment condition is `idx == 0 || str[0] == '#'` (str is the RAW line):
        // a line whose FIRST byte is '#' is wholly a comment EVEN when a later space-preceded '#'
        // exists (e.g. '#a b #c'). `hash >= 0` already guarantees `line` is non-empty, so line[0]
        // is safe.
        if (hash == 0 || line[0] == '#')
        {
            // Full-line comment: no content, the whole line is the comment.
            return ("", TrimEnd(line));
        }

        var before = line[hash - 1];
        if (before is ' ' or '\t')
        {
            // Inline comment: cut at '#'. Left is content (trimmed); '#'… is the comment.
            var content = Trim(line[..hash]);
            var comment = TrimEnd(line[hash..]);
            return (content, comment);
        }

        // Literal '#': the char before it is not whitespace, so it is part of the rule.
        return (Trim(line), null);
    }

    // The proxy uses Go's strings.TrimSpace, which trims all Unicode whitespace. Rule files are
    // ASCII in practice; we trim the ASCII whitespace set the loader actually encounters (space,
    // tab, CR, LF, VT, FF) plus general whitespace, so a CRLF '\r' is always removed.
    private static string Trim(string s) => s.Trim();

    private static string TrimEnd(string s) => s.TrimEnd();
}
