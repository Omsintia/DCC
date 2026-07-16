using System.Globalization;
using System.Text;
using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.Core.Sources;

/// <summary>
/// Parses the v2 resolver/relay list format (public-resolvers.md / relays.md) exactly as
/// dnscrypt-proxy 2.1.16's <c>parseV2</c> reads it, with deliberate hardening. Fail-closed:
/// never throws; hostile input yields typed results, size caps bound the work.
/// </summary>
public static class ResolverListParser
{
    /// <summary>Reject/truncate input larger than this (real files are ~170 KB + ~64 KB).</summary>
    public const int MaxFileChars = 4_000_000;

    /// <summary>Per-line cap (a hostile list could pad a single line arbitrarily).</summary>
    public const int MaxLineChars = 8192;

    /// <summary>Description display cap.</summary>
    public const int MaxDescriptionChars = 4096;

    /// <summary>Entry/block-count cap (bounds both entries and the malformed-block warning flood).</summary>
    public const int MaxEntries = 8192;

    /// <summary>Per-entry stamp-candidate cap (a hostile entry could list unbounded sdns: lines).</summary>
    public const int MaxStampsPerEntry = 256;

    /// <summary>
    /// Parses <paramref name="text"/> with the given source <paramref name="prefix"/> (prepended to
    /// each entry name, matching dnscrypt-proxy — the prefixed name is the config identity).
    /// </summary>
    public static ResolverListParseResult Parse(string? text, string prefix)
    {
        prefix ??= "";
        if (text is null) return ResolverListParseResult.Invalid();

        var truncated = false;
        if (text.Length > MaxFileChars)
        {
            text = text[..MaxFileChars];
            truncated = true;
        }

        // Split on the literal substring "## " (NOT line-anchored) — bug-compatible with parseV2.
        var parts = text.Split("## ");
        if (parts.Length < 2) return ResolverListParseResult.Invalid(truncated);

        var entries = new List<ResolverListEntry>();
        var warnings = new List<string>();
        int? proxyStop = null;
        var seenNames = new HashSet<string>(StringComparer.Ordinal);

        for (var p = 1; p < parts.Length; p++)  // parts[0] is the discarded preamble
        {
            // Cap on TOTAL blocks processed (not just added entries) so a flood of bare "## "
            // delimiters can't run millions of iterations appending millions of warnings.
            if (p - 1 >= MaxEntries) { truncated = true; break; }

            var lines = parts[p].Trim().Split('\n');

            // Hard-abort classes: a block with < 2 lines, or an empty name. dnscrypt-proxy
            // returns the entries parsed so far + an error and drops the rest; we record the
            // point and CONTINUE (so the UI can show the whole file) but mark it.
            if (lines.Length < 2)
            {
                proxyStop ??= entries.Count;
                warnings.Add("Malformed entry block (the proxy would stop loading here).");
                continue;
            }
            var rawName = lines[0].Trim();
            if (rawName.Length == 0)
            {
                proxyStop ??= entries.Count;
                warnings.Add("Empty server name (the proxy would stop loading here).");
                continue;
            }

            var name = prefix + rawName;

            var stampStrings = new List<string>();
            var descBuilder = new StringBuilder();
            for (var i = 1; i < lines.Length; i++)
            {
                var sub = lines[i].Trim();
                if (sub.Length > MaxLineChars) sub = sub[..MaxLineChars];
                if (sub.StartsWith("sdns:", StringComparison.Ordinal) && sub.Length >= 6)
                {
                    if (stampStrings.Count < MaxStampsPerEntry) stampStrings.Add(sub);
                }
                else if (sub.Length == 0 || sub.StartsWith("//", StringComparison.Ordinal))
                    continue; // blank or comment
                else
                {
                    if (descBuilder.Length > 0) descBuilder.Append('\n');
                    descBuilder.Append(sub);
                }
            }

            var anomalies = new List<string>();
            var description = Sanitize(descBuilder.ToString(), anomalies);
            if (description.Length > MaxDescriptionChars) description = description[..MaxDescriptionChars];

            var stamps = new List<ServerStamp>();
            var stampErrors = new List<StampParseError>();
            foreach (var s in stampStrings)
            {
                if (ServerStampParser.TryParse(s, out var stamp, out var error) && stamp is not null)
                    stamps.Add(stamp);
                else
                    stampErrors.Add(error);
            }

            if (stampStrings.Count == 0)
                warnings.Add($"Missing stamp for server [{name}].");
            else if (stamps.Count == 0)
                warnings.Add($"No usable stamp for server [{name}].");

            if (stamps.Count > 1 && stamps.Select(s => s.Protocol).Distinct().Count() > 1)
                anomalies.Add("Mixed protocols across stamps — the proxy picks one at random.");

            if (!seenNames.Add(name))
                warnings.Add($"Duplicate server name [{name}] — a later definition overrides the earlier stamp.");

            var selectable = IsSelectableName(name) && stamps.Count > 0;

            entries.Add(new ResolverListEntry(
                name, rawName, description, stampStrings, stamps, stampErrors, selectable, anomalies));
        }

        return new ResolverListParseResult(entries, warnings, proxyStop, WholeFileInvalid: false, truncated);
    }

    /// <summary>IC-7 selection allowlist — only names matching this may be written into config
    /// (the shared predicate lives in <see cref="ServerNamePolicy"/>).</summary>
    private static bool IsSelectableName(string name) => ServerNamePolicy.IsAllowedName(name);

    /// <summary>
    /// Strips control characters and Unicode bidi-override / zero-width code points from
    /// attacker-influenced description text (homoglyph/name-spoofing defense in an OPSEC UI),
    /// preserving newlines and tabs. Records an anomaly when anything was removed.
    /// </summary>
    private static string Sanitize(string s, List<string> anomalies)
    {
        var sb = new StringBuilder(s.Length);
        var stripped = false;
        foreach (var c in s)
        {
            if (c is '\n' or '\t') { sb.Append(c); continue; }
            if (IsBidiOrZeroWidth(c) || char.IsControl(c)) { stripped = true; continue; }
            sb.Append(c);
        }
        if (stripped)
            anomalies.Add("Description contained bidirectional/zero-width or control characters (removed for display).");
        return sb.ToString();
    }

    // Every Unicode Format (Cf) code point is invisible/directional - bidi marks (LRM/RLM/ALM),
    // embeddings/overrides, isolates, zero-width space/joiners, word joiner, BOM, etc. - so
    // stripping the whole category (plus the two line/paragraph separators U+2028/U+2029, which
    // are Zl/Zp and NOT Cf and NOT char.IsControl) covers the spoofing surface without a list.
    private static bool IsBidiOrZeroWidth(char c)
    {
        if (c == 0x2028 || c == 0x2029) return true; // line / paragraph separators
        return CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.Format;
    }
}
