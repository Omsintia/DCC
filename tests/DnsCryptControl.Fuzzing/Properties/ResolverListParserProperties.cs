using System.Globalization;
using CsCheck;
using DnsCryptControl.Core.Sources;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for <see cref="ResolverListParser.Parse"/> - the parser for
/// public-resolvers.md / relays.md / odoh-servers.md, i.e. DOWNLOADED, untrusted-remote content
/// (an attacker who controls a list source, a mirror, or a MITM of the fetch controls every byte).
/// Four invariant families are asserted, all at scale:
/// (1) TOTALITY - Parse never throws for any string or null and always returns a non-null result
///     (fail-closed: null / no-delimiter text yields a WholeFileInvalid result, never an exception);
/// (2) BOUNDED OUTPUT - the size caps hold regardless of input: Entries.Count is at most MaxEntries
///     (the block cap counts ALL "## " delimiters, so a delimiter flood cannot balloon the output),
///     every entry's StampStrings.Count is at most MaxStampsPerEntry, and every Description.Length is
///     at most MaxDescriptionChars - the anti-amplification guard the harness exists to prove;
/// (3) SANITIZED DESCRIPTION - every emitted Description is free of control characters (bar the
///     preserved newline / tab), Unicode Format (Cf) bidi/zero-width code points, and the line /
///     paragraph separators U+2028 / U+2029 - the homoglyph/spoof defense on display text. (The
///     NAME is rendered VERBATIM, not sanitized; its spoof defense is the selectability gate below.)
/// (4) SELECTABILITY IMPLIES ALLOWLIST - IsSelectable implies the prefixed name passes the IC-7
///     allowlist ([A-Za-z0-9._-], length 1..64) AND the entry has a usable stamp, so a hostile name
///     can be rendered but never written into config; since the allowlist admits no control/format/
///     separator code point, a SELECTABLE name is transitively spoof-free.
/// See the fuzzing design notes.
/// </summary>
public class ResolverListParserProperties
{
    // ------------------------------------------------------------------ totality (raw text + null)

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Parse_never_throws_on_arbitrary_text() =>
        // Mostly non-list text: exercises the "## " split, the fewer-than-2-parts early-out, and the
        // whole-file-invalid path. Every invariant is folded into the oracle so a throw is the only
        // way (besides a broken post-condition) to fail.
        Gen.String.Sample(AllInvariants, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Parse_never_throws_on_prefixed_text() =>
        // A "## " lead-in forces the per-block path (name trim, description build, stamp scan) instead
        // of the whole-file-invalid early-out, so the entry-producing code is what gets fuzzed.
        Gen.String.Select(s => "## " + s).Sample(AllInvariants, iter: Fuzz.Iter);

    [Fact]
    public void Parse_null_text_is_whole_file_invalid_not_a_throw()
    {
        var result = ResolverListParser.Parse(null, prefix: "");
        Assert.NotNull(result);
        Assert.True(result.WholeFileInvalid);
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void Parse_null_prefix_is_tolerated()
    {
        // prefix ??= "" inside Parse, so a null prefix must not throw.
        var result = ResolverListParser.Parse("## name\n\ndesc\n", prefix: null!);
        Assert.NotNull(result);
    }

    // ------------------------------------------------------------------ structured list bodies

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Parse_holds_all_invariants_on_structured_lists() =>
        // Realistic-ish blocks assembled from names, descriptions (seeded with bidi/zero-width/control
        // runes), sdns: lines and bare "## " delimiters - lands squarely on the caps and the sanitizer.
        ListBodyGen.Sample(AllInvariants, iter: Fuzz.Iter);

    // ------------------------------------------------------------------ the caps, driven directly

    [Fact]
    [Trait("Category", "Fuzz")]
    public void DelimiterFlood_keeps_entries_and_warnings_bounded() =>
        // A flood of bare "## " delimiters: the block cap must count ALL delimiters (p - 1 >= MaxEntries),
        // so neither Entries nor the per-block warning stream can exceed the cap-derived bound.
        Gen.Int[0, MaxEntriesProbe].Sample(count =>
        {
            var flood = string.Concat(Enumerable.Repeat(FloodDelimiter, count));
            var result = ResolverListParser.Parse(flood, prefix: "");
            // Bare blocks add at most one "malformed"/"empty-name" warning each and never an entry;
            // the block cap bounds processed blocks at MaxEntries, so both counts are cap-bounded.
            return result.Entries.Count <= ResolverListParser.MaxEntries
                && result.Warnings.Count <= ResolverListParser.MaxEntries;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void StampFlood_caps_stamp_candidates_per_entry() =>
        // A single entry padded with a huge run of sdns: lines: StampStrings must be capped at
        // MaxStampsPerEntry no matter how many candidates the attacker lists.
        Gen.Int[0, StampFloodProbe].Sample(count =>
        {
            var body = "## flood\n\n" + string.Concat(Enumerable.Repeat(StampLine, count));
            var result = ResolverListParser.Parse(body, prefix: "");
            return result.Entries.All(e => e.StampStrings.Count <= ResolverListParser.MaxStampsPerEntry);
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void GiantDescriptionLine_is_length_capped() =>
        // One description line padded far past the caps: the emitted Description must be clamped to
        // MaxDescriptionChars regardless of the raw line length.
        Gen.Int[0, GiantLineProbe].Sample(len =>
        {
            var body = "## big\n\n" + new string('x', len) + "\n";
            var result = ResolverListParser.Parse(body, prefix: "");
            return result.Entries.All(e => e.Description.Length <= ResolverListParser.MaxDescriptionChars);
        }, iter: Fuzz.Iter);

    // ------------------------------------------------------------------ regression anchors

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("## ")]
    [InlineData("## \n")]
    [InlineData("##  \n\n\n")]
    [InlineData("# just a header\nno entries here\n")]  // no delimiter -> whole-file-invalid
    public void Parse_hostile_inputs_never_throw_and_stay_sanitized(string? text)
    {
        var result = ResolverListParser.Parse(text, prefix: "");
        Assert.NotNull(result);
        Assert.True(AllInvariantsOfResult(result));
    }

    [Fact]
    public void Parse_bidi_override_in_description_is_stripped_and_flagged()
    {
        // U+202E RIGHT-TO-LEFT OVERRIDE embedded between two ASCII runs.
        var body = "## a\n\nsafe" + Rlo + "evil\n";
        var result = ResolverListParser.Parse(body, prefix: "");
        var entry = Assert.Single(result.Entries);
        Assert.DoesNotContain(Rlo, entry.Description);
        Assert.NotEmpty(entry.Anomalies);
        Assert.True(AllInvariantsOfResult(result));
    }

    [Fact]
    public void Parse_zero_width_and_separators_in_description_are_stripped()
    {
        // Zero-width space, zero-width non-joiner, and the line / paragraph separators.
        var body = "## a\n\nd" + Zwsp + "e" + Zwnj + "s" + LineSep + "c" + ParaSep + "x\n";
        var result = ResolverListParser.Parse(body, prefix: "");
        var entry = Assert.Single(result.Entries);
        Assert.True(IsSanitizedDescription(entry.Description));
        Assert.NotEmpty(entry.Anomalies);
    }

    [Fact]
    public void Parse_control_char_in_name_is_not_selectable()
    {
        // A BEL (U+0007) inside the raw name: the parser renders the name VERBATIM (names are not
        // sanitized - only Descriptions are), so the code-enforced defense is that such a name is
        // never selectable and thus never written into config.
        var body = "## a" + Bel + "b\n\ndesc\nsdns://x\n";
        var result = ResolverListParser.Parse(body, prefix: "");
        var entry = Assert.Single(result.Entries);
        Assert.False(entry.IsSelectable);       // the IC-7 allowlist gate refuses a control char
        Assert.Contains(Bel, entry.Name);       // documents the gap: the name is rendered unsanitized
        Assert.True(AllInvariantsOfResult(result));
    }

    // ------------------------------------------------------------------ the oracle

    /// <summary>The full oracle applied to a raw input string: Parse never throws (reaching this method
    /// at all proves that), returns non-null, and the parsed result satisfies every documented
    /// invariant. A false return shrinks to the minimal offending input.</summary>
    private static bool AllInvariants(string text)
    {
        var result = ResolverListParser.Parse(text, prefix: "");
        return result is not null && AllInvariantsOfResult(result);
    }

    /// <summary>Boundedness + description-sanitization + selectability-implies-allowlist over a parsed
    /// result. NOTE on scope: the parser sanitizes the DESCRIPTION but renders the NAME verbatim, so
    /// the code-enforced spoofing defense for the name is the IC-7 SELECTABILITY gate, not
    /// sanitization; the oracle asserts exactly that (a selectable name is allowlist-clean, hence
    /// implicitly free of control/format/separator code points) rather than over-claiming that every
    /// rendered name is sanitized (it is not - see the suspected-issue note).</summary>
    private static bool AllInvariantsOfResult(ResolverListParseResult result)
    {
        // (2) BOUNDED OUTPUT: the block cap counts all "## " delimiters, so Entries is cap-bounded.
        if (result.Entries.Count > ResolverListParser.MaxEntries)
        {
            return false;
        }

        foreach (var entry in result.Entries)
        {
            // (2) per-entry caps.
            if (entry.StampStrings.Count > ResolverListParser.MaxStampsPerEntry
                || entry.Description.Length > ResolverListParser.MaxDescriptionChars)
            {
                return false;
            }

            // (3) SANITIZED DESCRIPTION: the emitted Description carries no control/format/separator
            // spoofing code points (newline / tab are the only allowed controls).
            if (!IsSanitizedDescription(entry.Description))
            {
                return false;
            }

            // (4) SELECTABILITY IMPLIES ALLOWLIST: a selectable entry's prefixed name passes the IC-7
            // allowlist AND the entry has a usable stamp. Because the allowlist admits only
            // [A-Za-z0-9._-], a SELECTABLE name is transitively free of every spoofing code point -
            // this is the real, code-enforced name-spoof defense (the write-into-config gate).
            if (entry.IsSelectable &&
                (!PassesSelectionAllowlist(entry.Name) || !entry.HasUsableStamp || !IsSanitizedName(entry.Name)))
            {
                return false;
            }
        }

        return true;
    }

    // A SELECTABLE name must be fully sanitized (no control chars, no Format code points, no
    // line/paragraph separators). Applied only under IsSelectable, since unselectable names are
    // rendered verbatim by design.
    private static bool IsSanitizedName(string name) =>
        name.All(static c => !IsSpoofOrControl(c, allowWhitespaceControls: false));

    // A description preserves newline and tab (the only permitted controls) but nothing else spoofy.
    private static bool IsSanitizedDescription(string description) =>
        description.All(static c => !IsSpoofOrControl(c, allowWhitespaceControls: true));

    private static bool IsSpoofOrControl(char c, bool allowWhitespaceControls)
    {
        if (allowWhitespaceControls && (c == '\n' || c == '\t'))
        {
            return false;
        }

        if (c == LineSep || c == ParaSep)
        {
            return true; // line / paragraph separators (Zl / Zp, not Cf, not control)
        }

        return char.IsControl(c)
            || CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.Format;
    }

    // The IC-7 allowlist, replicated here as the independent oracle: [A-Za-z0-9._-], length 1..64.
    private static bool PassesSelectionAllowlist(string name) =>
        name.Length is > 0 and <= 64 && name.All(static c =>
            c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or '-');

    // ------------------------------------------------------------------ constants + generators

    // Spoofing / control code points, written as (char) numeric-cast constants so this SOURCE file
    // stays ASCII-only (the generators still PRODUCE these runes at runtime to drive the sanitizer).
    private const char Rlo = (char)0x202E;        // RIGHT-TO-LEFT OVERRIDE (Cf)
    private const char Lrm = (char)0x200E;        // LEFT-TO-RIGHT MARK (Cf)
    private const char Rlm = (char)0x200F;        // RIGHT-TO-LEFT MARK (Cf)
    private const char Zwsp = (char)0x200B;       // ZERO WIDTH SPACE (Cf)
    private const char Zwnj = (char)0x200C;       // ZERO WIDTH NON-JOINER (Cf)
    private const char Zwj = (char)0x200D;        // ZERO WIDTH JOINER (Cf)
    private const char WordJoiner = (char)0x2060; // WORD JOINER (Cf)
    private const char Bom = (char)0xFEFF;        // ZERO WIDTH NO-BREAK SPACE / BOM (Cf)
    private const char LineSep = (char)0x2028;    // LINE SEPARATOR (Zl)
    private const char ParaSep = (char)0x2029;    // PARAGRAPH SEPARATOR (Zp)
    private const char Nul = (char)0x0000;        // NUL (control)
    private const char Bel = (char)0x0007;        // BEL (control)
    private const char Esc = (char)0x001B;        // ESC (control)

    private const string FloodDelimiter = "## \n";
    private const string StampLine = "sdns://x\n";

    // Kept below the true caps so the probe both stresses the cap arithmetic AND exercises the
    // just-under / at-the-boundary region without generating multi-megabyte strings every iteration.
    private const int MaxEntriesProbe = 10_000;   // > MaxEntries (8192): forces the block-cap break
    private const int StampFloodProbe = 512;       // > MaxStampsPerEntry (256): forces the per-entry cap
    private const int GiantLineProbe = 9000;       // > MaxDescriptionChars (4096) and > MaxLineChars (8192)

    /// <summary>Content characters for names/descriptions: ordinary label bytes plus every spoofing
    /// class the sanitizer must strip - a bidi override (RLO), LRM/RLM, zero-width space / non-joiner
    /// / joiner, word joiner, BOM, the line/paragraph separators, and raw control bytes (NUL/BEL/ESC).
    /// A string (not a char[]) because CsCheck's Gen.Char indexer takes the allowed-char set as a
    /// string; it is assembled from the (char) constants so this SOURCE file stays ASCII-only.</summary>
    private static readonly string ContentAlphabet = new(
    [
        'a', 'Z', '0', '.', '_', '-', ' ', '"', '#',
        Rlo, Lrm, Rlm, Zwsp, Zwnj, Zwj, WordJoiner, Bom,
        LineSep, ParaSep, Nul, Bel, Esc,
    ]);

    private static readonly string[] StructuralTokens =
    [
        "## ",          // a delimiter (so a delimiter flood arises naturally)
        "\n",           // a line break
        StampLine,      // a stamp candidate
        "// comment\n", // a comment line (skipped, not description)
    ];

    /// <summary>Structural tokens the list assembler stitches together plus a content token that
    /// carries the spoofing runes into names and descriptions.</summary>
    private static readonly Gen<string> TokenGen = Gen.OneOf(
        Gen.OneOf(Array.ConvertAll(StructuralTokens, Gen.Const)),
        ContentRunGen);

    /// <summary>A short run (0..8 chars) over the spoof-heavy content alphabet - the payload that must
    /// come back sanitized when it lands in a description.</summary>
    private static Gen<string> ContentRunGen =>
        Gen.Int[0, 8].SelectMany(len => Gen.Char[ContentAlphabet].Array[len].Select(cs => new string(cs)));

    /// <summary>A whole list body: 0..40 tokens concatenated. Mixes real blocks, delimiter floods,
    /// stamp runs, comments and hostile content into one adversarial document.</summary>
    private static readonly Gen<string> ListBodyGen =
        Gen.Int[0, 40].SelectMany(count =>
            TokenGen.Array[count].Select(tokens => string.Concat(tokens)));
}
