using System.Globalization;
using CsCheck;
using DnsCryptControl.Core.QueryLog;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the dnscrypt-proxy TSV query-log parser (<see cref="QueryLogParser"/>) - the
/// live-tail parser behind the Query Monitor, fed a half-written line every poll and, in principle,
/// attacker-influenced qnames (a client can query any name it likes and the proxy logs it verbatim).
/// The headline invariant is TOTALITY: <see cref="QueryLogParser.ParseLine"/> /
/// <see cref="QueryLogParser.ParseLines"/> / <see cref="QueryLogParser.StripTimeBrackets"/> must NEVER
/// throw for any input. Around it: the LENIENCY contract - a line with fewer than the required 8
/// tab-columns yields null; a trailing partial (no-newline) line is dropped by ParseLines; an
/// unrecognised ACTION token maps to <see cref="QueryAction.Other"/>; a malformed duration is total
/// (yields 0 and never negative); and the VERBATIM contract - every string column round-trips
/// unchanged (no field is mutated). A separate property documents UI-DISPLAY SAFETY: because the
/// qname/client columns are kept verbatim with NO sanitizer, control characters (NUL, ESC, CR, ...)
/// reach the parsed fields intact and would flow to whatever renders them. See
/// the fuzzing design notes.
/// </summary>
public class QueryLogParserProperties
{
    /// <summary>The required tab-column count; a line with fewer columns must parse to null.</summary>
    private const int ColumnCount = 8;

    // NOTE: these data arrays are declared BEFORE the generator fields below because static field
    // initializers run in textual order - a generator that reads Array.Length must see a non-null array.

    /// <summary>The six action names the parser recognises (case-sensitive, upper-case), for the
    /// known-token generator and the mapping oracle. Order is irrelevant.</summary>
    private static readonly string[] KnownActions =
        { "PASS", "REJECT", "CLOAK", "SYNTH", "NXDOMAIN", "FORWARD" };

    /// <summary>Hostile palette EXCLUDING tab and newline (single-column fields). Escapes: NUL, BEL, ESC,
    /// CR, DEL, U+0080; then space, 'a', '-', '[', ']', e-acute, and a right-to-left override (U+202E).
    /// Deliberately no '\t'/'\n' so a field is exactly one column and cannot inject a line break.</summary>
    private static readonly char[] NoTabHostileChars =
    {
        '\0', '\a', '\u001b', '\r', '\u007f', '\u0080',
        ' ', 'a', '-', '[', ']', '\u00e9', '\u202e',
    };

    // ---------------------------------------------------------------------- totality (never throws)

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLine_never_throws_on_arbitrary_text() =>
        // Arbitrary text: exercises the < 8 column early-out and the no-column garbage path.
        Gen.String.Sample(ParseLineTotality, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLine_never_throws_on_tabbed_lines() =>
        // Random tab counts + hostile chars so the split lands on both sides of the 8-column boundary
        // and drives every field (action mapping, duration parse) with hostile bytes.
        TabbedLineGen.Sample(ParseLineTotality, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLines_never_throws_and_is_bounded_on_arbitrary_text() =>
        // Multi-line garbage: drives the partial-tail drop and the skip-and-continue loop. The output
        // is bounded by the number of newline-terminated lines.
        Gen.String.Sample(ParseLinesTotalityAndBounded, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLines_never_throws_on_tab_and_newline_soup() =>
        MultiLineGen.Sample(ParseLinesTotalityAndBounded, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void StripTimeBrackets_never_throws_and_only_peels_one_bracket_pair() =>
        // Non-null by construction (the method's documented contract rejects null). The result is
        // either the input verbatim or the input with exactly one leading '[' and trailing ']' removed.
        HostileFieldGen.Sample(StripBracketsInvariant, iter: Fuzz.Iter);

    // ---------------------------------------------------------------------- leniency: short -> null

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLine_fewer_than_8_columns_is_always_null() =>
        // 0..7 fields joined by a single tab: MUST be null (never a partially-populated line).
        ShortLineGen.Sample(line => QueryLogParser.ParseLine(line) is null, iter: Fuzz.Iter);

    // ---------------------------------------------------------------------- verbatim round-trip

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLine_preserves_every_string_field_verbatim() =>
        // Build a line from exactly 8 tab-free fields, parse it, and assert every string column comes
        // back byte-for-byte. This is the REAL "fields are preserved verbatim" contract and
        // simultaneously proves no field is silently sanitized/trimmed.
        EightFieldGen.Sample(RoundTripsVerbatim, iter: Fuzz.Iter);

    // ---------------------------------------------------------------------- action mapping totality

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLine_action_is_always_a_defined_enum_value_and_unknown_is_Other() =>
        // Any action token maps to a DEFINED QueryAction; and a token that is not one of the six known
        // upper-case names maps to exactly Other (the closed-taxonomy catch-all, never a crash).
        ActionTokenGen.Sample(ActionMapsClosed, iter: Fuzz.Iter);

    // ---------------------------------------------------------------------- duration totality

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLine_duration_is_total_and_non_negative() =>
        // Malformed / signed / oversized duration tokens must yield a NON-NEGATIVE int (0 on failure),
        // never throw and never a negative value (NumberStyles.None rejects sign/whitespace).
        DurationTokenGen.Sample(DurationIsTotal, iter: Fuzz.Iter);

    // ---------------------------------------------------------------------- UI-display-safety witness

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParseLine_does_not_strip_control_chars_from_qname_documenting_missing_sanitizer()
    {
        // This is a DOCUMENTING witness, not a demand for stripping: it asserts the parser's ACTUAL
        // (verbatim) behaviour so a future sanitizer visibly changes it. A qname carrying NUL, ESC and
        // CR survives intact into QueryLogLine.Name - i.e. control chars DO reach a parsed field, which
        // is why a display-time sanitizer is warranted (flagged in suspectedIssues).
        const string hostileName = "evil\0\u001b[31m\rname";
        var line = QueryLogParser.ParseLine(
            "[t]\t127.0.0.1\t" + hostileName + "\tA\tPASS\t1ms\ts\t-");

        Assert.NotNull(line);
        Assert.Equal(hostileName, line!.Name);                                   // verbatim
        Assert.Contains("\0", line.Name, StringComparison.Ordinal);             // NUL survived
        Assert.Contains("\u001b", line.Name, StringComparison.Ordinal);         // ESC survived
    }

    // ---------------------------------------------------------------------- concrete regression anchors

    [Theory]
    [InlineData("183ms", 183)]
    [InlineData("0ms", 0)]
    [InlineData("42", 42)]           // bare number, no ms suffix
    [InlineData("NOTMS", 0)]         // unparseable -> 0
    [InlineData("-5ms", 0)]          // NumberStyles.None rejects the sign -> 0 (never negative)
    [InlineData("+5ms", 0)]          // leading '+' rejected -> 0
    [InlineData(" 5ms", 0)]          // leading whitespace rejected -> 0
    [InlineData("ms", 0)]            // suffix only, empty digits -> 0
    [InlineData("999999999999ms", 0)] // overflows int -> parse fails -> 0 (still total)
    [InlineData("1_000ms", 0)]       // digit separator not a valid integer -> 0
    public void Duration_regression_anchors(string durationToken, int expectedMs)
    {
        var line = QueryLogParser.ParseLine(
            "[t]\t127.0.0.1\tn\tA\tPASS\t" + durationToken + "\ts\t-");

        Assert.NotNull(line);
        Assert.Equal(expectedMs, line!.DurationMs);
        Assert.True(line.DurationMs >= 0);
    }

    [Theory]
    [InlineData("PASS", QueryAction.Pass)]
    [InlineData("REJECT", QueryAction.Reject)]
    [InlineData("CLOAK", QueryAction.Cloak)]
    [InlineData("SYNTH", QueryAction.Synth)]
    [InlineData("NXDOMAIN", QueryAction.NxDomain)]
    [InlineData("FORWARD", QueryAction.Forward)]
    [InlineData("pass", QueryAction.Other)]        // case-sensitive -> Other
    [InlineData("WHATEVER", QueryAction.Other)]    // unknown -> Other
    [InlineData("", QueryAction.Other)]            // empty action token -> Other
    public void Action_regression_anchors(string actionToken, QueryAction expected)
    {
        var line = QueryLogParser.ParseLine(
            "[t]\t127.0.0.1\tn\tA\t" + actionToken + "\t1ms\ts\t-");

        Assert.NotNull(line);
        Assert.Equal(expected, line!.Action);
    }

    [Fact]
    public void ParseLine_extra_tabs_beyond_8_columns_flow_into_relay_verbatim()
    {
        // The split is capped at 8, so a 9th/10th tab does NOT drop the line: everything from the
        // eighth column on is kept as the Relay, tabs included, verbatim.
        var line = QueryLogParser.ParseLine(
            "[t]\t127.0.0.1\tn\tA\tPASS\t1ms\ts\trelay\textra\ttail");

        Assert.NotNull(line);
        Assert.Equal("s", line!.Server);
        Assert.Equal("relay\textra\ttail", line.Relay); // stray tabs preserved in the last field
    }

    [Fact]
    public void ParseLines_drops_partial_tail_but_keeps_a_newline_terminated_final_line()
    {
        const string complete = "[t]\t127.0.0.1\tn\tA\tPASS\t1ms\ts\t-";
        var withPartial = complete + "\n" + "[t]\t127.0.0.1\tpartial";
        var terminated = complete + "\n" + complete + "\n";

        Assert.Single(QueryLogParser.ParseLines(withPartial));         // partial tail dropped
        Assert.Equal(2, QueryLogParser.ParseLines(terminated).Count);  // both kept
    }

    // ---------------------------------------------------------------------- oracles

    /// <summary>Totality oracle: ParseLine must not throw for any input. When it ACCEPTS (non-null), every
    /// string field is non-null and the duration is non-negative (real post-conditions of the record).</summary>
    private static bool ParseLineTotality(string input)
    {
        var line = QueryLogParser.ParseLine(input);
        if (line is null)
        {
            return true; // rejecting a malformed/short line is the expected, valid outcome
        }

        return line.Time is not null
            && line.Client is not null
            && line.Name is not null
            && line.Type is not null
            && line.Server is not null
            && line.Relay is not null
            && line.DurationMs >= 0;
    }

    /// <summary>Totality + bounded-output oracle for ParseLines: never throws, and the number of parsed
    /// lines never exceeds the number of newline characters in the source (the partial tail is dropped and
    /// malformed lines are skipped, so the count can only be less-or-equal). Every element is non-null.</summary>
    private static bool ParseLinesTotalityAndBounded(string input)
    {
        var lines = QueryLogParser.ParseLines(input);

        // Upper bound: at most one parsed line per '\n' in the source (a final unterminated tail yields
        // no '\n' and is dropped; a terminated final line has its own '\n'). Never more.
        var newlineCount = input.Count(c => c == '\n');
        if (lines.Count > newlineCount)
        {
            return false;
        }

        foreach (var l in lines)
        {
            if (l is null || l.DurationMs < 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>StripTimeBrackets oracle: never throws for non-null input; the result is either the input
    /// unchanged, or the input with exactly one surrounding '[' ... ']' pair peeled (length shrinks by 2).</summary>
    private static bool StripBracketsInvariant(string input)
    {
        var stripped = QueryLogParser.StripTimeBrackets(input);

        var bracketed = input.Length >= 2 && input[0] == '[' && input[^1] == ']';
        if (bracketed)
        {
            return stripped.Length == input.Length - 2 && stripped == input[1..^1];
        }

        return stripped == input;
    }

    /// <summary>Verbatim oracle: parse a line assembled from 8 known tab-free fields and assert every
    /// string column comes back byte-for-byte. The six preserved string fields (Time/Client/Name/Type/
    /// Server/Relay) must be identical to the inputs - no trimming, no sanitizing.</summary>
    private static bool RoundTripsVerbatim(string[] fields)
    {
        var line = QueryLogParser.ParseLine(string.Join('\t', fields));
        if (line is null)
        {
            return false; // exactly 8 tab-free fields must always parse
        }

        return line.Time == fields[0]
            && line.Client == fields[1]
            && line.Name == fields[2]
            && line.Type == fields[3]
            && line.Server == fields[6]
            && line.Relay == fields[7];
    }

    /// <summary>Action-mapping oracle: the mapped action is always a defined enum value; and it equals
    /// Other exactly when the raw token is not one of the six known upper-case names.</summary>
    private static bool ActionMapsClosed(string actionToken)
    {
        var line = QueryLogParser.ParseLine(
            "[t]\t127.0.0.1\tn\tA\t" + actionToken + "\t1ms\ts\t-");
        if (line is null)
        {
            return false; // a well-formed 8-column line must parse regardless of the action token
        }

        if (!Enum.IsDefined(line.Action))
        {
            return false;
        }

        var isKnown = Array.IndexOf(KnownActions, actionToken) >= 0;
        return isKnown ? line.Action != QueryAction.Other : line.Action == QueryAction.Other;
    }

    /// <summary>Duration oracle: total (never throws) and never negative. When the token is a plain
    /// non-negative integer with an optional 'ms' suffix, the parsed value equals that integer; otherwise
    /// it is 0. Recomputes the expectation with the parser's exact NumberStyles.None contract.</summary>
    private static bool DurationIsTotal(string durationToken)
    {
        var line = QueryLogParser.ParseLine(
            "[t]\t127.0.0.1\tn\tA\tPASS\t" + durationToken + "\ts\t-");
        if (line is null)
        {
            return false; // a well-formed 8-column line must parse regardless of the duration token
        }

        if (line.DurationMs < 0)
        {
            return false; // NumberStyles.None forbids a sign, so a negative result is impossible
        }

        var digits = durationToken.EndsWith("ms", StringComparison.Ordinal)
            ? durationToken[..^2]
            : durationToken;
        var expected = int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var ms)
            ? ms
            : 0;

        return line.DurationMs == expected;
    }

    // ---------------------------------------------------------------------- generators

    /// <summary>Palette-index -> hostile string. Maps an int[] of palette indices to a string, so every
    /// generated field is built ONLY from the hostile palette (NUL, control chars, ESC, CR, non-ASCII).
    /// Kept as a helper so no generator lambda dereferences a possibly-null array element.</summary>
    private static string PaletteString(int[] indices)
    {
        var chars = new char[indices.Length];
        for (var i = 0; i < indices.Length; i++)
        {
            chars[i] = NoTabHostileChars[indices[i]];
        }

        return new string(chars);
    }

    /// <summary>A tab-free field over the hostile palette, length 0..8. Tab is excluded so the field
    /// occupies exactly one column. The array length is folded into the indexer, avoiding SelectMany.</summary>
    private static readonly Gen<string> HostileFieldGen =
        Gen.Int[0, NoTabHostileChars.Length - 1].Array[Gen.Int[0, 8]].Select(PaletteString);

    /// <summary>A raw action token: half the time a KNOWN name (so the "known -> not Other" side is
    /// exercised), half the time arbitrary hostile text (the "unknown -> Other" side). Never a tab.</summary>
    private static readonly Gen<string> ActionTokenGen =
        Gen.OneOf(
            Gen.Int[0, KnownActions.Length - 1].Select(i => KnownActions[i]),
            HostileFieldGen);

    /// <summary>A raw duration token: valid (NNNms / bare NNN), sign-prefixed, whitespace-prefixed,
    /// oversized (int-overflowing), or arbitrary garbage - all tab-free.</summary>
    private static readonly Gen<string> DurationTokenGen =
        Gen.OneOf(
            Gen.Int[0, int.MaxValue].Select(n => n.ToString(CultureInfo.InvariantCulture) + "ms"),
            Gen.Int[0, int.MaxValue].Select(n => n.ToString(CultureInfo.InvariantCulture)),
            Gen.Int[0, int.MaxValue].Select(n => "-" + n.ToString(CultureInfo.InvariantCulture) + "ms"),
            Gen.Int[0, int.MaxValue].Select(n => " " + n.ToString(CultureInfo.InvariantCulture) + "ms"),
            Gen.Const("999999999999999ms"),
            HostileFieldGen);

    /// <summary>Exactly 8 tab-free hostile fields, assembled with a tab separator into a full log line.
    /// Every field is drawn from the hostile palette so the verbatim contract is proven against control
    /// chars / non-ASCII / empty fields. A tab in the relay is covered by a dedicated regression.</summary>
    private static readonly Gen<string[]> EightFieldGen =
        Gen.Select(
            HostileFieldGen, HostileFieldGen, HostileFieldGen, HostileFieldGen,
            HostileFieldGen, HostileFieldGen, HostileFieldGen, HostileFieldGen,
            (f0, f1, f2, f3, f4, f5, f6, f7) => new[] { f0, f1, f2, f3, f4, f5, f6, f7 });

    /// <summary>0..7 tab-separated hostile fields: strictly fewer than the required 8 columns, so
    /// ParseLine must always reject (null). The field COUNT is what makes the line short.</summary>
    private static readonly Gen<string> ShortLineGen =
        HostileFieldGen.Array[Gen.Int[0, ColumnCount - 1]].Select(parts => string.Join('\t', parts));

    /// <summary>A raw log line built by joining 0..12 hostile fields with tabs: lands on both sides of the
    /// 8-column boundary and drives every field with hostile bytes. Feeds the ParseLine totality property.</summary>
    private static readonly Gen<string> TabbedLineGen =
        HostileFieldGen.Array[Gen.Int[0, 12]].Select(parts => string.Join('\t', parts));

    /// <summary>A multi-line blob: several tabbed lines joined by newlines, with a coin-flip trailing
    /// newline (so the partial-tail-drop branch is hit both ways). Feeds ParseLines.</summary>
    private static readonly Gen<string> MultiLineGen =
        Gen.Select(
            TabbedLineGen.Array[Gen.Int[0, 6]],
            Gen.Bool,
            (lines, trailingNewline) =>
                string.Join('\n', lines) + (trailingNewline ? "\n" : string.Empty));
}
