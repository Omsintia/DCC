using System.Linq;
using DnsCryptControl.Core.Rules;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A1: <see cref="NameRuleFile"/> parses a blocked_names/allowed_names .txt into an ordered
/// list of typed line-models (name rule | blank | full-line comment | unparsed-with-lint) and
/// serializes it back. Understood rows re-emit canonically, but preserved comments and line
/// order are re-attached verbatim (IC-4). Lint findings (severity, 1-based line, message) never
/// throw and mirror the proxy's skip-and-continue strictness for names (warn/error-on-save).
/// </summary>
public class NameRuleFileTests
{
    // ---------------------------------------------------------------- null / basic

    [Fact]
    public void Parse_null_returnsEmpty_noThrow()
    {
        var file = NameRuleFile.Parse(null);
        Assert.Empty(file.Lines);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_classifiesLineKinds()
    {
        // No trailing '\n' => exactly three lines (a trailing '\n' would add a final BlankLine,
        // which is correct provenance but not what this test pins).
        var file = NameRuleFile.Parse("# header\n\nexample.com");
        Assert.Collection(file.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<NameRuleLine>(l));
    }

    [Fact]
    public void Parse_nameRule_hasCorrectPatternAndKind()
    {
        var file = NameRuleFile.Parse("=exact.example.com\n");
        var rule = Assert.IsType<NameRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("=exact.example.com", rule.Pattern);
        Assert.Equal(NamePatternKind.Exact, rule.Kind);
        Assert.Null(rule.Schedule);
    }

    // ---------------------------------------------------------------- @schedule

    [Fact]
    public void Parse_schedule_splitsPatternAndScheduleName()
    {
        var file = NameRuleFile.Parse("ads.example @evenings\n");
        var rule = Assert.IsType<NameRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("ads.example", rule.Pattern);
        Assert.Equal("evenings", rule.Schedule);
        Assert.Equal(NamePatternKind.Suffix, rule.Kind);
    }

    [Fact]
    public void Parse_multipleAtSigns_isLintError_notThrow()
    {
        // '>=2 @' => per-line ParseTimeBasedRule failure => unparsed line + lint error.
        var file = NameRuleFile.Parse("ads @a @b\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    [Fact]
    public void Parse_bareTrailingAt_isPlainRule_withWarningNotError()
    {
        // 'ads.com @' — dnscrypt-proxy 2.1.16 ParseTimeBasedRule only resolves the schedule when
        // len(timeRangeName) > 0; an empty name skips the lookup and returns a plain unconditional
        // block. So this must parse as a NameRule (pattern=ads.com, schedule=null) with at most a
        // Warning, NOT an Error that blocks the save (over-strict divergence the review flagged).
        var file = NameRuleFile.Parse("ads.com @\n");
        var rule = Assert.IsType<NameRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("ads.com", rule.Pattern);
        Assert.Null(rule.Schedule);
        Assert.DoesNotContain(file.Findings, f => f.Severity == RuleLintSeverity.Error);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Warning && f.LineNumber == 1);
    }

    [Fact]
    public void Parse_firstByteHashLineWithLaterSpaceHash_isComment_notPhantomRule()
    {
        // '#a b #c' — first byte is '#', so the WHOLE line is a comment (proxy: idx==0 || str[0]=='#').
        // The old StripInlineComment produced a phantom NameRuleLine(Pattern="#a b"); it must now be a
        // CommentLine with no rule and no finding.
        var file = NameRuleFile.Parse("#a b #c\n");
        Assert.IsType<CommentLine>(file.Lines[0]);
        Assert.DoesNotContain(file.Lines, l => l is NameRuleLine);
        Assert.Empty(file.Findings);
    }

    // ---------------------------------------------------------------- lint on bad pattern

    [Fact]
    public void Parse_degeneratePattern_isLintFinding_lineNumberIsOneBased()
    {
        var file = NameRuleFile.Parse("good.example\n*\n");
        // Line 1 good, line 2 ('*') is degenerate.
        Assert.IsType<NameRuleLine>(file.Lines[0]);
        Assert.IsType<UnparsedLine>(file.Lines[1]);
        Assert.Contains(file.Findings, f => f.LineNumber == 2);
    }

    [Fact]
    public void Parse_malformedGlob_isLintFinding_andRoundTrips()
    {
        // A1 High finding: 'ads[0-9.example' is a glob candidate ('[') but filepath.Match rejects
        // the unterminated class => the proxy skips it (silently ineffective). It must surface as a
        // lint Error + an UnparsedLine that round-trips verbatim, NOT a silently-accepted NameRule.
        var file = NameRuleFile.Parse("good.example\nads[0-9.example\n");
        Assert.IsType<NameRuleLine>(file.Lines[0]);
        var unparsed = Assert.IsType<UnparsedLine>(file.Lines[1]);
        Assert.Equal("ads[0-9.example", unparsed.Content);
        Assert.Contains(
            file.Findings,
            f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 2);

        // Round-trip fixed point: the raw malformed line is preserved verbatim.
        var second = NameRuleFile.Parse(file.Serialize());
        Assert.Equal(file.Serialize(), second.Serialize());
        Assert.IsType<UnparsedLine>(second.Lines[1]);
    }

    [Fact]
    public void Parse_neverThrows_onGarbage()
    {
        // A pile of hostile inputs must never throw. '**' is a degenerate substring (full len 2 < 3).
        var file = NameRuleFile.Parse("**\n=\n\0\na[b\n@@@\n");
        Assert.NotNull(file);
    }

    // ---------------------------------------------------------------- serialize / round-trip

    [Fact]
    public void Serialize_understoodRow_isCanonical_rawPreservedForComment()
    {
        // Inline comment is re-attached verbatim after the canonical pattern.
        var file = NameRuleFile.Parse("   ads.example    # my note\n");
        var text = file.Serialize();
        Assert.Equal("ads.example # my note", text.TrimEnd('\n'));
    }

    [Fact]
    public void Serialize_literalHash_a_hash_b_survivesRoundTrip()
    {
        // 'a#b' has no space before '#', so it stays a literal SUFFIX pattern.
        var file = NameRuleFile.Parse("a#b\n");
        var rule = Assert.IsType<NameRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("a#b", rule.Pattern);
        Assert.Null(rule.TrailingComment);
        Assert.Equal("a#b", file.Serialize().TrimEnd('\n'));
    }

    [Fact]
    public void RoundTrip_fixedPoint_preservesCommentsAndOrder()
    {
        // A realistic multi-line fixture: full-line + inline comments, blanks, @schedule,
        // all 5 pattern kinds, CRLF lines, and an 'a#b' literal.
        const string fixture =
            "# blocked-names for DnsCryptControl\r\n" +
            "\r\n" +
            "=exact.example.com          # exact match\r\n" +
            "*.ads.example                                 # suffix\r\n" +
            "tracker*                     # prefix\r\n" +
            "*analytics*                  # substring\r\n" +
            "a*b                          # glob\r\n" +
            "sched.example @evenings      # time-based\r\n" +
            "a#b\r\n" +
            "\r\n" +
            "# trailing comment\r\n";

        var first = NameRuleFile.Parse(fixture);
        var serialized = first.Serialize();
        var second = NameRuleFile.Parse(serialized);

        // Fixed point: serialize -> parse -> serialize is stable.
        Assert.Equal(serialized, second.Serialize());

        // Line order + kinds preserved verbatim.
        Assert.Equal(first.Lines.Count, second.Lines.Count);
        Assert.Collection(second.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => { var r = Assert.IsType<NameRuleLine>(l).Rule; Assert.Equal(NamePatternKind.Exact, r.Kind); },
            l => { var r = Assert.IsType<NameRuleLine>(l).Rule; Assert.Equal(NamePatternKind.Suffix, r.Kind); },
            l => { var r = Assert.IsType<NameRuleLine>(l).Rule; Assert.Equal(NamePatternKind.Prefix, r.Kind); },
            l => { var r = Assert.IsType<NameRuleLine>(l).Rule; Assert.Equal(NamePatternKind.Substring, r.Kind); },
            l => { var r = Assert.IsType<NameRuleLine>(l).Rule; Assert.Equal(NamePatternKind.Glob, r.Kind); },
            l => { var r = Assert.IsType<NameRuleLine>(l).Rule; Assert.Equal("evenings", r.Schedule); },
            l => { var r = Assert.IsType<NameRuleLine>(l).Rule; Assert.Equal("a#b", r.Pattern); },
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<CommentLine>(l),
            // The fixture's trailing "\r\n" produces a final BlankLine (correct line-count provenance).
            l => Assert.IsType<BlankLine>(l));

        // Comments preserved verbatim on the understood rows.
        var exact = Assert.IsType<NameRuleLine>(second.Lines[2]).Rule;
        Assert.Equal("# exact match", exact.TrailingComment);
        var sched = Assert.IsType<NameRuleLine>(second.Lines[7]).Rule;
        Assert.Equal("# time-based", sched.TrailingComment);

        // Full-line comments preserved verbatim.
        Assert.Equal("# blocked-names for DnsCryptControl", ((CommentLine)second.Lines[0]).Text);
        Assert.Equal("# trailing comment", ((CommentLine)second.Lines[10]).Text);
    }

    [Fact]
    public void Serialize_emptyFile_isEmptyString()
    {
        Assert.Equal("", NameRuleFile.Parse("").Serialize());
    }
}
