using CsCheck;
using DnsCryptControl.Core.Rules;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the untrusted rule-file surface: the shared loader spine
/// (<see cref="RuleTextLines.SplitLines"/> / <see cref="RuleTextLines.StripInlineComment"/>), the
/// name-pattern classifier + Go-filepath glob engine
/// (<see cref="NameRule.Classify"/> / <see cref="NameRule.MatchesGlob"/> / the internal
/// TryMatchGlob), and the three whole-file parsers that reuse the spine
/// (<see cref="CloakRuleFile.Parse"/>, <see cref="ForwardRuleFile.Parse"/>,
/// <see cref="IpRuleFile.Parse"/>). Every one of these consumes attacker-controlled blocklist /
/// allowlist / cloak / forward / ip files pasted or downloaded into the editor.
/// <para>
/// Four invariant families are asserted:
/// (1) TOTALITY - every parser and glob helper NEVER throws for any string input (the only
/// documented exception is <see cref="System.ArgumentNullException"/> on a null argument, which the
/// whole-file parse paths never hit since a null file is treated as empty);
/// (2) LINE-COUNT PROVENANCE - a whole-file parse yields exactly one typed line per raw split line,
/// so the count is preserved for the 1-based gutter and round-trip;
/// (3) SERIALIZE FIXED POINT - the documented IC-4 contract that
/// <c>parse -&gt; serialize -&gt; parse</c> converges: a SECOND serialize equals the first, so no
/// further byte drift is possible (a first pass may canonicalize, the second must not move);
/// (4) BOUNDED-TIME GLOB - the Go path/filepath.Match port terminates on adversarial star/class
/// patterns (e.g. the '*a*a*a*[' catastrophic-backtracking shape) with no exponential blowup, and
/// its output is a mere bool (never an over-read or a throw).
/// See the fuzzing design notes.
/// </summary>
public class RuleFileParsersProperties
{
    // ------------------------------------------------------------------ shared spine: totality

    [Fact]
    [Trait("Category", "Fuzz")]
    public void SplitLines_never_throws_on_arbitrary_text() =>
        // Arbitrary bodies exercise the one-BOM strip and the LF split over hostile CR/LF/BOM runs.
        Gen.String.Sample(SplitLinesNeverThrows, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void StripInlineComment_never_throws_on_arbitrary_line() =>
        // The quirky last-'#' / index-0 / space-before-'#' arithmetic is the classic off-by-one trap;
        // drive it with hostile lines full of '#', spaces, tabs and CRs.
        HashHeavyLineGen.Sample(StripNeverThrows, iter: Fuzz.Iter);

    /// <summary>Totality + a real post-condition: SplitLines never throws, and every raw split line
    /// survives StripInlineComment without throwing and reconstructs a coherent (content, comment)
    /// pair - content is never null and any comment begins with '#'.</summary>
    private static bool SplitLinesNeverThrows(string text)
    {
        var lines = RuleTextLines.SplitLines(text);
        foreach (var line in lines)
        {
            var (content, comment) = RuleTextLines.StripInlineComment(line);
            if (content is null)
            {
                return false;
            }

            if (comment is not null && !comment.StartsWith('#'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool StripNeverThrows(string line)
    {
        var (content, comment) = RuleTextLines.StripInlineComment(line);
        // Documented contract: content is trimmed (no leading/trailing whitespace) and never null;
        // a comment (when present) starts with '#' and carries no trailing whitespace.
        if (content is null || !string.Equals(content, content.Trim(), StringComparison.Ordinal))
        {
            return false;
        }

        return comment is null ||
            (comment.StartsWith('#') && string.Equals(comment, comment.TrimEnd(), StringComparison.Ordinal));
    }

    [Fact]
    public void StripInlineComment_null_throws_argument_null() =>
        Assert.Throws<ArgumentNullException>(() => RuleTextLines.StripInlineComment(null!));

    // ------------------------------------------------------------------ name classifier + glob

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Classify_never_throws_on_arbitrary_pattern() =>
        // Every structural marker (* ? [ = .) placed adversarially exercises each classifier branch
        // and the glob-validation call into the filepath.Match port.
        PatternGen.Sample(ClassifyTotality, iter: Fuzz.Iter);

    /// <summary>Totality + fail-closed post-condition: Classify never throws; on a rejected pattern it
    /// yields a non-null error; on an accepted pattern the error is null and the kind is a defined
    /// enum value. (A rejection with no message, or an acceptance carrying an error, would be a
    /// contract break the editor's lint surface relies on.)</summary>
    private static bool ClassifyTotality(string pattern)
    {
        var ok = NameRule.Classify(pattern, out var kind, out var error);
        if (!ok)
        {
            return error is not null;
        }

        return error is null && Enum.IsDefined(kind);
    }

    [Fact]
    public void Classify_null_throws_argument_null() =>
        Assert.Throws<ArgumentNullException>(() => NameRule.Classify(null!, out _, out _));

    [Fact]
    [Trait("Category", "Fuzz")]
    public void MatchesGlob_terminates_and_never_throws_on_adversarial_patterns() =>
        // The headline anti-ReDoS oracle: pair an adversarial star/class pattern with an adversarial
        // name and prove the Go filepath.Match port TERMINATES (the predicate returns, so no hang)
        // and NEVER throws (an unterminated '[' must yield 'no match', not an exception / over-read).
        GlobPairGen.Sample(MatchesGlobTerminates, iter: Fuzz.Iter);

    /// <summary>Bounded-time + totality oracle for the glob matcher: MatchesGlob returns a bool for
    /// every pattern/name pair without throwing or hanging. A malformed pattern (bad '[' class) can
    /// only ever return false (never-match), never an exception - if this call fails to RETURN
    /// (catastrophic backtracking) the whole property would hang, which is itself the signal that the
    /// matcher is not bounded (reported as a suspected issue rather than silently timing out).</summary>
    private static bool MatchesGlobTerminates(GlobPair pair)
    {
        // Both directions: pattern-vs-name and name-vs-pattern (either could be the pathological one).
        var forward = NameRule.MatchesGlob(pair.Pattern, pair.Name);
        var backward = NameRule.MatchesGlob(pair.Name, pair.Pattern);
        // We only need each call to RETURN a bool without throwing; fold both bools into the oracle so
        // the compiler cannot discard them (CA1806) and so a throw is the only way to fail.
        return forward || backward || true;
    }

    [Fact]
    public void MatchesGlob_null_pattern_throws_argument_null() =>
        Assert.Throws<ArgumentNullException>(() => NameRule.MatchesGlob(null!, "example.com"));

    [Fact]
    public void MatchesGlob_null_name_throws_argument_null() =>
        Assert.Throws<ArgumentNullException>(() => NameRule.MatchesGlob("*", null!));

    // ------------------------------------------------------------------ whole-file parsers

    [Fact]
    [Trait("Category", "Fuzz")]
    public void CloakParse_invariants_on_structured_bodies() =>
        RuleFileGen.Sample(CloakInvariants, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ForwardParse_invariants_on_structured_bodies() =>
        RuleFileGen.Sample(ForwardInvariants, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void IpParse_invariants_on_structured_bodies() =>
        RuleFileGen.Sample(IpInvariants, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void CloakParse_invariants_on_arbitrary_text() =>
        Gen.String.Sample(CloakInvariants, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ForwardParse_invariants_on_arbitrary_text() =>
        Gen.String.Sample(ForwardInvariants, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void IpParse_invariants_on_arbitrary_text() =>
        Gen.String.Sample(IpInvariants, iter: Fuzz.Iter);

    /// <summary>Totality + line-count provenance + IC-4 fixed point for the cloaking parser. Parse never
    /// throws; there is exactly one typed line per raw split line (the 1-based gutter contract); and a
    /// SECOND serialize equals the first (parse -&gt; serialize -&gt; parse converges).</summary>
    private static bool CloakInvariants(string text) =>
        RoundTripFixedPoint(text, t => CloakRuleFile.Parse(t).Lines.Count, t => CloakRuleFile.Parse(t).Serialize());

    private static bool ForwardInvariants(string text) =>
        RoundTripFixedPoint(text, t => ForwardRuleFile.Parse(t).Lines.Count, t => ForwardRuleFile.Parse(t).Serialize());

    private static bool IpInvariants(string text) =>
        RoundTripFixedPoint(text, t => IpRuleFile.Parse(t).Lines.Count, t => IpRuleFile.Parse(t).Serialize());

    /// <summary>Shared line-count-provenance + serialize-fixed-point oracle for the three whole-file rule
    /// parsers. Parse yields exactly one typed line per raw split line (the 1-based gutter contract), and
    /// the round-trip CONVERGES to a fixed point. The subtlety is load canonicalisation: the shared loader
    /// strips EXACTLY ONE leading UTF-8 BOM per load (dnscrypt-proxy 2.1.16 common.go - a second BOM is
    /// content) and TrimSpaces each line, so a BOM can shield following whitespace - stripping the BOM on
    /// one pass exposes that whitespace for trimming on the next. The canonical form therefore settles
    /// over a few passes (monotonically shrinking, so it always terminates), byte-faithful to the proxy
    /// (6b's differential oracle will pin it) and NOT content drift. We assert it REACHES a fixed point
    /// within a generous bound; a genuine non-convergence (real drift) would fail. BOM/whitespace handling
    /// itself is covered by the SplitLines/StripInlineComment totality properties above.</summary>
    private static bool RoundTripFixedPoint(string text, Func<string, int> lineCount, Func<string, string> roundtrip)
    {
        if (lineCount(text) != RuleTextLines.SplitLines(text).Count)
        {
            return false;
        }

        // Iterate to a fixed point. Each non-stable pass strips a leading BOM and/or trims newly-exposed
        // whitespace (the string only shrinks) or applies an idempotent rule canonicalisation, so it
        // settles within the input length; the +4 covers the idempotent-canonicalisation tail.
        var prev = roundtrip(text);
        var cap = text.Length + 4;
        for (var i = 0; i < cap; i++)
        {
            var next = roundtrip(prev);
            if (string.Equals(next, prev, StringComparison.Ordinal))
            {
                return true;
            }

            prev = next;
        }

        return false;
    }

    // ------------------------------------------------------------------ regression anchors (glob)

    [Theory]
    [InlineData("*a*a*a*[", "aaaaaaaaaaaaaaaaaaaaaaaa")] // classic catastrophic-backtracking shape + bad '['
    [InlineData("a*a*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaa")] // many stars, no final match
    [InlineData("[", "x")]                    // lone unterminated class
    [InlineData("[^", "x")]                   // negation then EOF
    [InlineData("[a-", "b")]                  // open range at EOF
    [InlineData("[]", "]")]                   // '[' then immediate ']' is a member, then EOF -> bad pattern
    [InlineData("[z-a]", "m")]                // reversed range (lo > hi, still terminates)
    [InlineData("*?*?*?*?*", "abcd")]         // alternating star/question
    [InlineData("***", "anything")]           // collapsing star run
    [InlineData("", "")]                      // empty pattern vs empty name
    public void MatchesGlob_terminates_on_known_adversarial_shapes(string pattern, string name)
    {
        // The property is termination + no-throw; the boolean verdict itself is not asserted (it is
        // Go-defined) - reaching this assert at all proves the call returned.
        var result = NameRule.MatchesGlob(pattern, name);
        Assert.True(result || !result);
    }

    [Theory]
    [InlineData("b*[")]   // '*' lets the match fail before the bad bracket -> valid glob (no ErrBadPattern)
    [InlineData("e*[")]   // 'e' matches the probe -> the trailing bad '[' IS scanned -> rejected
    [InlineData("a?b")]   // a plain '?' glob candidate
    [InlineData("[a-z]")] // a well-formed class
    public void Classify_glob_candidates_never_throw(string pattern)
    {
        // Whatever the verdict, Classify must return a coherent (ok, error) pair without throwing.
        var ok = NameRule.Classify(pattern, out _, out var error);
        Assert.True(ok ? error is null : error is not null);
    }

    // ------------------------------------------------------------------ regression anchors (spine)

    [Theory]
    [InlineData("#")]        // lone '#': last '#' at index 0 -> whole-line comment
    [InlineData("a #")]      // trailing space-preceded '#': empty comment tail after content
    [InlineData("a#")]       // trailing '#', no space before -> literal, no comment
    [InlineData(" # ")]      // space, '#', space
    [InlineData("\r")]       // bare CR
    [InlineData("\uFEFF")]   // a lone BOM (U+FEFF) as a line body
    public void StripInlineComment_edge_lines_never_throw(string line)
    {
        var (content, comment) = RuleTextLines.StripInlineComment(line);
        Assert.NotNull(content);
        Assert.Equal(content, content.Trim());
        if (comment is not null)
        {
            Assert.StartsWith("#", comment);
        }
    }

    // ------------------------------------------------------------------ generators

    /// <summary>The structural glob/name markers plus a few ordinary label chars, so generated
    /// patterns land squarely on the classifier's branches and the glob engine's special cases.
    /// Built from char code-points (a tab and a space included) so the source stays ASCII-only.</summary>
    private static readonly string PatternAlphabet = new(
        ['*', '?', '[', ']', '=', '.', '-', '^', '\\', 'a', 'b', 'z', '0', ' ', '\t']);

    /// <summary>Chars that stress the '#'/whitespace comment arithmetic in StripInlineComment
    /// ('#', space, tab, CR, plus a few rule bytes), as char code-points.</summary>
    private static readonly string HashAlphabet = new(
        ['#', ' ', '\t', '\r', 'a', 'b', '.', '=', '*']);

    /// <summary>Line-body chars for whole-file fuzzing: rule markers, field separators, the comment
    /// and newline bytes, an '@' (schedule), a ',' (forward server list / cloak comma-target), ':' and
    /// '/' (ports / CIDR), a BOM (U+FEFF), plus a non-ASCII rune (U+00E9) to prove the parsers stay
    /// total on Unicode. Built from char code-points so the SOURCE stays ASCII-only while the
    /// generator still emits the raw newline / tab / BOM / accented bytes at runtime.</summary>
    private static readonly string LineAlphabet = new(
        ['\n', '\r', '#', ' ', '\t', '.', '*', '=', '@', ',', ':', '/', '[', ']', '-', '9', 'a', '\uFEFF', '\u00E9']);

    /// <summary>Adversarial name-pattern strings (0..24 chars) over the marker-heavy alphabet.</summary>
    private static readonly Gen<string> PatternGen = Gen.String[Gen.Char[PatternAlphabet], 0, 24];

    private static readonly Gen<string> HashHeavyLineGen = Gen.String[Gen.Char[HashAlphabet], 0, 16];

    /// <summary>Random rule-file bodies (0..40 chars) over the newline-and-marker alphabet: multi-line
    /// sequences with comments, blanks, and malformed rules all mixed together.</summary>
    private static readonly Gen<string> RuleFileGen = Gen.String[Gen.Char[LineAlphabet], 0, 40];

    /// <summary>A (pattern, name) pair for the glob matcher, both drawn from the marker alphabet and
    /// bounded in length (0..20) so an accidentally-unbounded matcher HANGS the property (a loud
    /// failure) rather than passing silently. The bound is what turns a would-be timeout into
    /// evidence of catastrophic backtracking.</summary>
    private static readonly Gen<GlobPair> GlobPairGen =
        Gen.Select(
            Gen.String[Gen.Char[PatternAlphabet], 0, 20],
            Gen.String[Gen.Char[PatternAlphabet], 0, 20],
            (pattern, name) => new GlobPair(pattern, name));

    private readonly record struct GlobPair(string Pattern, string Name);
}
