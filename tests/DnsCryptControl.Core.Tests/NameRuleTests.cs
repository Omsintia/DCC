using DnsCryptControl.Core.Rules;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A1: <see cref="NameRule.Classify"/> replicates dnscrypt-proxy 2.1.16's
/// <c>PatternMatcher.Add</c> write-time classification (first match wins):
/// GLOB (?/[/interior-*) -> SUBSTRING (*x*, >=3) -> PREFIX (x*, >=2) -> EXACT (=x, >=2) ->
/// SUFFIX (default; strip one leading '*' then one leading '.'). Empty-after-strip and
/// under-min-len forms are lint errors. Classification is on the LOWERCASED pattern but the
/// raw text is preserved elsewhere for round-trip.
/// </summary>
public class NameRuleTests
{
    // ---------------------------------------------------------------- GLOB (highest precedence)

    [Theory]
    [InlineData("a?b")]  // '?' anywhere
    [InlineData("a[b]")] // '[' anywhere
    [InlineData("a*b")]  // interior '*' (not index 0, not last)
    public void Classify_glob(string pattern)
    {
        Assert.True(NameRule.Classify(pattern, out var kind, out var error));
        Assert.Equal(NamePatternKind.Glob, kind);
        Assert.Null(error);
    }

    [Fact]
    public void Classify_leadingAndTrailingStar_isSubstring_notGlob()
    {
        // '*x*' — stars are at index 0 and last, so NOT interior => not a glob candidate.
        Assert.True(NameRule.Classify("*sub*", out var kind, out _));
        Assert.Equal(NamePatternKind.Substring, kind);
    }

    // ---------------------------------------------------------------- SUBSTRING

    [Fact]
    public void Classify_substring_minLen3()
    {
        // Core must be >= 3 chars between the '*'.
        Assert.True(NameRule.Classify("*ads*", out var kind, out _));
        Assert.Equal(NamePatternKind.Substring, kind);
    }

    [Theory]
    [InlineData("*a*")]  // FULL len 3 >= 3 => accepted (proxy: len(pattern) < 3)
    [InlineData("*ab*")] // FULL len 4 >= 3 => accepted
    public void Classify_substring_fullLenAtLeast3_isSubstring(string pattern)
    {
        // dnscrypt-proxy 2.1.16 PatternMatcher.Add guards the FULL pattern: `if len(pattern) < 3`.
        // '*a*' is len 3 (>= 3) so the proxy ACCEPTS it — the guard is on the whole pattern, NOT the
        // stripped core. (Fix for the review High: we previously guarded core.Length < 3.)
        Assert.True(NameRule.Classify(pattern, out var kind, out var error), error);
        Assert.Equal(NamePatternKind.Substring, kind);
        Assert.Null(error);
    }

    [Fact]
    public void Classify_substring_fullLenBelow3_isError()
    {
        // '**' is FULL len 2 < 3 => rejected (core empty), matching the proxy.
        Assert.False(NameRule.Classify("**", out _, out var error));
        Assert.NotNull(error);
    }

    // ---------------------------------------------------------------- PREFIX

    [Fact]
    public void Classify_prefix_trailingStarOnly()
    {
        Assert.True(NameRule.Classify("ads*", out var kind, out _));
        Assert.Equal(NamePatternKind.Prefix, kind);
    }

    [Theory]
    [InlineData("a*")]  // FULL len 2 >= 2 => accepted (proxy: len(pattern) < 2)
    [InlineData("q*")]
    public void Classify_prefix_fullLenAtLeast2_isPrefix(string pattern)
    {
        // The proxy guards the FULL pattern: `if len(pattern) < 2`. 'a*' is len 2 (>= 2) => ACCEPTED.
        Assert.True(NameRule.Classify(pattern, out var kind, out var error), error);
        Assert.Equal(NamePatternKind.Prefix, kind);
        Assert.Null(error);
    }

    [Fact]
    public void Classify_prefix_fullLenBelow2_isError()
    {
        // Bare '*' is FULL len 1 < 2 => rejected (falls to SUFFIX default: strip '*' => empty).
        Assert.False(NameRule.Classify("*", out _, out var error));
        Assert.NotNull(error);
    }

    // ---------------------------------------------------------------- EXACT

    [Fact]
    public void Classify_exact_leadingEquals()
    {
        Assert.True(NameRule.Classify("=exact.example.com", out var kind, out _));
        Assert.Equal(NamePatternKind.Exact, kind);
    }

    [Fact]
    public void Classify_exact_fullLenAtLeast2_isExact()
    {
        // The proxy guards the FULL pattern: `if len(pattern) < 2`. '=a' is len 2 (>= 2) => ACCEPTED.
        Assert.True(NameRule.Classify("=a", out var kind, out var error), error);
        Assert.Equal(NamePatternKind.Exact, kind);
        Assert.Null(error);
    }

    [Fact]
    public void Classify_exact_fullLenBelow2_isError()
    {
        // Bare '=' is FULL len 1 < 2 => rejected (strip '=' => empty core).
        Assert.False(NameRule.Classify("=", out _, out var error));
        Assert.NotNull(error);
    }

    // ---------------------------------------------------------------- SUFFIX (default)

    [Theory]
    [InlineData("*.example.com")]
    [InlineData(".example.com")]
    [InlineData("example.com")]
    public void Classify_suffix_allEquivalentForms(string pattern)
    {
        Assert.True(NameRule.Classify(pattern, out var kind, out _));
        Assert.Equal(NamePatternKind.Suffix, kind);
    }

    [Fact]
    public void Classify_leadingStarOnly_fallsIntoSuffix()
    {
        // '*lead' — leading '*' only, not a glob, not trailing-'*' => SUFFIX
        // (strip one leading '*', then one leading '.').
        Assert.True(NameRule.Classify("*lead", out var kind, out _));
        Assert.Equal(NamePatternKind.Suffix, kind);
    }

    // ---------------------------------------------------------------- min-len / empty guards

    [Theory]
    [InlineData("*")]  // bare star: SUFFIX default, strip leading '*' => empty
    [InlineData("=")]  // bare equals: EXACT, strip '=' => empty (also < 2)
    [InlineData(".")]  // bare dot: SUFFIX, strip leading '.' => empty
    public void Classify_degenerate_isError(string pattern)
    {
        Assert.False(NameRule.Classify(pattern, out _, out var error));
        Assert.NotNull(error);
    }

    // -------------------------------------------------- malformed glob (filepath.Match rejects)
    // A1 High finding: the proxy's PatternMatcher.Add glob branch validates the pattern via
    // filepath.Match(pattern, "example.com"); an unterminated '[' character class returns
    // filepath.ErrBadPattern => Add returns a rule-file syntax error => the line is skipped
    // (silently ineffective for names, FATAL for cloaking). Our classifier must reject these as a
    // lint error, not silently accept them as a valid Glob.

    // Ground truth: verified against real Go path/filepath.Match(pattern, "example.com") on
    // windows/amd64 (go1.26.4) — each of these returns filepath.ErrBadPattern.
    [Theory]
    [InlineData("ab[c")]      // unterminated class: '[' never closed
    [InlineData("a[b-")]      // unterminated class with a dangling range, never closed
    [InlineData("x[")]        // '[' at end, empty unterminated class
    [InlineData("a[^")]       // negated class, never closed
    [InlineData("a[]")]       // getEsc rejects a leading ']' member => never terminates
    [InlineData("a[]b]c")]    // getEsc rejects the leading ']' (nrange==0) => ErrBadPattern
    [InlineData("a[]]b")]     // same: leading ']' cannot start a member
    [InlineData("a[-x]b")]    // getEsc rejects a leading '-'
    [InlineData("a[x-]b")]    // range hi is ']' after '-' with no member => getEsc on ']' fails
    public void Classify_malformedGlob_isError(string pattern)
    {
        Assert.False(NameRule.Classify(pattern, out _, out var error));
        Assert.NotNull(error);
        Assert.Contains("glob", error, StringComparison.OrdinalIgnoreCase);
    }

    // Ground truth: these return err==nil from real Go filepath.Match on Windows.
    [Theory]
    [InlineData("a[bc]d")]    // well-formed class
    [InlineData("a[b-d]e")]   // well-formed range
    [InlineData("a[^0-9]b")]  // well-formed negated range
    [InlineData("a[!x]b")]    // '!' is a literal member char (NOT a negator), class well-formed
    [InlineData("a?b")]       // '?' is always a valid glob metachar
    [InlineData("a*b")]       // interior '*' is a valid glob
    public void Classify_wellFormedGlob_isGlob(string pattern)
    {
        Assert.True(NameRule.Classify(pattern, out var kind, out var error));
        Assert.Equal(NamePatternKind.Glob, kind);
        Assert.Null(error);
    }

    // The malformed-glob verdict is NAME-DEPENDENT: filepath.Match matches the pattern against the
    // fixed probe "example.com", so an earlier '*' can let the match resolve BEFORE the bad '['
    // chunk is ever scanned. Verified against real Go (filepath.Match(p, "example.com")):
    //   'b*['  -> (false, nil)          : prefix 'b' fails the probe -> the '[' chunk is never scanned
    //   'e*['  -> (false, ErrBadPattern): prefix 'e' matches -> '*' consumes rest -> '[' IS scanned
    // Our classifier must reproduce this exactly (byte-checked against 400k Go vectors during dev),
    // NOT flag every trailing '[' as malformed. Both are glob candidates ('*' interior).
    [Fact]
    public void Classify_malformedGlob_isNameDependent_starBeforeBadBracket()
    {
        // 'b*[' : the proxy's filepath.Match never reaches the bad bracket -> loads (as a glob).
        Assert.True(NameRule.Classify("b*[", out var kind, out var error), error);
        Assert.Equal(NamePatternKind.Glob, kind);
        Assert.Null(error);

        // 'e*[' : the bad bracket IS scanned -> ErrBadPattern -> the proxy skips it -> lint error.
        Assert.False(NameRule.Classify("e*[", out _, out var error2));
        Assert.NotNull(error2);
        Assert.Contains("glob", error2, StringComparison.OrdinalIgnoreCase);
    }
}
