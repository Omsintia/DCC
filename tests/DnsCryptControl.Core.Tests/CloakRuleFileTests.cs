using System.Linq;
using DnsCryptControl.Core.Rules;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A3: <see cref="CloakRuleFile"/> parses a cloaking .txt into an ordered list of typed
/// line-models (cloak rule | blank | full-line comment | unparsed-with-lint) and serializes it
/// back. The cloaking grammar is EXACTLY TWO whitespace-separated tokens per meaningful line
/// (any Unicode whitespace, runs collapse): <c>name &lt;WS&gt; target</c>. The name side reuses
/// the shared name-pattern taxonomy (<see cref="NameRule.Classify"/>); the target is an IP (by
/// <see cref="System.Net.IPAddress"/> parse) or otherwise a CNAME domain.
///
/// Unlike names/IPs (skip-and-continue = fail-open), cloaking has TWO FATAL start-blockers: a
/// degenerate name pattern (<c>*</c>, <c>=</c>, <c>.</c>, <c>**</c>, empty-after-strip, a glob
/// <c>filepath.Match</c> rejects) and a RECURSIVE CNAME (a <c>=cname</c> target that itself
/// matches a cloak name pattern in the file). Both make <c>loadRules</c> return an error →
/// <c>Init</c> aborts → the proxy WON'T START, so our lint flags them as
/// <see cref="RuleLintSeverity.Error"/> save-blockers. A <c>&gt;2</c>-token line and a
/// missing-field line are per-line skip-and-continue (still Errors here — the line is dropped).
/// <c>@schedule</c> is unsupported in cloaking (it becomes a bogus 3rd token / invalid target),
/// so we reject it explicitly. Never throws (except <see cref="System.ArgumentNullException"/>
/// for null args — a null file is empty).
/// </summary>
public class CloakRuleFileTests
{
    // ---------------------------------------------------------------- null / basic

    [Fact]
    public void Parse_null_returnsEmpty_noThrow()
    {
        var file = CloakRuleFile.Parse(null);
        Assert.Empty(file.Lines);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_empty_serializesToEmptyString()
    {
        Assert.Equal("", CloakRuleFile.Parse("").Serialize());
    }

    [Fact]
    public void Parse_classifiesLineKinds()
    {
        // No trailing '\n' => exactly three lines.
        var file = CloakRuleFile.Parse("# header\n\nexample.com 192.168.2.37");
        Assert.Collection(file.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<CloakRuleLine>(l));
    }

    // ---------------------------------------------------------------- IP vs CNAME target

    [Fact]
    public void Parse_ipv4Target_isIp()
    {
        var file = CloakRuleFile.Parse("example.com 192.168.2.37\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("example.com", rule.NamePattern);
        Assert.Equal("192.168.2.37", rule.Target);
        Assert.True(rule.IsIp);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_ipv6Target_isIp()
    {
        var file = CloakRuleFile.Parse("localhost ::1\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("localhost", rule.NamePattern);
        Assert.Equal("::1", rule.Target);
        Assert.True(rule.IsIp);
    }

    [Fact]
    public void Parse_cnameTarget_isNotIp()
    {
        var file = CloakRuleFile.Parse("www.google.* forcesafesearch.google.com\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("www.google.*", rule.NamePattern);
        Assert.Equal("forcesafesearch.google.com", rule.Target);
        Assert.False(rule.IsIp);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_exactSigilName_withIpTarget()
    {
        // '=' here is the pattern-EXACT sigil on the NAME, target is an IP.
        var file = CloakRuleFile.Parse("=example.com 127.0.0.1\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("=example.com", rule.NamePattern);
        Assert.True(rule.IsIp);
        Assert.Empty(file.Findings);
    }

    // ---------------------------------------------------------------- whitespace tokenizing

    [Fact]
    public void Parse_tabSeparator_collapsesToTwoTokens()
    {
        var file = CloakRuleFile.Parse("example.com\t\t192.168.2.37\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("example.com", rule.NamePattern);
        Assert.Equal("192.168.2.37", rule.Target);
    }

    [Fact]
    public void Parse_alignedSpaceRuns_collapse()
    {
        var file = CloakRuleFile.Parse("server        192.168.100.55\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("server", rule.NamePattern);
        Assert.Equal("192.168.100.55", rule.Target);
    }

    // ---------------------------------------------------------------- token-count lint

    [Fact]
    public void Parse_moreThanTwoTokens_isLintError()
    {
        // 3 tokens => the proxy logs 'Unexpected space character' + skips the line.
        var file = CloakRuleFile.Parse("example.com 1.2.3.4 extra\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Equal(1, finding.LineNumber);
    }

    [Fact]
    public void Parse_singleToken_missingTarget_isLintError()
    {
        // 1 token => 'Missing name or target' skip.
        var file = CloakRuleFile.Parse("example.com\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Equal(1, finding.LineNumber);
    }

    // ---------------------------------------------------------------- @schedule rejected

    [Fact]
    public void Parse_scheduleSuffix_isLintError_notSupportedForCloaking()
    {
        // 'name @weekend' with a real IP target would be a 3rd token; even 'name @weekend' as the
        // whole line is 2 tokens where '@weekend' is an invalid target. We reject '@' explicitly.
        var file = CloakRuleFile.Parse("example.com @weekend\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Contains("@", finding.Message);
    }

    // ---------------------------------------------------------------- FATAL: degenerate pattern

    [Theory]
    [InlineData("* 1.2.3.4")]
    [InlineData("= 1.2.3.4")]
    [InlineData(". 1.2.3.4")]
    [InlineData("** 1.2.3.4")]
    public void Parse_degenerateNamePattern_isFatalBlocker(string line)
    {
        // A lone '*'/'='/'.'/'**' makes loadRules' Add() return an error => Init aborts => proxy
        // WON'T START. These MUST be Error-level save blockers.
        var file = CloakRuleFile.Parse(line + "\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Equal(1, finding.LineNumber);
    }

    [Fact]
    public void Parse_malformedGlobName_isFatalBlocker()
    {
        // Unterminated '[' class => filepath.Match rejects => Add error => fatal.
        var file = CloakRuleFile.Parse("ads[0-9.example 0.0.0.0\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    // ---------------------------------------------------------------- FATAL: recursive CNAME

    [Fact]
    public void Parse_recursiveCname_targetMatchesSuffixPattern_isFatalBlocker()
    {
        // Name '*.example.com' is a SUFFIX pattern for example.com + subdomains. The CNAME target
        // 'foo.example.com' matches that pattern => the proxy aborts with 'recursive cloaking rule'.
        var file = CloakRuleFile.Parse("*.example.com foo.example.com\n");
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Contains("recursive", finding.Message, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_recursiveCname_targetMatchesExactPattern_isFatalBlocker()
    {
        // '=cname.example' exact-matches, and a target 'cname.example' equals it.
        var file = CloakRuleFile.Parse(
            "=cname.example 1.2.3.4\n" +
            "other.example cname.example\n");
        Assert.Contains(
            file.Findings,
            f => f.Severity == RuleLintSeverity.Error &&
                 f.Message.Contains("recursive", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Parse_ipTarget_isNeverRecursive()
    {
        // An IP target is not a CNAME, so it can never trigger recursion even if its text matched.
        var file = CloakRuleFile.Parse("*.example.com 1.2.3.4\n");
        Assert.Empty(file.Findings);
        Assert.IsType<CloakRuleLine>(file.Lines[0]);
    }

    [Fact]
    public void Parse_cnameNotMatchingAnyPattern_isClean()
    {
        var file = CloakRuleFile.Parse("www.google.* forcesafesearch.google.com\n");
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_recursion_caseInsensitive()
    {
        // Names are lowercased; a mixed-case target that matches a pattern is still recursive.
        var file = CloakRuleFile.Parse("*.EXAMPLE.com FOO.example.COM\n");
        Assert.Contains(
            file.Findings,
            f => f.Severity == RuleLintSeverity.Error &&
                 f.Message.Contains("recursive", System.StringComparison.OrdinalIgnoreCase));
    }

    // ---------------------------------------------------------------- Go-faithful IP classification

    // .NET IPAddress.TryParse is LENIENT: it accepts leading-zero octets, short dotted forms,
    // 0x-hex, and IPv6 zone IDs that Go net.ParseIP (>=Go 1.17, dnscrypt-proxy 2.1.16) REJECTS
    // as nil. When the proxy's net.ParseIP returns nil it treats the token as a CNAME and runs
    // its recursive-cloaking start-blocker check on it. If our editor mis-flags such a token
    // IsIp=true, the recursion pass SKIPS it (CloakRuleFile.Parse: `if (rule.IsIp) continue;`)
    // and produces a FALSE-CLEAN verdict on a FATAL start-blocker. IsIp must match net.ParseIP:
    // parse AND canonical round-trip equality (the A2 IpRule precedent).

    [Theory]
    [InlineData("1.2.3.04")]   // leading-zero octet
    [InlineData("010.0.0.1")]  // leading-zero octet
    [InlineData("1.2.3")]      // short dotted form
    [InlineData("1")]          // bare integer
    [InlineData("fe80::1%eth0")] // IPv6 zone id
    public void Parse_nonCanonicalIpTarget_isTreatedAsCname_notIp(string target)
    {
        // These are all True under IPAddress.TryParse but nil under Go net.ParseIP. The proxy
        // treats them as CNAME targets, so our IsIp must be false (they must fall through to the
        // recursion pass, not be skipped as IPs).
        var file = CloakRuleFile.Parse($"example.com {target}\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.False(rule.IsIp);
    }

    [Fact]
    public void Parse_nonCanonicalIpTarget_recursion_isDetected_notFalseClean()
    {
        // The exact reproducer from the review finding: '1.2.3.04' is IPAddress.TryParse-true but
        // net.ParseIP-nil, so the proxy treats it as a CNAME. Suffix pattern '*.04' matches the
        // CNAME '1.2.3.04' (ends with '.04') => the proxy aborts at startup with 'recursive
        // cloaking rule'. Mis-flagging IsIp=true would SKIP recursion => false-clean fail-open.
        var file = CloakRuleFile.Parse(
            "*.04 9.9.9.9\n" +
            "example 1.2.3.04\n");
        Assert.Contains(
            file.Findings,
            f => f.Severity == RuleLintSeverity.Error &&
                 f.Message.Contains("recursive", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Parse_nonCanonicalIpTarget_exactPatternRecursion_isDetected()
    {
        // '=1.2.3.04' exact-matches the CNAME target '1.2.3.04' (proxy treats it as a CNAME).
        var file = CloakRuleFile.Parse(
            "=1.2.3.04 9.9.9.9\n" +
            "host 1.2.3.04\n");
        Assert.Contains(
            file.Findings,
            f => f.Severity == RuleLintSeverity.Error &&
                 f.Message.Contains("recursive", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Parse_canonicalIpv6Target_stillIsIp()
    {
        // Guard against over-tightening: a genuine canonical IPv6 must remain IsIp=true.
        var file = CloakRuleFile.Parse("localhost 2001:db8::1\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.True(rule.IsIp);
    }

    // ---------------------------------------------------------------- multi-IP expansion

    [Fact]
    public void Parse_multipleIpsForOneName_areSeparateLines_bothKept()
    {
        // IPv4 and IPv6 for the same name = two separate single-target lines (never comma/2-target).
        var file = CloakRuleFile.Parse(
            "localhost 127.0.0.1\n" +
            "localhost ::1\n");
        Assert.Empty(file.Findings);
        var a = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        var b = Assert.IsType<CloakRuleLine>(file.Lines[1]).Rule;
        Assert.Equal("localhost", a.NamePattern);
        Assert.Equal("127.0.0.1", a.Target);
        Assert.True(a.IsIp);
        Assert.Equal("localhost", b.NamePattern);
        Assert.Equal("::1", b.Target);
        Assert.True(b.IsIp);
    }

    [Fact]
    public void Parse_commaTarget_isNotAnIp_treatedAsCname()
    {
        // A comma-list target is a single token, not an IP => a (bogus) CNAME. We must NOT split it
        // into two targets. It parses as a CNAME (IsIp=false) — the serializer never emits commas.
        var file = CloakRuleFile.Parse("example.com 1.2.3.4,5.6.7.8\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.False(rule.IsIp);
        Assert.Equal("1.2.3.4,5.6.7.8", rule.Target);
    }

    // ---------------------------------------------------------------- comments / literals

    [Fact]
    public void Parse_inlineComment_stripsAndPreserves()
    {
        var file = CloakRuleFile.Parse("ads.example.com 0.0.0.0    # blackhole\n");
        var line = Assert.IsType<CloakRuleLine>(file.Lines[0]);
        Assert.Equal("ads.example.com", line.Rule.NamePattern);
        Assert.Equal("0.0.0.0", line.Rule.Target);
        Assert.Equal("# blackhole", line.Rule.TrailingComment);
    }

    [Fact]
    public void Parse_fullLineComment_isCommentLine()
    {
        var file = CloakRuleFile.Parse("# this is a full-line comment\n");
        var comment = Assert.IsType<CommentLine>(file.Lines[0]);
        Assert.Equal("# this is a full-line comment", comment.Text);
    }

    [Fact]
    public void Parse_lowercasesNameForEquality_butPreservesRawPattern()
    {
        // The pattern is preserved verbatim (raw case) for display/round-trip.
        var file = CloakRuleFile.Parse("EXAMPLE.COM 1.2.3.4\n");
        var rule = Assert.IsType<CloakRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("EXAMPLE.COM", rule.NamePattern);
    }

    // ---------------------------------------------------------------- round-trip fixed point

    [Fact]
    public void RoundTrip_fixedPoint_preservesCommentsAndOrder()
    {
        const string fixture =
            "# cloaking for DnsCryptControl\r\n" +
            "\r\n" +
            "example.com          192.168.2.37   # exact-ish\r\n" +
            "localhost            127.0.0.1\r\n" +
            "localhost            ::1\r\n" +
            "*.example.com        10.0.0.1\r\n" +
            "www.google.*         forcesafesearch.google.com\r\n" +
            "*doubleclick*        0.0.0.0\r\n" +
            "\r\n" +
            "# trailing comment\r\n";

        var first = CloakRuleFile.Parse(fixture);
        var serialized = first.Serialize();
        var second = CloakRuleFile.Parse(serialized);

        // Fixed point.
        Assert.Equal(serialized, second.Serialize());
        Assert.Empty(first.Findings);

        // Order + kinds preserved.
        Assert.Equal(first.Lines.Count, second.Lines.Count);
        Assert.Collection(second.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => { var r = Assert.IsType<CloakRuleLine>(l).Rule; Assert.True(r.IsIp); },
            l => { var r = Assert.IsType<CloakRuleLine>(l).Rule; Assert.True(r.IsIp); },
            l => { var r = Assert.IsType<CloakRuleLine>(l).Rule; Assert.True(r.IsIp); },
            l => { var r = Assert.IsType<CloakRuleLine>(l).Rule; Assert.True(r.IsIp); },
            l => { var r = Assert.IsType<CloakRuleLine>(l).Rule; Assert.False(r.IsIp); },
            l => { var r = Assert.IsType<CloakRuleLine>(l).Rule; Assert.True(r.IsIp); },
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l)); // final CRLF => trailing BlankLine

        // Comments preserved verbatim.
        var exact = Assert.IsType<CloakRuleLine>(second.Lines[2]).Rule;
        Assert.Equal("# exact-ish", exact.TrailingComment);
        Assert.Equal("# cloaking for DnsCryptControl", ((CommentLine)second.Lines[0]).Text);
        Assert.Equal("# trailing comment", ((CommentLine)second.Lines[9]).Text);
    }

    [Fact]
    public void Serialize_understoodRow_isCanonical_singleSpaceSeparated()
    {
        // Canonical form: 'name target' with a single space, inline comment re-attached verbatim.
        var file = CloakRuleFile.Parse("  example.com      192.168.2.37    # note\n");
        Assert.Equal("example.com 192.168.2.37 # note", file.Serialize().TrimEnd('\n'));
    }

    [Fact]
    public void RoundTrip_unparsedLine_preservedVerbatim()
    {
        // A flagged (proxy-would-skip / fatal) line survives serialization verbatim.
        var file = CloakRuleFile.Parse("example.com 1.2.3.4 extra\n* 5.6.7.8\n");
        var second = CloakRuleFile.Parse(file.Serialize());
        Assert.Equal(file.Serialize(), second.Serialize());
        Assert.IsType<UnparsedLine>(second.Lines[0]);
        Assert.IsType<UnparsedLine>(second.Lines[1]);
    }

    // ---------------------------------------------------------------- never throws

    [Fact]
    public void Parse_neverThrows_onGarbage()
    {
        var file = CloakRuleFile.Parse("*\n= x\n. .\n**  \na b c d\n\0\n@sched x\nname\nname target\n");
        Assert.NotNull(file);
    }
}
