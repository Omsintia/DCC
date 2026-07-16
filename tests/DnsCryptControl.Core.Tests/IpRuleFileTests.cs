using System.Linq;
using DnsCryptControl.Core.Rules;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A2: <see cref="IpRuleFile"/> parses a blocked_ips/allowed_ips .txt into an ordered list of
/// typed line-models (ip rule | blank | full-line comment | unparsed-with-lint) and serializes
/// it back. The IP grammar is one token per line (the whole comment-stripped, trimmed line):
/// CIDR (contains '/'), else trailing-'*' textual prefix, else exact IP. Understood rows re-emit
/// CANONICALLY (exact IP → <c>IPAddress.ToString()</c>; CIDR → network address; prefix → stripped
/// core + '*'), but preserved comments and line order are re-attached verbatim (IC-4).
///
/// The proxy skip-and-continues on bad IP rules (a silently-ineffective rule = fail-open), so our
/// lint is STRICTER: non-canonical exact IPs, '@' anywhere, brackets, and interior '*' are Errors
/// (block on save); host-bits-set CIDR and too-short textual prefixes are Warnings. Never throws
/// (except <see cref="System.ArgumentNullException"/> for null args — a null file is empty).
/// </summary>
public class IpRuleFileTests
{
    // ---------------------------------------------------------------- null / basic

    [Fact]
    public void Parse_null_returnsEmpty_noThrow()
    {
        var file = IpRuleFile.Parse(null);
        Assert.Empty(file.Lines);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_empty_serializesToEmptyString()
    {
        Assert.Equal("", IpRuleFile.Parse("").Serialize());
    }

    [Fact]
    public void Parse_classifiesLineKinds()
    {
        // No trailing '\n' => exactly three lines.
        var file = IpRuleFile.Parse("# header\n\n94.140.14.14");
        Assert.Collection(file.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<IpRuleLine>(l));
    }

    // ---------------------------------------------------------------- each kind

    [Fact]
    public void Parse_exactIpv4_classifiedExact()
    {
        var file = IpRuleFile.Parse("94.140.14.14\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(IpRuleKind.Exact, rule.Kind);
        Assert.Equal("94.140.14.14", rule.Value);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_exactIpv6_classifiedExact_canonicalStaysCanonical()
    {
        var file = IpRuleFile.Parse("2620:fe::fe\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(IpRuleKind.Exact, rule.Kind);
        Assert.Equal("2620:fe::fe", rule.Value);
        Assert.Empty(file.Findings);
    }

    [Theory]
    [InlineData("192.168.*", "192.168")]
    [InlineData("10.*", "10")]
    [InlineData("fe80:*", "fe80")]
    [InlineData("2001:db8:*", "2001:db8")]
    public void Parse_trailingStar_classifiedTextPrefix_stripsStarThenOneSeparator(string input, string core)
    {
        var file = IpRuleFile.Parse(input + "\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(IpRuleKind.TextPrefix, rule.Kind);
        Assert.Equal(core, rule.Value);
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("192.168.0.0/16")]
    [InlineData("2620:fe::/32")]
    [InlineData("::1/128")]
    public void Parse_cidr_classifiedCidr(string input)
    {
        var file = IpRuleFile.Parse(input + "\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(IpRuleKind.Cidr, rule.Kind);
        Assert.Empty(file.Findings);
    }

    // ---------------------------------------------------------------- canonicalization (exact)

    [Theory]
    [InlineData("2620:00fe:0000::00fe", "2620:fe::fe")]
    [InlineData("2620:fe:0:0:0:0:0:fe", "2620:fe::fe")]
    [InlineData("FE80::1", "fe80::1")]
    public void Parse_nonCanonicalIpv6_isLintError_showsCanonicalForm(string input, string canonical)
    {
        var file = IpRuleFile.Parse(input + "\n");
        // The proxy would store the verbatim string and NEVER match the canonical answer =>
        // silently ineffective => our lint blocks it as an Error and shows the canonical spelling.
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Equal(1, finding.LineNumber);
        Assert.Contains(canonical, finding.Message);
    }

    [Fact]
    public void Parse_nonCanonicalIpv4_leadingZeros_isLintError()
    {
        // '192.168.001.001' parses in .NET to '192.168.1.1' — a different string than typed, so
        // the proxy's exact-string match would never fire. Flag it.
        var file = IpRuleFile.Parse("192.168.001.001\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Contains("192.168.1.1", finding.Message);
    }

    // ---------------------------------------------------------------- strict rejects

    [Fact]
    public void Parse_atSign_isLintError_notASchedule()
    {
        // IP files do not support '@schedule'; the proxy turns 'ip @sched' into a dead literal.
        var file = IpRuleFile.Parse("1.2.3.4 @office\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Contains("@", finding.Message);
    }

    [Fact]
    public void Parse_bracketedIpv6_isLintError()
    {
        // Response IPs never carry brackets; '[::1]' becomes a dead literal in the proxy.
        var file = IpRuleFile.Parse("[::1]\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    [Fact]
    public void Parse_interiorWildcard_isLintError()
    {
        // '1.2.*.4' — '*' is only legal as a suffix; the proxy errors + skips it.
        var file = IpRuleFile.Parse("1.2.*.4\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    [Fact]
    public void Parse_garbageExact_isLintError()
    {
        var file = IpRuleFile.Parse("nonsense\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    // ---------------------------------------------------------------- textual-prefix warnings

    [Fact]
    public void Parse_tooShortTextPrefix_isWarning_butStillARule()
    {
        // '1*' strips to '1' — matches broadly (any IP string starting '1' at a boundary). The
        // proxy accepts it; we WARN because it is a footgun, but keep it as a TextPrefix rule.
        var file = IpRuleFile.Parse("1*\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(IpRuleKind.TextPrefix, rule.Kind);
        Assert.Equal("1", rule.Value);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Warning && f.LineNumber == 1);
    }

    [Fact]
    public void Parse_bareStar_isLintError_tooShort()
    {
        // A bare '*' is len 1 (< 2) — the proxy rejects it ('suspicious IP rule'), so do we.
        var file = IpRuleFile.Parse("*\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    [Fact]
    public void Parse_atSignInPrefix_isLintError()
    {
        var file = IpRuleFile.Parse("10.@*\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error);
    }

    // ---------------------------------------------------------------- CIDR host-bits decision

    [Theory]
    [InlineData("10.0.0.5/8", "10.0.0.0/8")]
    [InlineData("192.168.1.130/25", "192.168.1.128/25")]
    [InlineData("2620:fe::fe/32", "2620:fe::/32")]
    public void Parse_cidrWithHostBitsSet_isWarning_canonicalizesToNetworkAddress(string input, string network)
    {
        // DOCUMENTED DECISION: accept a host-bits-set CIDR, canonicalize to the network address,
        // and WARN (the proxy's critbitgo tolerates it; we normalize + surface it).
        var file = IpRuleFile.Parse(input + "\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(IpRuleKind.Cidr, rule.Kind);
        Assert.Equal(network, rule.Value);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Warning, finding.Severity);
        Assert.Contains(network, finding.Message);
    }

    [Fact]
    public void Parse_cidrCanonicalNetwork_noWarning()
    {
        var file = IpRuleFile.Parse("10.0.0.0/8\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("10.0.0.0/8", rule.Value);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_nonCanonicalCidrBase_canonicalizesSilently()
    {
        // '2620:00fe::/32' is already a network address but non-canonically spelled; canonicalize
        // to '2620:fe::/32'. No host bits => no warning (the base is unchanged numerically).
        var file = IpRuleFile.Parse("2620:00fe::/32\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("2620:fe::/32", rule.Value);
        Assert.Empty(file.Findings);
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/8foo")]
    [InlineData("10.0.0.0/")]
    [InlineData("nonsense/8")]
    [InlineData("10.0.0.0/8/16")]
    public void Parse_malformedCidr_isLintError(string input)
    {
        var file = IpRuleFile.Parse(input + "\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    [Theory]
    // The proxy's critbitgo AddCIDR wraps Go net.ParseCIDR, whose digit-only prefix scan REJECTS a
    // leading '+' and any whitespace in the prefix. .NET int.TryParse (NumberStyles.Integer) accepts
    // them, so the editor would tell the user the CIDR is valid, save it, and the proxy would then
    // silently DROP the rule (fail-open OPSEC hole). Our lint must reject them to match the proxy.
    [InlineData("10.0.0.0/+8")]
    [InlineData("10.0.0.0/ 8")]
    [InlineData("10.0.0.0/\t8")]
    public void Parse_cidrPrefixWithSignOrWhitespace_isLintError_matchesProxyRejection(string input)
    {
        var file = IpRuleFile.Parse(input + "\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    [Theory]
    // Go net.ParseCIDR REJECTS non-canonical IPv4 network addresses ('invalid CIDR address'), but
    // .NET IPAddress.TryParse silently REWRITES them to a DIFFERENT network: 010.0.0.0 -> 8.0.0.0,
    // 1.2.3.04 -> 1.2.3.4, 192.168.1 -> 192.168.0.1. Without a guard the editor calls the CIDR valid,
    // masks the rewritten address, and either writes a numerically different network to the file
    // (010.0.0.0/8, 192.168.1/24) or silently normalizes leading zeros — while the proxy would drop
    // the rule entirely (fail-open OPSEC hole). Reject non-canonical IPv4 CIDR bases to match Go.
    [InlineData("010.0.0.0/8")]
    [InlineData("1.2.3.04/32")]
    [InlineData("192.168.1/24")]
    public void Parse_nonCanonicalIpv4CidrBase_isLintError_matchesGoRejection(string input)
    {
        var file = IpRuleFile.Parse(input + "\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        Assert.Contains(file.Findings, f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1);
    }

    [Fact]
    public void Parse_nonCanonicalIpv6CidrBase_stillCanonicalizes_noError()
    {
        // Go net.ParseCIDR ACCEPTS IPv6 leading-zero hextets and canonicalizes them, so the IPv4-only
        // guard must NOT regress the existing IPv6 silent-accept (2620:00fe::/32 -> 2620:fe::/32).
        var file = IpRuleFile.Parse("2620:00fe::/32\n");
        var rule = Assert.IsType<IpRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("2620:fe::/32", rule.Value);
        Assert.Empty(file.Findings);
    }

    // ---------------------------------------------------------------- comments / literals

    [Fact]
    public void Parse_inlineComment_stripsAndPreserves()
    {
        var file = IpRuleFile.Parse("203.0.113.7 # known-bad C2 endpoint\n");
        var line = Assert.IsType<IpRuleLine>(file.Lines[0]);
        Assert.Equal("203.0.113.7", line.Rule.Value);
        Assert.Equal("# known-bad C2 endpoint", line.Rule.TrailingComment);
    }

    [Fact]
    public void Parse_fullLineComment_isCommentLine()
    {
        var file = IpRuleFile.Parse("# just a comment\n");
        var comment = Assert.IsType<CommentLine>(file.Lines[0]);
        Assert.Equal("# just a comment", comment.Text);
    }

    [Fact]
    public void Parse_firstByteHashLineWithLaterSpaceHash_isComment_notUnparsed()
    {
        // '#1.2.3.4 #c' — first byte is '#', so the WHOLE line is a comment (proxy: str[0]=='#').
        // The old StripInlineComment left content '#1.2.3.4' -> a spurious UnparsedLine + Error; it
        // must now be a CommentLine with no finding (byte-exact-vs-proxy vector for the IP family).
        var file = IpRuleFile.Parse("#1.2.3.4 #c\n");
        Assert.IsType<CommentLine>(file.Lines[0]);
        Assert.Empty(file.Findings);
    }

    // ---------------------------------------------------------------- round-trip fixed point

    [Fact]
    public void RoundTrip_fixedPoint_preservesCommentsAndOrder()
    {
        const string fixture =
            "# blocked-ips for DnsCryptControl\r\n" +
            "\r\n" +
            "94.140.14.14                # exact v4\r\n" +
            "2620:fe::fe                 # exact v6\r\n" +
            "192.168.*                   # textual prefix\r\n" +
            "10.0.0.0/8                  # cidr\r\n" +
            "203.0.113.7\r\n" +
            "\r\n" +
            "# trailing comment\r\n";

        var first = IpRuleFile.Parse(fixture);
        var serialized = first.Serialize();
        var second = IpRuleFile.Parse(serialized);

        // Fixed point.
        Assert.Equal(serialized, second.Serialize());

        // Order + kinds preserved.
        Assert.Equal(first.Lines.Count, second.Lines.Count);
        Assert.Collection(second.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => { var r = Assert.IsType<IpRuleLine>(l).Rule; Assert.Equal(IpRuleKind.Exact, r.Kind); },
            l => { var r = Assert.IsType<IpRuleLine>(l).Rule; Assert.Equal(IpRuleKind.Exact, r.Kind); },
            l => { var r = Assert.IsType<IpRuleLine>(l).Rule; Assert.Equal(IpRuleKind.TextPrefix, r.Kind); },
            l => { var r = Assert.IsType<IpRuleLine>(l).Rule; Assert.Equal(IpRuleKind.Cidr, r.Kind); },
            l => { var r = Assert.IsType<IpRuleLine>(l).Rule; Assert.Equal(IpRuleKind.Exact, r.Kind); },
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l)); // final CRLF => trailing BlankLine

        // Comments preserved verbatim.
        var v4 = Assert.IsType<IpRuleLine>(second.Lines[2]).Rule;
        Assert.Equal("# exact v4", v4.TrailingComment);
        Assert.Equal("# blocked-ips for DnsCryptControl", ((CommentLine)second.Lines[0]).Text);
        Assert.Equal("# trailing comment", ((CommentLine)second.Lines[8]).Text);
    }

    [Fact]
    public void RoundTrip_canonicalizedExact_isFixedPoint()
    {
        // A canonical exact IP round-trips to itself byte-for-byte.
        var file = IpRuleFile.Parse("94.140.14.14\n2620:fe::fe\n");
        var text = file.Serialize();
        Assert.Equal("94.140.14.14\n2620:fe::fe", text.TrimEnd('\n'));
        Assert.Equal(text, IpRuleFile.Parse(text).Serialize());
    }

    [Fact]
    public void RoundTrip_unparsedLine_preservedVerbatim()
    {
        // A flagged (proxy-would-skip) line survives serialization verbatim so nothing is silently
        // dropped from the user's file.
        var file = IpRuleFile.Parse("good.example.is.not.an.ip\n192.168.001.001\n");
        var second = IpRuleFile.Parse(file.Serialize());
        Assert.Equal(file.Serialize(), second.Serialize());
        Assert.IsType<UnparsedLine>(second.Lines[0]);
        Assert.IsType<UnparsedLine>(second.Lines[1]);
    }

    [Theory]
    // Doubled-separator prefixes: strip '*' leaves a core still ending in a separator, so
    // ClassifyTextPrefix strips ONE MORE. The serializer must re-append the stripped separator
    // (not just the '*') or the prefix silently broadens across a single editor save (IC-4).
    [InlineData("fe80::*")]     // IPv6 link-local; strip '*' -> 'fe80::' -> strip ':' -> 'fe80:'
    [InlineData("2001:db8::*")] // documentation prefix; -> '2001:db8:'
    [InlineData("10..*")]       // doubled dot; strip '*' -> '10.' -> strip '.' -> '10.'? no: '10.'->'10'
    public void RoundTrip_doubledSeparatorTextPrefix_isFixedPoint_prefixDoesNotBroaden(string input)
    {
        // First parse: canonicalize.
        var first = IpRuleFile.Parse(input + "\n");
        var firstRule = Assert.IsType<IpRuleLine>(first.Lines[0]).Rule;
        Assert.Equal(IpRuleKind.TextPrefix, firstRule.Kind);

        // parse -> serialize -> parse must be a fixed point: the second serialize equals the first,
        // and the re-parsed rule Value equals the first (the prefix did NOT broaden).
        var serialized = first.Serialize();
        var second = IpRuleFile.Parse(serialized);
        Assert.Equal(serialized, second.Serialize());

        var secondRule = Assert.IsType<IpRuleLine>(second.Lines[0]).Rule;
        Assert.Equal(firstRule.Value, secondRule.Value);
        Assert.Equal(firstRule.Kind, secondRule.Kind);
    }

    // ---------------------------------------------------------------- never throws

    [Fact]
    public void Parse_neverThrows_onGarbage()
    {
        var file = IpRuleFile.Parse("*\n@\n[::1]\n1.2.*.4\n\0\n//\n10.0.0.0/\n:::::\n1.2.3.4#x\n");
        Assert.NotNull(file);
    }
}
