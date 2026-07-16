using DnsCryptControl.Core.Rules;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A4: <see cref="ForwardRuleFile"/> parses a forwarding_rules .txt into an ordered list of typed
/// line-models (forward rule | blank | full-line comment | unparsed-with-lint) and serializes it
/// back. The forwarding grammar (from <c>parseForwardFile</c> in <c>plugin_forward.go</c>, tag
/// 2.1.16) splits each meaningful line on the FIRST whitespace only: field 1 = domain, field 2 =
/// the ENTIRE trimmed remainder = a comma-separated server list.
///
/// <para>
/// Domain: a leading <c>*.</c> is cosmetic-stripped; ANY OTHER <c>*</c> is a FATAL start-blocker
/// (the proxy's <c>parseForwardFile</c> returns an error → <c>Init</c> aborts → the proxy WON'T
/// START); the domain is lowercased. Servers: comma-split, each trimmed; forms are bare IPv4 →
/// <c>ip:53</c>, <c>ip:port</c>, bare IPv6 → <c>[ip6]:53</c>, <c>[ip6]:port</c>; plus the
/// case-SENSITIVE special keywords <c>$BOOTSTRAP</c> / <c>$DHCP</c> / <c>$RESOLVCONF:&lt;path&gt;</c>.
/// <c>$RESOLVCONF:&lt;path&gt;</c> is a filesystem-path sink (IC-7): a relative path is a warning.
/// </para>
///
/// <para>
/// FATAL blockers (Error): a stray <c>*</c> in the domain, a missing server, a missing separator.
/// ORDER IS LOAD-BEARING (first-match-wins) — it is preserved verbatim and NEVER reordered; a
/// broader suffix preceding a narrower one is a shadowing WARNING. Understood rows re-emit
/// canonically (servers as <c>ip:port</c>/<c>[ip6]:port</c>, keywords in exact UPPERCASE). Never
/// throws (except <see cref="System.ArgumentNullException"/> for null args — a null file is empty).
/// </para>
/// </summary>
public class ForwardRuleFileTests
{
    // ---------------------------------------------------------------- null / basic

    [Fact]
    public void Parse_null_returnsEmpty_noThrow()
    {
        var file = ForwardRuleFile.Parse(null);
        Assert.Empty(file.Lines);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_empty_serializesToEmptyString()
    {
        Assert.Equal("", ForwardRuleFile.Parse("").Serialize());
    }

    [Fact]
    public void Parse_classifiesLineKinds()
    {
        var file = ForwardRuleFile.Parse("# header\n\nexample.com 9.9.9.9");
        Assert.Collection(file.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<ForwardRuleLine>(l));
    }

    // ---------------------------------------------------------------- domain field

    [Fact]
    public void Parse_bareSuffixDomain_lowercased()
    {
        var file = ForwardRuleFile.Parse("EXAMPLE.com 9.9.9.9\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("example.com", rule.Domain);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_leadingStarDot_cosmeticStripped()
    {
        var file = ForwardRuleFile.Parse("*.internal.example 192.168.2.1\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("internal.example", rule.Domain);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_rootDot_catchAllDomain_isValid()
    {
        var file = ForwardRuleFile.Parse(". 9.9.9.9\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(".", rule.Domain);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_reverseDnsZone_isOrdinarySuffix()
    {
        var file = ForwardRuleFile.Parse("254.169.in-addr.arpa 192.168.1.1\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("254.169.in-addr.arpa", rule.Domain);
        Assert.Empty(file.Findings);
    }

    // ---------------------------------------------------------------- FATAL: stray '*'

    [Theory]
    [InlineData("*example.com 9.9.9.9")]
    [InlineData("ex*.com 9.9.9.9")]
    [InlineData("example.*.com 9.9.9.9")]
    [InlineData("example.com* 9.9.9.9")]
    public void Parse_strayStarInDomain_isFatalBlocker(string line)
    {
        // Any '*' other than a leading '*.' makes parseForwardFile return an error => Init aborts
        // => proxy WON'T START. MUST be an Error-level save blocker.
        var file = ForwardRuleFile.Parse(line + "\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Equal(1, finding.LineNumber);
    }

    // ---------------------------------------------------------------- FATAL: missing separator / server

    [Fact]
    public void Parse_singleToken_noSeparator_isFatalBlocker()
    {
        // A domain with no server (no whitespace) is a fatal syntax error.
        var file = ForwardRuleFile.Parse("example.com\n");
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Equal(1, finding.LineNumber);
    }

    [Fact]
    public void Parse_domainThenOnlyWhitespace_missingServer_isFatalBlocker()
    {
        // 'example.com   ' -> remainder empty after trim => fatal.
        var file = ForwardRuleFile.Parse("example.com    \n");
        // Trailing-whitespace-only after the domain: StripInlineComment trims, so this is actually a
        // single-token line 'example.com' => missing separator => still a blocker.
        Assert.IsType<UnparsedLine>(file.Lines[0]);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
    }

    // ---------------------------------------------------------------- server canonical forms

    [Fact]
    public void Parse_bareIpv4_canonicalizesToPort53()
    {
        var file = ForwardRuleFile.Parse("example.com 9.9.9.9\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "9.9.9.9:53" }, rule.Servers);
    }

    [Fact]
    public void Parse_ipv4WithPort_preservesPort()
    {
        var file = ForwardRuleFile.Parse("example.com 9.9.9.9:5353\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "9.9.9.9:5353" }, rule.Servers);
    }

    [Fact]
    public void Parse_leadingZeroPort_preservedVerbatim_notRenumbered()
    {
        // The proxy's normalizeIPAndOptionalPort re-emits the port substring verbatim (only the IP
        // host is canonicalized), so a non-minimal '053' must stay '053' — we must not renumber it
        // to '53' (editor-only byte drift on an existing file). Covers both v4 and bracketed v6.
        var v4 = ForwardRuleFile.Parse("example.com 8.8.8.8:053\n");
        Assert.Equal(new[] { "8.8.8.8:053" }, Assert.IsType<ForwardRuleLine>(v4.Lines[0]).Rule.Servers);

        var v6 = ForwardRuleFile.Parse("example.com [::1]:053\n");
        Assert.Equal(new[] { "[::1]:053" }, Assert.IsType<ForwardRuleLine>(v6.Lines[0]).Rule.Servers);
    }

    [Fact]
    public void Parse_bareIpv6_canonicalizesToBracketedPort53()
    {
        var file = ForwardRuleFile.Parse("example.com 2620:fe::fe\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "[2620:fe::fe]:53" }, rule.Servers);
    }

    [Fact]
    public void Parse_bracketedIpv6_noPort_canonicalizesToPort53()
    {
        var file = ForwardRuleFile.Parse("example.com [::1]\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "[::1]:53" }, rule.Servers);
    }

    [Fact]
    public void Parse_bracketedIpv6WithPort_preservesPort()
    {
        var file = ForwardRuleFile.Parse("example.com [::1]:5353\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "[::1]:5353" }, rule.Servers);
    }

    [Fact]
    public void Parse_multipleServers_commaSplit_allCanonicalized()
    {
        var file = ForwardRuleFile.Parse("example.com 9.9.9.9,8.8.8.8\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "9.9.9.9:53", "8.8.8.8:53" }, rule.Servers);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_mixedIpv4AndBracketedIpv6WithPorts()
    {
        var file = ForwardRuleFile.Parse("example.com 192.168.1.1:5353,[2620:fe::fe]:5353\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "192.168.1.1:5353", "[2620:fe::fe]:5353" }, rule.Servers);
    }

    [Fact]
    public void Parse_serversWithSpacesAroundComma_trimmed()
    {
        var file = ForwardRuleFile.Parse("example.com 9.9.9.9 , 8.8.8.8\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "9.9.9.9:53", "8.8.8.8:53" }, rule.Servers);
    }

    // ---------------------------------------------------------------- bad server token

    [Fact]
    public void Parse_invalidServerToken_isLintFinding()
    {
        // 'not-an-ip' fails net.ParseIP; the proxy skips that server (non-fatal) but the rule loses
        // a resolver — our lint flags it.
        var file = ForwardRuleFile.Parse("example.com not-an-ip\n");
        Assert.NotEmpty(file.Findings);
    }

    [Fact]
    public void Parse_trailingJunkAfterServer_isLintFinding()
    {
        // 'example.com 9.9.9.9 note' -> serversStr '9.9.9.9 note' -> one token with a space ->
        // net.ParseIP rejects -> the rule ends up with NO usable resolver. Reject the junk.
        var file = ForwardRuleFile.Parse("example.com 9.9.9.9 note\n");
        Assert.NotEmpty(file.Findings);
    }

    [Fact]
    public void Parse_trailingComma_emptyServerToken_isLintFinding()
    {
        var file = ForwardRuleFile.Parse("example.com 9.9.9.9,\n");
        Assert.NotEmpty(file.Findings);
    }

    // ---------------------------------------------------------------- keywords (case-sensitive UPPER)

    [Fact]
    public void Parse_bootstrapKeyword_preservedUpper()
    {
        var file = ForwardRuleFile.Parse("example.com 192.168.1.1,$BOOTSTRAP\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "192.168.1.1:53", "$BOOTSTRAP" }, rule.Servers);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_dhcpKeyword_preservedUpper()
    {
        var file = ForwardRuleFile.Parse("corp.example $DHCP\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "$DHCP" }, rule.Servers);
        Assert.Empty(file.Findings);
    }

    [Fact]
    public void Parse_resolvconfKeyword_posixSlashPath_isRelativeWarningOnWindows()
    {
        // The deployed proxy is dnscrypt-proxy.exe (win64): Go's Windows filepath.IsAbs('/etc/...')
        // is FALSE (a lone leading '/' is 'rooted but not absolute'), so the proxy logs a relative-
        // path warning and resolves it against its CWD. Our lint must mirror that, NOT treat a POSIX
        // '/etc/resolv.conf' as clean/absolute on this Windows-only deployment.
        var file = ForwardRuleFile.Parse("vpn.example $RESOLVCONF:/etc/resolv.conf\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { "$RESOLVCONF:/etc/resolv.conf" }, rule.Servers); // KEPT verbatim
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Warning, finding.Severity);
        Assert.Contains("relative", finding.Message, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_resolvconfKeyword_windowsAbsolutePath_isSurfacedWarning_kept()
    {
        // A genuine Windows absolute path (drive-rooted) is accepted by the proxy silently, but it is
        // still a proxy-privileged filesystem-path sink — IC-7 says surface it prominently. We KEEP
        // the token and emit a (non-blocking) Warning so the sink is reviewable.
        var file = ForwardRuleFile.Parse(@"vpn.example $RESOLVCONF:C:\ProgramData\resolv.conf" + "\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal(new[] { @"$RESOLVCONF:C:\ProgramData\resolv.conf" }, rule.Servers);
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Warning, finding.Severity);
        Assert.Contains("absolute", finding.Message, System.StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("$bootstrap")]
    [InlineData("$Bootstrap")]
    [InlineData("$dhcp")]
    [InlineData("$UNKNOWN")]
    public void Parse_wrongCaseOrUnknownKeyword_isLintFinding(string keyword)
    {
        // Keywords are CASE-SENSITIVE exact tokens; the proxy silently drops an unknown '$...' token
        // (the rule loses that target). A wrong-case '$dhcp' is a silent-failure footgun.
        var file = ForwardRuleFile.Parse($"example.com {keyword}\n");
        Assert.NotEmpty(file.Findings);
    }

    // ---------------------------------------------------------------- $RESOLVCONF path sink (IC-7)

    [Fact]
    public void Parse_resolvconfRelativePath_isWarning()
    {
        // The proxy only warns on a relative $RESOLVCONF path (still uses it). Surface it.
        var file = ForwardRuleFile.Parse("vpn.example $RESOLVCONF:relative/resolv.conf\n");
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Warning, finding.Severity);
        Assert.Contains("RESOLVCONF", finding.Message, System.StringComparison.OrdinalIgnoreCase);
        // The rule is KEPT (proxy accepts it) so it round-trips.
        Assert.IsType<ForwardRuleLine>(file.Lines[0]);
    }

    [Fact]
    public void Parse_resolvconfEmptyPath_isError()
    {
        // '$RESOLVCONF:' with no path -> the proxy logs Criticalf + skips the token (rule loses it).
        var file = ForwardRuleFile.Parse("vpn.example $RESOLVCONF:\n");
        var finding = Assert.Single(file.Findings);
        Assert.Equal(RuleLintSeverity.Error, finding.Severity);
        Assert.Contains("RESOLVCONF", finding.Message, System.StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- shadowing order (first-match)

    [Fact]
    public void Parse_broaderSuffixBeforeNarrower_isShadowingWarning()
    {
        // '.' (root, matches everything) placed ABOVE 'example.com' shadows it: first-match-wins.
        var file = ForwardRuleFile.Parse(
            ". 9.9.9.9\n" +
            "example.com 8.8.8.8\n");
        Assert.Contains(
            file.Findings,
            f => f.Severity == RuleLintSeverity.Warning &&
                 f.LineNumber == 2 &&
                 f.Message.Contains("shadow", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Parse_broaderSuffixBeforeNarrower_parentZone_isShadowingWarning()
    {
        // 'example.com' (suffix) shadows the more specific 'sub.example.com' that follows it.
        var file = ForwardRuleFile.Parse(
            "example.com 9.9.9.9\n" +
            "sub.example.com 8.8.8.8\n");
        Assert.Contains(
            file.Findings,
            f => f.Severity == RuleLintSeverity.Warning &&
                 f.LineNumber == 2 &&
                 f.Message.Contains("shadow", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Parse_narrowerBeforeBroader_isNotShadowed()
    {
        // Correct ordering: specific first, broad after => no shadowing warning.
        var file = ForwardRuleFile.Parse(
            "sub.example.com 9.9.9.9\n" +
            "example.com 8.8.8.8\n");
        Assert.DoesNotContain(
            file.Findings,
            f => f.Message.Contains("shadow", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Parse_unrelatedDomains_notShadowed()
    {
        var file = ForwardRuleFile.Parse(
            "example.com 9.9.9.9\n" +
            "example.net 8.8.8.8\n");
        Assert.DoesNotContain(
            file.Findings,
            f => f.Message.Contains("shadow", System.StringComparison.OrdinalIgnoreCase));
    }

    // ---------------------------------------------------------------- order NEVER reordered

    [Fact]
    public void Serialize_preservesFileOrder_verbatim()
    {
        // Even a shadowing (warned) order must round-trip in the SAME order — never silently sorted.
        var file = ForwardRuleFile.Parse(
            ". 9.9.9.9\n" +
            "example.com 8.8.8.8\n" +
            "sub.example.com 1.1.1.1\n");
        var second = ForwardRuleFile.Parse(file.Serialize());
        var domains = new List<string>();
        foreach (var line in second.Lines)
        {
            if (line is ForwardRuleLine frl)
            {
                domains.Add(frl.Rule.Domain);
            }
        }

        Assert.Equal(new[] { ".", "example.com", "sub.example.com" }, domains);
    }

    // ---------------------------------------------------------------- comments / whitespace

    [Fact]
    public void Parse_inlineComment_stripsAndPreserves()
    {
        var file = ForwardRuleFile.Parse("example.net 9.9.9.9 # forward this zone to Quad9\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("example.net", rule.Domain);
        Assert.Equal(new[] { "9.9.9.9:53" }, rule.Servers);
        Assert.Equal("# forward this zone to Quad9", rule.TrailingComment);
    }

    [Fact]
    public void Parse_tabSeparator_isAccepted()
    {
        var file = ForwardRuleFile.Parse("example.com\t9.9.9.9\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("example.com", rule.Domain);
        Assert.Equal(new[] { "9.9.9.9:53" }, rule.Servers);
    }

    [Fact]
    public void Parse_multipleSpacesBetweenDomainAndServers_collapse()
    {
        var file = ForwardRuleFile.Parse("example.com      9.9.9.9\n");
        var rule = Assert.IsType<ForwardRuleLine>(file.Lines[0]).Rule;
        Assert.Equal("example.com", rule.Domain);
        Assert.Equal(new[] { "9.9.9.9:53" }, rule.Servers);
    }

    // ---------------------------------------------------------------- canonical serialization

    [Fact]
    public void Serialize_understoodRow_isCanonical_singleSpace_canonicalServers()
    {
        var file = ForwardRuleFile.Parse("  EXAMPLE.com     9.9.9.9 , 8.8.8.8   # note\n");
        Assert.Equal("example.com 9.9.9.9:53,8.8.8.8:53 # note", file.Serialize().TrimEnd('\n'));
    }

    [Fact]
    public void Serialize_keywords_emittedExactUpper()
    {
        var file = ForwardRuleFile.Parse("example.com 192.168.1.1,$BOOTSTRAP\n");
        Assert.Equal("example.com 192.168.1.1:53,$BOOTSTRAP", file.Serialize().TrimEnd('\n'));
    }

    [Fact]
    public void Serialize_leadingStarDot_reemittedAsBareSuffix()
    {
        // The '*.' is cosmetic; canonical form is the bare suffix (round-trips as a fixed point).
        var file = ForwardRuleFile.Parse("*.internal.example 192.168.2.1\n");
        Assert.Equal("internal.example 192.168.2.1:53", file.Serialize().TrimEnd('\n'));
    }

    // ---------------------------------------------------------------- round-trip fixed point

    [Fact]
    public void RoundTrip_fixedPoint_preservesCommentsAndOrder()
    {
        const string fixture =
            "# forwarding rules for DnsCryptControl\r\n" +
            "\r\n" +
            "example.com          9.9.9.9,8.8.8.8   # quad9 + google\r\n" +
            "*.internal.example   192.168.2.1,192.168.2.2\r\n" +
            "10.in-addr.arpa      192.168.1.1\r\n" +
            "corp.example         $DHCP\r\n" +
            "vpn.example          9.9.9.10\r\n" +
            "boot.example         192.168.1.1,$BOOTSTRAP\r\n" +
            "\r\n" +
            "# trailing comment\r\n";

        var first = ForwardRuleFile.Parse(fixture);
        var serialized = first.Serialize();
        var second = ForwardRuleFile.Parse(serialized);

        // Fixed point.
        Assert.Equal(serialized, second.Serialize());
        Assert.Empty(first.Findings);

        // Order + kinds preserved.
        Assert.Equal(first.Lines.Count, second.Lines.Count);
        Assert.Collection(second.Lines,
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<ForwardRuleLine>(l),
            l => Assert.IsType<ForwardRuleLine>(l),
            l => Assert.IsType<ForwardRuleLine>(l),
            l => Assert.IsType<ForwardRuleLine>(l),
            l => Assert.IsType<ForwardRuleLine>(l),
            l => Assert.IsType<ForwardRuleLine>(l),
            l => Assert.IsType<BlankLine>(l),
            l => Assert.IsType<CommentLine>(l),
            l => Assert.IsType<BlankLine>(l)); // final CRLF => trailing BlankLine

        // Comments preserved verbatim.
        var quad9 = Assert.IsType<ForwardRuleLine>(second.Lines[2]).Rule;
        Assert.Equal("# quad9 + google", quad9.TrailingComment);
        Assert.Equal("# forwarding rules for DnsCryptControl", ((CommentLine)second.Lines[0]).Text);
        Assert.Equal("# trailing comment", ((CommentLine)second.Lines[9]).Text);
    }

    [Fact]
    public void RoundTrip_keywordsAndResolvconf_upperAndPathPreserved()
    {
        var file = ForwardRuleFile.Parse(
            "a.example $DHCP\n" +
            "b.example $BOOTSTRAP\n" +
            "c.example $RESOLVCONF:/etc/resolv.conf\n");
        var second = ForwardRuleFile.Parse(file.Serialize());
        Assert.Equal(file.Serialize(), second.Serialize());
        Assert.Equal(new[] { "$DHCP" }, Assert.IsType<ForwardRuleLine>(second.Lines[0]).Rule.Servers);
        Assert.Equal(new[] { "$BOOTSTRAP" }, Assert.IsType<ForwardRuleLine>(second.Lines[1]).Rule.Servers);
        Assert.Equal(
            new[] { "$RESOLVCONF:/etc/resolv.conf" },
            Assert.IsType<ForwardRuleLine>(second.Lines[2]).Rule.Servers);
    }

    [Fact]
    public void RoundTrip_unparsedLine_preservedVerbatim()
    {
        // A flagged (fatal) line survives serialization verbatim.
        var file = ForwardRuleFile.Parse("ex*.com 9.9.9.9\nexample.com\n");
        var second = ForwardRuleFile.Parse(file.Serialize());
        Assert.Equal(file.Serialize(), second.Serialize());
        Assert.IsType<UnparsedLine>(second.Lines[0]);
        Assert.IsType<UnparsedLine>(second.Lines[1]);
    }

    // ---------------------------------------------------------------- never throws

    [Fact]
    public void Parse_neverThrows_onGarbage()
    {
        var file = ForwardRuleFile.Parse(
            "ex*.com x\n. \n*\nexample.com\nexample.com 9.9.9.9 junk here\n\0\n$DHCP\nexample.com $RESOLVCONF:\n");
        Assert.NotNull(file);
    }
}
