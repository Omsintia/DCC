using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A3: <see cref="ResolverListParser"/> mirrors dnscrypt-proxy 2.1.16's parseV2 (substring
/// "## " split, 1:N stamps per entry, hard-abort semantics, prefix-inside-parser) with
/// hardening (caps, IC-7 selectability, description sanitization). Fail-closed on hostile input.
/// </summary>
public class ResolverListParserTests
{
    private const string DohCloudflare = "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5";
    private const string DohGoogle = "sdns://AgUAAAAAAAAABzguOC44LjggsKKKE4EwvtIbNjGjagI2607EdKSVHowYZtyvD9iPrkkHOC44LjguOAovZG5zLXF1ZXJ5";
    private const string Relay = "sdns://gQ8xNDYuNzAuODIuMzo0NDM";

    private const string TwoEntries =
        "# public-resolvers\n" +
        "\n" +
        "intro text that must be discarded\n" +
        "--\n" +
        "\n" +
        "\n" +
        "## cloudflare\n" +
        "\n" +
        "Cloudflare DNS.\n" +
        "\n" +
        DohCloudflare + "\n" +
        "\n" +
        "\n" +
        "## a-and-a\n" +
        "\n" +
        "Non-filtering DoH.\n" +
        "// this line is a comment and must be skipped\n" +
        DohCloudflare + "\n" +
        DohGoogle + "\n";

    [Fact]
    public void Parse_discardsPreamble_andReadsEntries()
    {
        var result = ResolverListParser.Parse(TwoEntries, prefix: "");

        Assert.False(result.WholeFileInvalid);
        Assert.Equal(2, result.Entries.Count);
        Assert.Equal("cloudflare", result.Entries[0].Name);
        Assert.Equal("a-and-a", result.Entries[1].Name);
    }

    [Fact]
    public void Parse_cloudflareEntry_hasStampDescriptionAndSelectable()
    {
        var e = ResolverListParser.Parse(TwoEntries, prefix: "").Entries[0];

        Assert.Equal("Cloudflare DNS.", e.Description);
        Assert.Single(e.Stamps);
        Assert.Equal(StampProtocol.DoH, e.Stamps[0].Protocol);
        Assert.True(e.HasUsableStamp);
        Assert.True(e.IsSelectable);
    }

    [Fact]
    public void Parse_multiStampEntry_retainsAllStamps_andSkipsCommentLines()
    {
        var e = ResolverListParser.Parse(TwoEntries, prefix: "").Entries[1];

        Assert.Equal(2, e.StampStrings.Count);
        Assert.Equal(2, e.Stamps.Count);
        Assert.DoesNotContain("comment", e.Description); // // lines are skipped, not description
        Assert.Equal("Non-filtering DoH.", e.Description);
    }

    [Fact]
    public void Parse_appliesPrefixToNames()
    {
        var result = ResolverListParser.Parse(TwoEntries, prefix: "quad9-");
        Assert.Equal("quad9-cloudflare", result.Entries[0].Name);
        Assert.Equal("cloudflare", result.Entries[0].RawName);
    }

    [Fact]
    public void Parse_toleratesCrlf()
    {
        var crlf = TwoEntries.Replace("\n", "\r\n");
        var result = ResolverListParser.Parse(crlf, prefix: "");
        Assert.Equal(2, result.Entries.Count);
        Assert.Equal("cloudflare", result.Entries[0].Name);
        Assert.Equal("Cloudflare DNS.", result.Entries[0].Description);
    }

    [Fact]
    public void Parse_toleratesBom()
    {
        var result = ResolverListParser.Parse("﻿" + TwoEntries, prefix: "");
        Assert.Equal(2, result.Entries.Count);
    }

    [Fact]
    public void Parse_relayEntry_isClassifiedByStampProto()
    {
        var result = ResolverListParser.Parse("## anon-cs-de\n\nA relay.\n" + Relay + "\n", prefix: "");
        var e = Assert.Single(result.Entries);
        Assert.True(e.IsRelay);
        Assert.Equal(StampProtocol.DnsCryptRelay, e.PrimaryProtocol);
    }

    [Fact]
    public void Parse_missingStampEntry_isRetainedButNotSelectable_withWarning()
    {
        var result = ResolverListParser.Parse("## no-stamp\n\nJust a description, no stamp.\n", prefix: "");
        var e = Assert.Single(result.Entries);
        Assert.False(e.HasUsableStamp);
        Assert.False(e.IsSelectable);
        Assert.Contains(result.Warnings, w => w.Contains("no-stamp"));
    }

    [Fact]
    public void Parse_hostileName_isRenderedButNotSelectable()
    {
        var result = ResolverListParser.Parse("## bad\"name\n\ndesc\n" + DohCloudflare + "\n", prefix: "");
        var e = Assert.Single(result.Entries);
        Assert.Equal("bad\"name", e.RawName); // rendered as-is
        Assert.True(e.HasUsableStamp);
        Assert.False(e.IsSelectable);          // fails the IC-7 allowlist — refuse to write it into config
    }

    [Fact]
    public void Parse_mixedProtocolEntry_isFlaggedAnomalous()
    {
        // one DoH stamp + one relay stamp under a single name — the proxy picks one at random.
        var result = ResolverListParser.Parse("## mixed\n\ndesc\n" + DohCloudflare + "\n" + Relay + "\n", prefix: "");
        var e = Assert.Single(result.Entries);
        Assert.NotEmpty(e.Anomalies);
    }

    [Fact]
    public void Parse_bidiOverrideInDescription_isStrippedAndFlagged()
    {
        var result = ResolverListParser.Parse("## spoof\n\nsafe‮evil\n" + DohCloudflare + "\n", prefix: "");
        var e = Assert.Single(result.Entries);
        Assert.DoesNotContain('‮', e.Description);
        Assert.NotEmpty(e.Anomalies);
    }

    [Fact]
    public void Parse_extendedBidiAndSeparators_areStripped()
    {
        // Core review IMPORTANT: LRM (U+200E), RLM (U+200F), and the line/paragraph separators
        // (U+2028/U+2029) sit outside the old enumerated ranges and previously survived.
        var input = "## spoof\n\nsafe" + (char)0x200E + "evil" + (char)0x2028 + "line"
            + (char)0x2029 + "para" + (char)0x200F + "mark\n" + DohCloudflare + "\n";
        var e = Assert.Single(ResolverListParser.Parse(input, prefix: "").Entries);
        Assert.DoesNotContain(e.Description, ch =>
            ch == (char)0x2028 || ch == (char)0x2029
            || System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) == System.Globalization.UnicodeCategory.Format);
        Assert.NotEmpty(e.Anomalies);
    }

    [Fact]
    public void Parse_delimiterFlood_boundsWarnings()
    {
        // Core review MINOR: a flood of bare "## " must not append unbounded warnings.
        var flood = string.Concat(System.Linq.Enumerable.Repeat("## \n", 50_000));
        var result = ResolverListParser.Parse(flood, prefix: "");
        Assert.True(result.Warnings.Count <= ResolverListParser.MaxEntries);
    }

    [Fact]
    public void Parse_hardAbortEntry_setsProxyWouldStopAt_butContinuesParsing()
    {
        var text =
            "## good\n\ndesc\n" + DohCloudflare + "\n" +
            "## lonely\n"; // single line after trim -> proxy aborts here
        var result = ResolverListParser.Parse(text, prefix: "");

        Assert.Equal(1, result.ProxyWouldStopAtEntryIndex); // proxy keeps [good], drops the rest
        Assert.True(result.IsBeyondProxyStop(1));
        Assert.False(result.IsBeyondProxyStop(0));
    }

    [Fact]
    public void Parse_noDelimiterAtAll_isWholeFileInvalid()
    {
        var result = ResolverListParser.Parse("# just a header\nno entries here\n", prefix: "");
        Assert.True(result.WholeFileInvalid);
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void Parse_duplicateNames_warns_butRetainsBoth()
    {
        var text =
            "## dup\n\nfirst\n" + DohCloudflare + "\n" +
            "## dup\n\nsecond\n" + DohGoogle + "\n";
        var result = ResolverListParser.Parse(text, prefix: "");
        Assert.Equal(2, result.Entries.Count);
        Assert.Contains(result.Warnings, w => w.Contains("dup"));
    }

    [Fact]
    public void Parse_oversizeInput_isTruncated_notThrown()
    {
        var big = "## big\n\ndesc\n" + DohCloudflare + "\n" + new string('x', ResolverListParser.MaxFileChars + 10);
        var result = ResolverListParser.Parse(big, prefix: "");
        Assert.True(result.Truncated);
    }

    [Fact]
    public void Parse_neverThrows_onHostileInput()
    {
        string?[] inputs = { null, "", "## ", "## \n", "##  \n\n\n", "## a\n\n" + new string('#', 5000) };
        foreach (var i in inputs)
        {
            var result = ResolverListParser.Parse(i, prefix: "");
            Assert.NotNull(result);
        }
    }

    [Fact]
    public void Parse_nullText_isWholeFileInvalid()
    {
        var result = ResolverListParser.Parse(null, prefix: "");
        Assert.True(result.WholeFileInvalid);
    }
}
