using DnsCryptControl.Core.Rules;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A1 (shared primitive): <see cref="RuleTextLines"/> replicates dnscrypt-proxy 2.1.16's
/// shared loader spine byte-for-byte — one leading UTF-8 BOM stripped, '\n' (LF) split with a
/// trailing '\r' eaten by TrimSpace, and the quirky <c>TrimAndStripInlineComments</c> where only
/// the LAST '#' counts, a line whose FIRST byte is '#' (or whose last '#' is at index 0) is a
/// whole-line comment, and an inline '#' strips only when the char immediately before it is a
/// space or tab. A2/A3/A4 reuse these helpers, so they are pinned here.
/// </summary>
public class RuleTextLinesTests
{
    // ---------------------------------------------------------------- BOM + LF split

    [Fact]
    public void SplitLines_stripsOneLeadingBom()
    {
        // A single leading UTF-8 BOM (U+FEFF) is stripped; a second one is content.
        var lines = RuleTextLines.SplitLines("﻿example.com\nads.example");
        Assert.Equal(new[] { "example.com", "ads.example" }, lines);
    }

    [Fact]
    public void SplitLines_splitsOnLf_notCrlf_leavesTrailingCrOnRawLine()
    {
        // The splitter splits on '\n' only; the trailing '\r' from a CRLF file stays on the raw
        // line (it is eaten later by StripInlineComment's trim, matching the proxy spine).
        var lines = RuleTextLines.SplitLines("a.com\r\nb.com\r\n");
        // Trailing empty from the final '\n' is preserved as a blank line.
        Assert.Equal(new[] { "a.com\r", "b.com\r", "" }, lines);
    }

    [Fact]
    public void StripInlineComment_eatsTrailingCr_fromCrlfLine()
    {
        // The '\r' left on a raw CRLF line by SplitLines is removed by the content trim.
        var (content, comment) = RuleTextLines.StripInlineComment("example.com\r");
        Assert.Equal("example.com", content);
        Assert.Null(comment);
    }

    [Fact]
    public void SplitLines_null_returnsEmpty()
    {
        Assert.Empty(RuleTextLines.SplitLines(null));
    }

    // ---------------------------------------------------------------- '#' semantics (byte-exact)

    [Fact]
    public void StripInlineComment_literalHash_noSpaceBefore_staysLiteral()
    {
        // 'a#b' — the char before '#' is 'a' (not space/tab) => literal, no comment.
        var (content, comment) = RuleTextLines.StripInlineComment("a#b");
        Assert.Equal("a#b", content);
        Assert.Null(comment);
    }

    [Fact]
    public void StripInlineComment_spaceBeforeHash_strips()
    {
        // 'x # note' — space before '#' => strip to 'x', comment '# note'.
        var (content, comment) = RuleTextLines.StripInlineComment("x # note");
        Assert.Equal("x", content);
        Assert.Equal("# note", comment);
    }

    [Fact]
    public void StripInlineComment_tabBeforeHash_strips()
    {
        var (content, comment) = RuleTextLines.StripInlineComment("x\t# note");
        Assert.Equal("x", content);
        Assert.Equal("# note", comment);
    }

    [Fact]
    public void StripInlineComment_fullLineComment_dropsToEmpty()
    {
        // Last '#' at index 0 => whole line is a comment => empty content.
        var (content, comment) = RuleTextLines.StripInlineComment("#full line");
        Assert.Equal("", content);
        Assert.Equal("#full line", comment);
    }

    [Fact]
    public void StripInlineComment_onlyLastHashConsidered_precedingHashStaysLiteral()
    {
        // 'x#y # z' — only the LAST '#' (before ' z', space-preceded) is a comment;
        // the first '#' in 'x#y' stays literal.
        var (content, comment) = RuleTextLines.StripInlineComment("x#y # z");
        Assert.Equal("x#y", content);
        Assert.Equal("# z", comment);
    }

    [Fact]
    public void StripInlineComment_lastHashNotSpacePreceded_staysLiteral_evenWithEarlierSpaceHash()
    {
        // 'a # b#c' — the LAST '#' is in 'b#c', preceded by 'b' (not space) => literal.
        // Only the last '#' is considered, so the earlier space-'#' does NOT strip.
        var (content, comment) = RuleTextLines.StripInlineComment("a # b#c");
        Assert.Equal("a # b#c", content);
        Assert.Null(comment);
    }

    [Fact]
    public void StripInlineComment_noHash_returnsTrimmedContent_noComment()
    {
        var (content, comment) = RuleTextLines.StripInlineComment("  example.com  ");
        Assert.Equal("example.com", content);
        Assert.Null(comment);
    }

    [Fact]
    public void StripInlineComment_contentTrimmedAfterStrip()
    {
        // Leading/trailing whitespace on the content side is trimmed after the strip.
        var (content, comment) = RuleTextLines.StripInlineComment("   ads.example   # blocked   ");
        Assert.Equal("ads.example", content);
        Assert.Equal("# blocked", comment);
    }

    [Fact]
    public void StripInlineComment_firstByteHash_isFullComment_evenWithLaterSpacePrecededHash()
    {
        // '#a b #c' — the LAST '#' (before 'c') is space-preceded, so the old code took the inline
        // branch and produced a phantom rule '#a b'. The proxy's condition is `idx==0 || str[0]=='#'`
        // — the line's first byte IS '#', so the WHOLE line is a comment. Byte-exact-vs-proxy vector.
        var (content, comment) = RuleTextLines.StripInlineComment("#a b #c");
        Assert.Equal("", content);
        Assert.Equal("#a b #c", comment);
    }

    [Fact]
    public void StripInlineComment_hashAtIndexZeroWithLeadingWhitespaceIsNotIndexZero()
    {
        // '   # comment' — after considering the raw line, the last '#' is not at index 0
        // (leading spaces precede it) and IS space-preceded => strips to empty content,
        // comment preserved.
        var (content, comment) = RuleTextLines.StripInlineComment("   # comment");
        Assert.Equal("", content);
        Assert.Equal("# comment", comment);
    }
}
