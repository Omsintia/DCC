using DnsCryptControl.Core.QueryLog;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// Ground-truth tests for <see cref="QueryLogParser"/> against the dnscrypt-proxy 2.1.16 TSV query
/// log captured live from the shipped binary (VM spikes 501/502). The parser is pure/total and
/// lenient: it maps the full <see cref="QueryAction"/> taxonomy, normalises the duration, preserves
/// every string field verbatim, drops a partial trailing line, and skips-and-continues on any
/// malformed line — never throwing (mirrors the Phase 5d rule-parser discipline).
/// </summary>
public class QueryLogParserTests
{
    // The five taxonomy rows captured live (columns TAB-separated) — exactly as in the design spec.
    private const string PassLine = "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tPASS\t183ms\ta-and-a\t-";
    private const string RejectLine = "[2026-07-03 10:24:59]\t127.0.0.1\tdoubleclick.net\tA\tREJECT\t5ms\t-\t-";
    private const string CloakLine = "[2026-07-03 10:24:59]\t127.0.0.1\tmyrouter.home\tA\tCLOAK\t0ms\t-\t-";
    private const string SynthLine = "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tAAAA\tSYNTH\t2ms\t-\t-";
    private const string NxDomainLine = "[2026-07-03 10:24:59]\t127.0.0.1\tnonexistent-xyz-12345.invalid\tA\tNXDOMAIN\t174ms\ta-and-a\t-";

    // --------------------------------------------------------------- the 5 ground-truth taxonomy rows

    [Fact]
    public void ParseLine_pass_parsesAllFields()
    {
        var line = QueryLogParser.ParseLine(PassLine);

        Assert.NotNull(line);
        Assert.Equal("[2026-07-03 10:24:59]", line!.Time);
        Assert.Equal("127.0.0.1", line.Client);
        Assert.Equal("example.com", line.Name);
        Assert.Equal("A", line.Type);
        Assert.Equal(QueryAction.Pass, line.Action);
        Assert.Equal(183, line.DurationMs);
        Assert.Equal("a-and-a", line.Server);
        Assert.Equal("-", line.Relay);
    }

    [Fact]
    public void ParseLine_reject_mapsActionAndLocalAnswerDashes()
    {
        var line = QueryLogParser.ParseLine(RejectLine);

        Assert.NotNull(line);
        Assert.Equal("doubleclick.net", line!.Name);
        Assert.Equal(QueryAction.Reject, line.Action);
        Assert.Equal(5, line.DurationMs);
        Assert.Equal("-", line.Server); // locally answered => '-'
        Assert.Equal("-", line.Relay);
    }

    [Fact]
    public void ParseLine_cloak_mapsActionAndZeroDuration()
    {
        var line = QueryLogParser.ParseLine(CloakLine);

        Assert.NotNull(line);
        Assert.Equal("myrouter.home", line!.Name);
        Assert.Equal(QueryAction.Cloak, line.Action);
        Assert.Equal(0, line.DurationMs);
    }

    [Fact]
    public void ParseLine_synth_mapsActionAndAaaaType()
    {
        var line = QueryLogParser.ParseLine(SynthLine);

        Assert.NotNull(line);
        Assert.Equal("AAAA", line!.Type);
        Assert.Equal(QueryAction.Synth, line.Action);
        Assert.Equal(2, line.DurationMs);
    }

    [Fact]
    public void ParseLine_nxDomain_mapsAction()
    {
        var line = QueryLogParser.ParseLine(NxDomainLine);

        Assert.NotNull(line);
        Assert.Equal("nonexistent-xyz-12345.invalid", line!.Name);
        Assert.Equal(QueryAction.NxDomain, line.Action);
        Assert.Equal(174, line.DurationMs);
        Assert.Equal("a-and-a", line.Server);
    }

    [Fact]
    public void ParseLine_forward_mapsAction()
    {
        // FORWARD is in the taxonomy though not in the 5 captured rows (forwarding-rule match).
        var line = QueryLogParser.ParseLine(
            "[2026-07-03 10:24:59]\t127.0.0.1\tinternal.corp\tA\tFORWARD\t12ms\t-\t-");

        Assert.NotNull(line);
        Assert.Equal(QueryAction.Forward, line!.Action);
    }

    // --------------------------------------------------------------- unknown action -> Other

    [Fact]
    public void ParseLine_unknownAction_mapsToOther()
    {
        // An unseen future action token must classify, never crash (taxonomy is closed + Other).
        var line = QueryLogParser.ParseLine(
            "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tWHATEVER\t9ms\ta-and-a\t-");

        Assert.NotNull(line);
        Assert.Equal(QueryAction.Other, line!.Action);
    }

    [Fact]
    public void ParseLine_actionMappingIsCaseSensitive_lowercaseIsOther()
    {
        // The proxy always upper-cases the action; a lowercase token is not a known action.
        var line = QueryLogParser.ParseLine(
            "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tpass\t9ms\ta-and-a\t-");

        Assert.NotNull(line);
        Assert.Equal(QueryAction.Other, line!.Action);
    }

    // --------------------------------------------------------------- malformed / short line -> null

    [Fact]
    public void ParseLine_shortLine_returnsNull()
    {
        // Only 5 columns (< 8 required) — a half-written / malformed line is skipped, never fatal.
        var line = QueryLogParser.ParseLine("[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tPASS");
        Assert.Null(line);
    }

    [Fact]
    public void ParseLine_emptyString_returnsNull()
    {
        Assert.Null(QueryLogParser.ParseLine(string.Empty));
    }

    [Fact]
    public void ParseLine_null_returnsNull()
    {
        Assert.Null(QueryLogParser.ParseLine(null));
    }

    [Fact]
    public void ParseLine_neverThrows_onArbitraryGarbage()
    {
        // No column layout at all — must not throw, must return null.
        var line = QueryLogParser.ParseLine("this is not a tsv line at all");
        Assert.Null(line);
    }

    // --------------------------------------------------------------- bad duration -> 0

    [Fact]
    public void ParseLine_badDuration_yieldsZero()
    {
        var line = QueryLogParser.ParseLine(
            "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tPASS\tNOTMS\ta-and-a\t-");

        Assert.NotNull(line);
        Assert.Equal(0, line!.DurationMs); // unparseable token -> 0, line still kept
    }

    [Fact]
    public void ParseLine_bareNumericDuration_noMsSuffix_isParsed()
    {
        var line = QueryLogParser.ParseLine(
            "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tPASS\t42\ta-and-a\t-");

        Assert.NotNull(line);
        Assert.Equal(42, line!.DurationMs);
    }

    // --------------------------------------------------------------- verbatim fields (server/relay)

    [Fact]
    public void ParseLine_serverAndRelay_preservedVerbatim()
    {
        var line = QueryLogParser.ParseLine(
            "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tPASS\t7ms\tcloudflare\tanon-relay-1");

        Assert.NotNull(line);
        Assert.Equal("cloudflare", line!.Server);
        Assert.Equal("anon-relay-1", line.Relay);
    }

    // --------------------------------------------------------------- StripTimeBrackets helper

    [Fact]
    public void StripTimeBrackets_removesSurroundingBrackets()
    {
        Assert.Equal("2026-07-03 10:24:59", QueryLogParser.StripTimeBrackets("[2026-07-03 10:24:59]"));
    }

    [Fact]
    public void StripTimeBrackets_unbracketedInput_returnedVerbatim()
    {
        Assert.Equal("no brackets", QueryLogParser.StripTimeBrackets("no brackets"));
    }

    // --------------------------------------------------------------- ParseLines: empty / partial-tail

    [Fact]
    public void ParseLines_emptyString_returnsEmpty()
    {
        Assert.Empty(QueryLogParser.ParseLines(string.Empty));
    }

    [Fact]
    public void ParseLines_null_returnsEmpty()
    {
        Assert.Empty(QueryLogParser.ParseLines(null));
    }

    [Fact]
    public void ParseLines_dropsPartialTrailingLine_keepsCompleteLines()
    {
        // Two complete newline-terminated lines + a half-written third line with NO terminator.
        // A live tail can read that partial last line, so it must be dropped.
        var text = PassLine + "\n" + RejectLine + "\n" + "[2026-07-03 10:24:59]\t127.0.0.1\tpartial";

        var lines = QueryLogParser.ParseLines(text);

        Assert.Equal(2, lines.Count);
        Assert.Equal("example.com", lines[0].Name);
        Assert.Equal("doubleclick.net", lines[1].Name);
    }

    [Fact]
    public void ParseLines_keepsFinalCompleteLine_whenTerminatedByNewline()
    {
        // A trailing '\n' means the last real line is COMPLETE and must be kept.
        var text = PassLine + "\n" + RejectLine + "\n";

        var lines = QueryLogParser.ParseLines(text);

        Assert.Equal(2, lines.Count);
        Assert.Equal("doubleclick.net", lines[1].Name);
    }

    [Fact]
    public void ParseLines_skipsMalformedLine_andContinues()
    {
        // A malformed (short) middle line is skipped; the surrounding valid lines still parse.
        var text = PassLine + "\n" + "garbage-short-line\n" + RejectLine + "\n";

        var lines = QueryLogParser.ParseLines(text);

        Assert.Equal(2, lines.Count);
        Assert.Equal(QueryAction.Pass, lines[0].Action);
        Assert.Equal(QueryAction.Reject, lines[1].Action);
    }

    [Fact]
    public void ParseLines_parsesAllFiveTaxonomyRows_inOrder()
    {
        var text = string.Join("\n", PassLine, RejectLine, CloakLine, SynthLine, NxDomainLine) + "\n";

        var lines = QueryLogParser.ParseLines(text);

        Assert.Equal(5, lines.Count);
        Assert.Equal(
            new[]
            {
                QueryAction.Pass,
                QueryAction.Reject,
                QueryAction.Cloak,
                QueryAction.Synth,
                QueryAction.NxDomain,
            },
            lines.Select(l => l.Action).ToArray());
    }
}
