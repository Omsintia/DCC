using DnsCryptControl.Core.Rules;
using DnsCryptControl.Platform;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Shared row-projection spine for the per-family codecs. The Core rule files
/// (<see cref="NameRuleFile"/> / <see cref="IpRuleFile"/> / <see cref="CloakRuleFile"/> /
/// <see cref="ForwardRuleFile"/>) expose the SAME shape — an ordered
/// <see cref="RuleFileLine"/> list, a <see cref="RuleLintFinding"/> list, and a
/// <c>Serialize()</c> — but share no interface, so each adapter hands this spine its parsed
/// <c>Lines</c>, its <c>Findings</c>, and its serialized text, and the spine builds the
/// display-neutral <see cref="RuleParseResult"/>. The per-line canonical text is produced by the
/// SAME serializer the family uses (a one-line list round-trip) so understood rules re-emit
/// canonically and blank/comment/unparsed lines re-emit verbatim (IC-4) — never a hand-rolled
/// second serialization that could drift from Core.
/// </summary>
internal static class RuleRowProjection
{
    /// <summary>
    /// Projects one family's parse into the shared <see cref="RuleParseResult"/>. <paramref name="lineTexts"/>
    /// is the per-line canonical text (same order as <paramref name="lines"/>, produced by the family's
    /// own serializer split on <c>'\n'</c>); <paramref name="wholeText"/> is the whole-file canonical
    /// serialization. Findings are bucketed onto their 1-based owning row.
    /// </summary>
    public static RuleParseResult Build(
        IReadOnlyList<RuleFileLine> lines,
        IReadOnlyList<string> lineTexts,
        string wholeText,
        IReadOnlyList<RuleLintFinding> findings)
    {
        // A serializer joins N lines with N-1 '\n', so split yields exactly N segments — one per line.
        // Guard defensively: if they ever diverge, fall back to the line's own kind text so we never
        // index out of range (Core keeps them equal — asserted by the round-trip tests).
        var byLine = new List<RuleLintFinding>[lines.Count];
        foreach (var finding in findings)
        {
            var idx = finding.LineNumber - 1;
            if (idx < 0 || idx >= lines.Count)
            {
                continue;
            }

            (byLine[idx] ??= new List<RuleLintFinding>()).Add(finding);
        }

        var rows = new RuleRowModel[lines.Count];
        for (var i = 0; i < lines.Count; i++)
        {
            var text = i < lineTexts.Count ? lineTexts[i] : string.Empty;
            var rowFindings = (IReadOnlyList<RuleLintFinding>?)byLine[i] ?? Array.Empty<RuleLintFinding>();
            rows[i] = new RuleRowModel(KindOf(lines[i]), text, rowFindings);
        }

        return new RuleParseResult(rows, wholeText, findings);
    }

    /// <summary>Splits a whole-file serialization back into per-line segments (the serializer joins with
    /// <c>'\n'</c>; empty input is zero lines, matching an empty <c>Lines</c> list).</summary>
    public static IReadOnlyList<string> SplitLines(string serialized) =>
        serialized.Length == 0 ? Array.Empty<string>() : serialized.Split('\n');

    private static RuleRowKind KindOf(RuleFileLine line) => line switch
    {
        BlankLine => RuleRowKind.Blank,
        CommentLine => RuleRowKind.Comment,
        UnparsedLine => RuleRowKind.Unparsed,
        _ => RuleRowKind.Rule, // NameRuleLine / IpRuleLine / CloakRuleLine / ForwardRuleLine
    };
}

/// <summary>Codec over the A1 blocked_names / allowed_names parser (<see cref="NameRuleFile"/>).</summary>
public sealed class NameRuleFamilyCodec : IRuleFamilyCodec
{
    public NameRuleFamilyCodec(RuleFileKind kind)
    {
        if (kind is not (RuleFileKind.BlockedNames or RuleFileKind.AllowedNames))
        {
            throw new ArgumentOutOfRangeException(
                nameof(kind), kind, "the name codec handles only BlockedNames/AllowedNames");
        }

        Kind = kind;
    }

    public RuleFileKind Kind { get; }

    public RuleParseResult Parse(string? text)
    {
        var file = NameRuleFile.Parse(text);
        var whole = file.Serialize();
        return RuleRowProjection.Build(file.Lines, RuleRowProjection.SplitLines(whole), whole, file.Findings);
    }
}

/// <summary>Codec over the A2 blocked_ips / allowed_ips parser (<see cref="IpRuleFile"/>).</summary>
public sealed class IpRuleFamilyCodec : IRuleFamilyCodec
{
    public IpRuleFamilyCodec(RuleFileKind kind)
    {
        if (kind is not (RuleFileKind.BlockedIps or RuleFileKind.AllowedIps))
        {
            throw new ArgumentOutOfRangeException(
                nameof(kind), kind, "the IP codec handles only BlockedIps/AllowedIps");
        }

        Kind = kind;
    }

    public RuleFileKind Kind { get; }

    public RuleParseResult Parse(string? text)
    {
        var file = IpRuleFile.Parse(text);
        var whole = file.Serialize();
        return RuleRowProjection.Build(file.Lines, RuleRowProjection.SplitLines(whole), whole, file.Findings);
    }
}

/// <summary>Codec over the A3 cloaking_rules parser (<see cref="CloakRuleFile"/>).</summary>
public sealed class CloakRuleFamilyCodec : IRuleFamilyCodec
{
    public RuleFileKind Kind => RuleFileKind.Cloaking;

    public RuleParseResult Parse(string? text)
    {
        var file = CloakRuleFile.Parse(text);
        var whole = file.Serialize();
        return RuleRowProjection.Build(file.Lines, RuleRowProjection.SplitLines(whole), whole, file.Findings);
    }
}

/// <summary>Codec over the A4 forwarding_rules parser (<see cref="ForwardRuleFile"/>).</summary>
public sealed class ForwardRuleFamilyCodec : IRuleFamilyCodec
{
    public RuleFileKind Kind => RuleFileKind.Forwarding;

    public RuleParseResult Parse(string? text)
    {
        var file = ForwardRuleFile.Parse(text);
        var whole = file.Serialize();
        return RuleRowProjection.Build(file.Lines, RuleRowProjection.SplitLines(whole), whole, file.Findings);
    }
}
