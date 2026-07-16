using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DnsCryptControl.Core.Rules;

namespace DnsCryptControl.Fuzzing.Oracles;

/// <summary>
/// DIFFERENTIAL oracle (Phase 6b): our <see cref="NameRule.MatchesGlob"/> is a hand-port of Go's
/// <c>path/filepath.Match</c> (WINDOWS separator semantics), used to decide whether a block/cloak name
/// pattern matches a domain. A divergence would mean a rule that blocks in the app's view but not in the
/// proxy's (or vice-versa) - a silently-no-op filter = fail-open. Corpus/glob/oracle-vectors.jsonl froze the
/// reference verdict of <c>filepath.Match(pattern, name)</c> (built on Windows) for each pattern/name pair;
/// we assert our folded match (matched AND well-formed) equals it.
/// <para>
/// The corpus includes separator-bearing vectors (literal <c>\</c>, <c>?</c> not matching the <c>\</c>
/// separator, <c>/</c> NOT being a Windows separator) so a Unix-built oracle would produce a different corpus
/// and a mis-port of the Windows separator/escape rules would diverge - the platform axis this mode exists
/// for. One case is intentionally NOT asserted: a trailing <c>*</c> matching a name that contains a <c>\</c>
/// (e.g. <c>*</c> ~ <c>a\b</c>). Go's filepath.Match rejects it (<c>*</c> cannot cross a Separator) but
/// NameRule.MatchesGlob deliberately simplifies this (see NameRule.cs:270-271, :348-349) - safe because a DNS
/// name can never contain a <c>\</c>, so the case is unreachable in production filtering.
/// </para>
/// <para>
/// This differential asserts the folded MATCH; the per-(pattern,name) ErrBadPattern (<c>bad</c>) verdict is
/// asserted directly by the Core NameRuleTests (Classify_malformedGlob_isError and the name-dependent b*[
/// vs e*[ cases), so it is intentionally not re-asserted here.
/// </para>
/// See the fuzzing design notes.
/// </summary>
public class GlobDifferentialTests
{
    private sealed record GlobVector(string Pattern, string Name, bool Match, bool Bad);

    private static List<GlobVector> LoadVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Corpus", "glob", "oracle-vectors.jsonl");
        var vectors = new List<GlobVector>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            vectors.Add(new GlobVector(
                r.GetProperty("pattern").GetString() ?? "",
                r.GetProperty("name").GetString() ?? "",
                r.GetProperty("match").GetBoolean(),
                r.GetProperty("bad").GetBoolean()));
        }
        return vectors;
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void MatchesGlob_agrees_with_filepath_Match()
    {
        var vectors = LoadVectors();
        Assert.NotEmpty(vectors);

        var divergences = new List<string>();
        foreach (var v in vectors)
        {
            var cs = NameRule.MatchesGlob(v.Pattern, v.Name);
            if (cs != v.Match)
                divergences.Add($"'{v.Pattern}' ~ '{v.Name}': C#={cs} filepath.Match={v.Match} (bad={v.Bad})");
        }

        Assert.True(divergences.Count == 0,
            $"{divergences.Count} glob-match divergence(s) vs Go filepath.Match:{Environment.NewLine}" +
            string.Join(Environment.NewLine, divergences));
    }
}
