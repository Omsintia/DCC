using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DnsCryptControl.Core.Rules;

namespace DnsCryptControl.Fuzzing.Oracles;

/// <summary>
/// DIFFERENTIAL oracle (Phase 6b): our <see cref="RuleTextLines.StripInlineComment"/> reproduces
/// dnscrypt-proxy 2.1.16's per-line <c>TrimAndStripInlineComments</c> (vendored verbatim into the oracle's
/// internal/dcp package) - the pre-tokenisation every rule file (blocklist/allowlist/cloak/forward) shares.
/// The comment logic is quirky (only the LAST '#' matters; a leading '#' or a '#' preceded by space/tab cuts
/// the line, any other '#' is literal), so a divergence would silently mis-parse or drop a rule (a filter
/// that no-ops = fail-open). Corpus/rule/oracle-vectors.jsonl froze the reference content for each raw line;
/// we assert our stripped content equals it byte-for-byte. See
/// the fuzzing design notes.
/// </summary>
public class RuleTokenizerDifferentialTests
{
    private sealed record RuleVector(string In, string Content);

    private static List<RuleVector> LoadVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Corpus", "rule", "oracle-vectors.jsonl");
        var vectors = new List<RuleVector>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            vectors.Add(new RuleVector(
                r.GetProperty("in").GetString() ?? "",
                r.GetProperty("content").GetString() ?? ""));
        }
        return vectors;
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void StripInlineComment_agrees_with_TrimAndStripInlineComments()
    {
        var vectors = LoadVectors();
        Assert.NotEmpty(vectors);

        var divergences = new List<string>();
        foreach (var v in vectors)
        {
            var (content, _) = RuleTextLines.StripInlineComment(v.In);
            if (!string.Equals(content, v.Content, StringComparison.Ordinal))
                divergences.Add($"'{v.In}': C#='{content}' Go='{v.Content}'");
        }

        Assert.True(divergences.Count == 0,
            $"{divergences.Count} rule-tokenizer divergence(s) vs 2.1.16 TrimAndStripInlineComments:" +
            $"{Environment.NewLine}" + string.Join(Environment.NewLine, divergences));
    }
}
