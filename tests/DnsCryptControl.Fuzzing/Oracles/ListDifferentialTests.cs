using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using DnsCryptControl.Core.Sources;

namespace DnsCryptControl.Fuzzing.Oracles;

/// <summary>
/// DIFFERENTIAL oracle (Phase 6b): our <see cref="ResolverListParser.Parse"/> reads the v2 markdown resolver
/// list (public-resolvers.md / relays.md) exactly as dnscrypt-proxy 2.1.16's <c>(*Source).parseV2</c> does
/// (that function is adapted into the oracle's internal/dcp package - Source/dlog plumbing stripped, the
/// non-deterministic stamp shuffle dropped, every parsing decision byte-for-byte the reference). A divergence
/// would mean the app registers a different set of resolvers / names / stamps than the proxy actually loads.
/// Corpus/list/oracle-vectors.jsonl froze the reference entries per (base64-encoded) list.
/// <para>
/// parseV2 emits an entry only for a block with at least one stamp parseable by go-dnsstamps; our parser
/// marks HasUsableStamp only for a block with at least one stamp parseable by the STRICTER ServerStampParser.
/// So the comparison aligns by name: the safety-critical direction is that a block C# would register (usable)
/// must also be a parseV2 entry (else C# accepted a stamp the reference rejected = fail-open); a parseV2 entry
/// whose C# counterpart is non-usable is documented STAMP-level hardening (counted, not failed - stamp
/// faithfulness is StampDifferentialTests' job). Descriptions are compared only when the reference text is
/// clean+within-cap, since C# sanitizes/caps them (a deliberate display-hardening difference, not a bug).
/// Only well-formed lists (Ok=true, no format abort) are compared - our parser deliberately continues past a
/// malformed block where the proxy aborts. See the fuzzing design notes.
/// </para>
/// </summary>
public class ListDifferentialTests
{
    private sealed record ListEntry(string Name, string Description, IReadOnlyList<string> Stamps);
    private sealed record ListVector(string InB64, bool Ok, List<ListEntry> Entries);

    private static List<ListVector> LoadVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Corpus", "list", "oracle-vectors.jsonl");
        var vectors = new List<ListVector>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            var entries = new List<ListEntry>();
            foreach (var e in r.GetProperty("entries").EnumerateArray())
            {
                var stamps = e.TryGetProperty("stamps", out var s) && s.ValueKind == JsonValueKind.Array
                    ? s.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
                    : new List<string>();
                entries.Add(new ListEntry(
                    e.GetProperty("name").GetString() ?? "",
                    e.GetProperty("description").GetString() ?? "",
                    stamps));
            }
            vectors.Add(new ListVector(r.GetProperty("in_b64").GetString() ?? "",
                r.GetProperty("ok").GetBoolean(), entries));
        }
        return vectors;
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ResolverListParser_agrees_with_parseV2()
    {
        var vectors = LoadVectors();
        Assert.NotEmpty(vectors);

        var divergences = new List<string>();
        int comparedLists = 0, hardeningEntries = 0;

        foreach (var v in vectors)
        {
            if (!v.Ok) continue; // format abort: our lenient parser continues where the proxy stops
            comparedLists++;

            var text = Encoding.UTF8.GetString(Convert.FromBase64String(v.InB64));
            var result = ResolverListParser.Parse(text, "");
            // Both parsers split the SAME "## " blocks; align by name (real lists have unique names, so a
            // later duplicate simply wins).
            var csByName = result.Entries.GroupBy(e => e.Name, StringComparer.Ordinal)
                                         .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);
            var goNames = new HashSet<string>(v.Entries.Select(e => e.Name), StringComparer.Ordinal);

            foreach (var g in v.Entries)
            {
                if (!csByName.TryGetValue(g.Name, out var c))
                {
                    divergences.Add($"block '{g.Name}' parsed by parseV2 but absent from C# entries");
                    continue;
                }
                if (!c.HasUsableStamp)
                {
                    // C# rejected EVERY stamp go-dnsstamps accepted for this block = documented hardening
                    // (31-byte pubkey, non-canonical base64url/IP, non-UTF8/control provider). Stamp-level
                    // faithfulness is StampDifferentialTests' job; here it is a hardening entry, not a fail.
                    hardeningEntries++;
                    continue;
                }
                if (!c.StampStrings.SequenceEqual(g.Stamps, StringComparer.Ordinal))
                    divergences.Add($"stamps[{g.Name}] C#=[{string.Join(",", c.StampStrings)}] Go=[{string.Join(",", g.Stamps)}]");
                if (IsDescriptionComparable(g.Description) && !string.Equals(c.Description, g.Description, StringComparison.Ordinal))
                    divergences.Add($"desc[{g.Name}] C#='{c.Description}' Go='{g.Description}'");
            }

            // Fail-open direction: a block C# would register (usable) that parseV2 did NOT emit means C#
            // accepted a stamp the reference rejected - the dangerous case.
            foreach (var c in result.Entries.Where(e => e.HasUsableStamp))
                if (!goNames.Contains(c.Name))
                    divergences.Add($"FAIL-OPEN: C# registered '{c.Name}' but parseV2 did not");
        }

        Assert.True(divergences.Count == 0,
            $"{divergences.Count} resolver-list divergence(s) vs 2.1.16 parseV2 (compared {comparedLists} lists, " +
            $"{hardeningEntries} hardening entries):{Environment.NewLine}" + string.Join(Environment.NewLine, divergences));
    }

    // C#'s ResolverListParser sanitizes the description (strips control chars EXCEPT newline/tab, plus Unicode
    // Format/bidi/zero-width and the line/paragraph separators) and caps it at MaxDescriptionChars; the Go
    // reference stores it raw. The two agree only when the reference text is already clean and within the cap
    // - compare only then, so a deliberate display-hardening difference is never a false failure.
    private static bool IsDescriptionComparable(string desc)
    {
        if (desc.Length > ResolverListParser.MaxDescriptionChars) return false;
        foreach (var ch in desc)
        {
            if (ch is '\n' or '\t') continue;      // preserved by both
            if (char.IsControl(ch)) return false;  // C0/C1 control, stripped by C#
            // Cf (bidi / zero-width) + Zl (U+2028) + Zp (U+2029) are all stripped by C#'s Sanitize.
            var cat = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (cat is UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
                return false;
        }
        return true;
    }
}
