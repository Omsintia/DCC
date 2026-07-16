using System.Text;
using DnsCryptControl.FuzzTargets;

namespace DnsCryptControl.Fuzzing.Oracles;

/// <summary>
/// The Phase 6c offline crash-REPLAY guard - the durable, CI-safe half of coverage-guided fuzzing.
///
/// The live SharpFuzz + libfuzzer-dotnet run (tools/fuzz-harnesses/run-fuzz.ps1) is a DEV/nightly discovery
/// tool: it needs instrumentation + a native driver and never runs in CI. Its output is committed corpus
/// files under Corpus/&lt;target&gt;/crashes/. This theory re-feeds every committed corpus input (seeds AND
/// captured crashes) through the SAME <see cref="FuzzDecoders"/> invariants the harness drives - but with NO
/// instrumentation and NO driver - so it rides the normal `dotnet test`. A coverage-guided find therefore
/// becomes a permanent regression: once a crash is captured + committed, this test fails until the underlying
/// totality/post-condition break is fixed, then guards it forever.
///
/// Reachability note: the harness (and this replay) feed bytes decoded as UTF-8, matching the app's real
/// file/download input path. Ill-formed byte sequences are sanitized to U+FFFD by that decode, so the full
/// UTF-16 string space (e.g. lone surrogates like the 6a `\uD800` Parse crash) is intentionally out of scope
/// here - that space is covered by the 6a CsCheck properties, which fuzz the string API directly.
/// </summary>
public class CrashCorpusReplayTests
{
    /// <summary>Enumerates one row per committed corpus FILE (a target's seeds.txt, any seeds/* raw file, and
    /// any crashes/* captured artifact), so a failure names the exact file. Yields a sentinel when the corpus
    /// is empty so the theory is never data-less.</summary>
    public static IEnumerable<object[]> CorpusFiles()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "Corpus");
        var yielded = false;
        foreach (var target in FuzzDecoders.All)
        {
            var targetDir = Path.Combine(root, target);
            if (!Directory.Exists(targetDir))
            {
                continue;
            }

            var seedsTxt = Path.Combine(targetDir, "seeds.txt");
            if (File.Exists(seedsTxt))
            {
                yielded = true;
                yield return new object[] { target, seedsTxt };
            }

            foreach (var sub in new[] { "seeds", "crashes" })
            {
                var dir = Path.Combine(targetDir, sub);
                if (!Directory.Exists(dir))
                {
                    continue;
                }

                foreach (var file in Directory.EnumerateFiles(dir))
                {
                    if (Path.GetFileName(file).StartsWith('.'))
                    {
                        continue; // .gitkeep and friends
                    }

                    yielded = true;
                    yield return new object[] { target, file };
                }
            }
        }

        if (!yielded)
        {
            yield return new object[] { string.Empty, string.Empty };
        }
    }

    /// <summary>Every committed corpus input for every target is handled by the decoder without throwing.
    /// A seeds.txt file is replayed line-by-line as UTF-8 bytes (matching the 6b seed convention); every other
    /// file is replayed as its raw bytes (matching what libFuzzer captured).</summary>
    [Theory]
    [Trait("Category", "Fuzz")]
    [MemberData(nameof(CorpusFiles))]
    public void Committed_corpus_input_is_handled_without_throwing(string target, string path)
    {
        if (target.Length == 0)
        {
            return; // sentinel: no corpus committed yet - nothing to replay
        }

        if (string.Equals(Path.GetFileName(path), "seeds.txt", StringComparison.Ordinal))
        {
            var lineNo = 0;
            foreach (var line in File.ReadLines(path))
            {
                lineNo++;
                if (line.Length == 0)
                {
                    continue;
                }

                var ex = Record.Exception(() => FuzzDecoders.Invoke(target, Encoding.UTF8.GetBytes(line)));
                Assert.True(ex is null,
                    $"[{target}] seeds.txt line {lineNo} threw {ex?.GetType().Name}: {ex?.Message}");
            }

            return;
        }

        var bytes = File.ReadAllBytes(path);
        var crashEx = Record.Exception(() => FuzzDecoders.Invoke(target, bytes));
        Assert.True(crashEx is null,
            $"[{target}] captured input '{Path.GetFileName(path)}' still throws {crashEx?.GetType().Name}: {crashEx?.Message}");
    }
}
