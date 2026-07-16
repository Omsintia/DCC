using System.Text;
using DnsCryptControl.Core.QueryLog;
using DnsCryptControl.Core.Rules;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Ipc.Transport;
using DnsCryptControl.Service.Supplychain;

namespace DnsCryptControl.FuzzTargets;

/// <summary>
/// The Phase 6c fuzz-target invariants - the SINGLE source of truth shared by the coverage-guided
/// discovery harness (tools/fuzz-harnesses/DnsCryptControl.SharpFuzz, driven by libfuzzer-dotnet) and the
/// offline crash-REPLAY theory (tests/DnsCryptControl.Fuzzing/Oracles/CrashCorpusReplayTests). Each target
/// decodes untrusted bytes and exercises exactly one trust-boundary decoder; the ONLY ways it fails are an
/// unexpected throw (a TOTALITY break) or a thrown <see cref="FuzzInvariantException"/> (a post-condition
/// break). libFuzzer captures + minimizes either; the replay theory re-feeds the captured bytes with no
/// instrumentation. Because both call THIS code, the fuzzer and the regression can never test different
/// contracts. See the fuzzing design notes.
/// </summary>
public static class FuzzDecoders
{
    /// <summary>The target names (kept in sync with <see cref="Invoke"/> and the run-fuzz.ps1 matrix).</summary>
    public static readonly IReadOnlyList<string> All =
        new[] { "stamp", "toml", "resolver-list", "querylog", "rule", "minisign", "framing" };

    /// <summary>Runs one target over the given input bytes. Returns normally on a clean (rejected or accepted)
    /// outcome; throws only when the decoder itself throws (totality break) or an invariant is violated.</summary>
    public static void Invoke(string target, ReadOnlySpan<byte> data)
    {
        switch (target)
        {
            case "stamp": Stamp(data); break;
            case "toml": Toml(data); break;
            case "resolver-list": ResolverList(data); break;
            case "querylog": QueryLog(data); break;
            case "rule": Rule(data); break;
            case "minisign": Minisign(data); break;
            case "framing": Framing(data); break;
            default: throw new ArgumentOutOfRangeException(nameof(target), target, "unknown fuzz target");
        }
    }

    /// <summary>sdns:// decoder - arbitrary attacker text from downloaded resolver lists + pasted config.
    /// Totality; and an ACCEPT must yield a non-null stamp.</summary>
    private static void Stamp(ReadOnlySpan<byte> data)
    {
        string input = Encoding.UTF8.GetString(data);
        if (ServerStampParser.TryParse(input, out var stamp, out _) && stamp is null)
            throw new FuzzInvariantException("stamp: TryParse accepted but produced a null stamp");
        // Composite (relay|server) shares the byte readers. Weak, safe post-condition: an accept must
        // yield at least one stamp (never claim success while producing neither).
        if (ServerStampParser.TryParseComposite(input, out var relay, out var server, out _)
            && relay is null && server is null)
            throw new FuzzInvariantException("stamp: TryParseComposite accepted but produced neither relay nor server");
    }

    /// <summary>The app's own TOML config byte-path - home of the fixed <c>\uD800</c> Parse-totality crash and
    /// the 2.26 GB encoding-amplification class. Parse + ToText + re-Parse must all be total (a fixed-point
    /// totality check: emitting text we then cannot re-read would be a round-trip defect).</summary>
    private static void Toml(ReadOnlySpan<byte> data)
    {
        string input = Encoding.UTF8.GetString(data);
        var doc = TomlConfigDocument.Parse(input);
        TomlConfigDocument.Parse(doc.ToText());
    }

    /// <summary>Downloaded public-resolvers.md / relays.md markdown. Totality (typed result, never a throw).</summary>
    private static void ResolverList(ReadOnlySpan<byte> data) =>
        ResolverListParser.Parse(Encoding.UTF8.GetString(data), prefix: "");

    /// <summary>The proxy's TSV query-log lines (arbitrary resolved hostnames). Per-line + whole-buffer totality.</summary>
    private static void QueryLog(ReadOnlySpan<byte> data)
    {
        string input = Encoding.UTF8.GetString(data);
        QueryLogParser.ParseLine(input);
        QueryLogParser.ParseLines(input);
    }

    /// <summary>The four dnscrypt rule-file grammars + the Go <c>filepath.Match</c> glob port. The glob input is
    /// split on the first NUL into (pattern, name); the matcher must TERMINATE (libFuzzer's per-input -timeout is
    /// the backtracking backstop) and never throw.</summary>
    private static void Rule(ReadOnlySpan<byte> data)
    {
        string input = Encoding.UTF8.GetString(data);
        CloakRuleFile.Parse(input);
        ForwardRuleFile.Parse(input);
        IpRuleFile.Parse(input);
        NameRuleFile.Parse(input);
        int nul = input.IndexOf('\0');
        string pattern = nul >= 0 ? input[..nul] : input;
        string name = nul >= 0 ? input[(nul + 1)..] : "example.com";
        NameRule.MatchesGlob(pattern, name);
    }

    // The minisign supply-chain gate decides whether a downloaded dnscrypt-proxy binary runs as LocalSystem.
    // We fuzz the signature TEXT against a fixed payload + the pinned (all-zero) key: Verify must NEVER throw
    // and NEVER return Ok (no reachable Ed25519 signature over BLAKE2b-512(payload) for that key), so any Ok is
    // a catastrophic fail-open.
    private const string ExpectedAsset = "dnscrypt-proxy-win64-2.1.16.zip";
    private static readonly byte[] MinisignPayload = Encoding.UTF8.GetBytes("dnscrypt-proxy 6c fuzz fixture payload");

    /// <summary>Fail-closed supply-chain verifier: never throws, never accepts a fuzzed signature.
    /// The pinned key is constructed HERE (not in a static field): under the SharpFuzz harness the
    /// MinisignPublicKey ctor lives in the instrumented Service.dll, and running instrumented code at
    /// type-initialization - before Fuzzer.LibFuzzer.Run wires up the coverage trace buffer - dereferences a
    /// not-yet-allocated buffer (NRE). Building it inside the fuzz-loop body avoids that ordering trap.</summary>
    private static void Minisign(ReadOnlySpan<byte> data)
    {
        var key = new MinisignPublicKey(new byte[8], new byte[32]);
        string sigText = Encoding.UTF8.GetString(data);
        if (MinisignVerifier.Verify(MinisignPayload, sigText, key, ExpectedAsset).Ok)
            throw new FuzzInvariantException("minisign: Verify returned Ok for a fuzzed signature (fail-open!)");
    }

    /// <summary>The LocalSystem IPC wire boundary. ReadFrameAsync reads a length-prefixed frame from a stream of
    /// the mutated bytes; it must never throw (null on malformed), never allocate an oversized body, and never
    /// hang past -timeout.</summary>
    private static void Framing(ReadOnlySpan<byte> data)
    {
        using var ms = new MemoryStream(data.ToArray());
        IpcFraming.ReadFrameAsync(ms, CancellationToken.None).GetAwaiter().GetResult();
    }
}

/// <summary>Thrown to signal a decoder post-condition violation - surfaces to libFuzzer as a crash so the
/// offending input is captured + minimized, and fails the replay theory offline, exactly like an unexpected
/// framework exception.</summary>
public sealed class FuzzInvariantException : Exception
{
    public FuzzInvariantException() { }
    public FuzzInvariantException(string message) : base(message) { }
    public FuzzInvariantException(string message, Exception innerException) : base(message, innerException) { }
}
