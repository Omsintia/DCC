using CsCheck;
using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the <c>sdns://</c> stamp decoder - the first and most representative
/// untrusted-input parser (arbitrary attacker-controlled text arrives from downloaded
/// public-resolvers.md / relays.md and from stamps pasted into the config). The headline
/// invariant is TOTALITY: <see cref="ServerStampParser.TryParse"/> must NEVER throw on any input,
/// only ever returning a typed <c>StampParseError</c>. Deeper structural + canonical-round-trip +
/// differential-vs-Go oracles follow in sub-phases 6b/6c; see
/// the fuzzing design notes.
/// </summary>
public class ServerStampParserProperties
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void TryParse_never_throws_on_arbitrary_text() =>
        // Mostly non-stamp text: exercises the prefix / length / early-out guards.
        Gen.String.Sample(NeverThrows, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void TryParse_never_throws_on_sdns_prefixed_text() =>
        // Forces the strict base64url decode path with hostile bodies (padding, non-url alphabet).
        Gen.String.Select(s => "sdns://" + s).Sample(NeverThrows, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void TryParse_never_throws_on_wellformed_base64_bodies() =>
        // Valid base64url over random bytes reaches the protocol dispatch + the byte readers
        // (length-prefix / VLP continuation-bit arithmetic) - the code most likely to over-read
        // on hostile framing, and exactly what the totality oracle must prove safe.
        Gen.Byte.Array.Select(b => "sdns://" + Base64Url(b)).Sample(NeverThrows, iter: Fuzz.Iter);

    [Fact]
    public void TryParse_null_input_is_a_clean_false()
    {
        Assert.False(ServerStampParser.TryParse(null, out var stamp, out _));
        Assert.Null(stamp);
    }

    /// <summary>The totality oracle: calling <c>TryParse</c> must not throw for any input. A
    /// <c>false</c> return (rejected) is a valid, expected outcome for hostile input; when it instead
    /// ACCEPTS, the out stamp must be non-null (a real post-condition). The property fails only if the
    /// call throws, or accepts with a null stamp - CsCheck surfaces the shrunk reproducer either way.</summary>
    private static bool NeverThrows(string input) =>
        !ServerStampParser.TryParse(input, out var stamp, out _) || stamp is not null;

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
