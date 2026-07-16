using CsCheck;
using DnsCryptControl.Service.Supplychain;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for the minisign supply-chain verifier - the gate that decides whether a
/// downloaded dnscrypt-proxy binary runs as LocalSystem. A single fail-open (accepting a signature the real
/// minisign would reject) installs an attacker binary with SYSTEM privilege. Oracles: the parser and the
/// verifier NEVER throw on hostile input (only typed Fail results); an ACCEPTED parse carries exactly the
/// mandated fixed field lengths; and Verify NEVER returns Ok for fuzzed input (forging a valid Ed25519
/// signature over a BLAKE2b digest by fuzzing is infeasible). Full crypto-differential vs reference minisign
/// is sub-phase 6b. See the fuzzing design notes.
/// </summary>
public class MinisignProperties
{
    private const string ExpectedAsset = "dnscrypt-proxy-win64-2.1.16.zip";
    private static readonly MinisignPublicKey PinnedKey = new(new byte[8], new byte[32]);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void TryParseSignature_never_throws_and_accepts_only_correctly_sized_fields() =>
        Gen.String.Sample(text =>
        {
            // Never-throws for any text; on ACCEPT every field is EXACTLY the mandated length (a stamp that
            // parsed with a short/long key or signature would be a confusion bug or a DoS in the verifier).
            if (!MinisignFormat.TryParseSignature(text, out var sig, out _))
            {
                return true;
            }

            return sig.SigAlgo.Length == 2 && sig.KeyId.Length == 8
                && sig.MessageSig.Length == 64 && sig.GlobalSig.Length == 64;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void TryDecodePublicKey_never_throws_and_accepts_only_42_byte_blobs() =>
        Gen.String.Sample(text =>
        {
            if (!MinisignFormat.TryDecodePublicKey(text, out var keyId, out var publicKey, out _))
            {
                return true;
            }

            return keyId.Length == 8 && publicKey.Length == 32;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Verify_never_throws_and_never_accepts_fuzzed_input() =>
        Gen.Select(Gen.Byte.Array, Gen.String, (file, sigText) => (file, sigText)).Sample(pair =>
        {
            // Fail-closed: no fuzzed (fileBytes, signature) can produce Ok - there is no reachable valid
            // Ed25519 signature over BLAKE2b-512(file) for the pinned key. A throw would fail the property.
            var result = MinisignVerifier.Verify(pair.file, pair.sigText, PinnedKey, ExpectedAsset);
            return !result.Ok;
        }, iter: Fuzz.Iter);

    [Theory]
    [InlineData("")]                                                       // empty
    [InlineData("not a signature")]                                        // single line
    [InlineData("untrusted comment: x\nAAAA\ntrusted comment: y\nBBBB")]   // wrong base64 lengths
    [InlineData("a\nb\nc\nd")]                                             // 4 lines, no trusted-comment prefix
    public void TryParseSignature_rejects_malformed(string text) =>
        Assert.False(MinisignFormat.TryParseSignature(text, out _, out _));
}
