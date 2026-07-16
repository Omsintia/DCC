using DnsCryptControl.Service.Supplychain;
using Xunit;

namespace DnsCryptControl.Service.Tests.Supplychain;

public class MinisignVerifierTests
{
    [Fact]
    public void PinnedReleaseKey_decodesToKeyId_e4d715ea71338379()
    {
        var key = PinnedReleaseKey.Get();
        Assert.Equal(8, key.KeyId.Length);
        Assert.Equal(32, key.PublicKey.Length);
        Assert.Equal("e4d715ea71338379", System.Convert.ToHexString(key.KeyId).ToLowerInvariant());
    }

    // ── research §[3] vectors (throwaway test key RWQf6…, message "test") ──────────────
    private const string VectorPubKey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    private static readonly byte[] TestMessage = System.Text.Encoding.ASCII.GetBytes("test");
    private static readonly byte[] TamperMessage = System.Text.Encoding.ASCII.GetBytes("Test"); // capital T

    // Vector A — PREHASHED 'ED', positive. sig line starts 'RUQ' => 0x45,0x44.
    private const string VectorA =
        "untrusted comment: signature from minisign secret key\n" +
        "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n" +
        "trusted comment: timestamp:1556193335\tfile:test\n" +
        "y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n";

    // Vector B — LEGACY 'Ed', positive-in-minisign. sig line starts 'RWQ' => 0x45,0x64.
    private const string VectorB =
        "untrusted comment: signature from minisign secret key\n" +
        "RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n" +
        "trusted comment: timestamp:1555779966\tfile:test\n" +
        "QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==\n";

    private static MinisignPublicKey Key()
    {
        Assert.True(MinisignPublicKey.TryParse(VectorPubKey, out var k, out _));
        return k;
    }

    [Fact]
    public void Verify_vectorA_prehashed_passes()
    {
        var r = MinisignVerifier.Verify(TestMessage, VectorA, Key(), expectedAssetFileName: "test");
        Assert.True(r.Ok);
        Assert.Equal(MinisignVerifyError.None, r.Error);
    }

    [Fact]
    public void Verify_vectorB_legacy_isRejectedByDowngradeGuard()
    {
        var r = MinisignVerifier.Verify(TestMessage, VectorB, Key(), expectedAssetFileName: "test");
        Assert.False(r.Ok);
        Assert.Equal(MinisignVerifyError.LegacyModeRejected, r.Error);
    }

    [Fact]
    public void Verify_vectorC_tamperedMessage_failsMessageSignature()
    {
        // Vector A's ED signature verified over the wrong bytes ("Test") must fail the message sig.
        var r = MinisignVerifier.Verify(TamperMessage, VectorA, Key(), expectedAssetFileName: "test");
        Assert.False(r.Ok);
        Assert.Equal(MinisignVerifyError.MessageSignatureInvalid, r.Error);
    }

    [Fact]
    public void Verify_keyIdMismatch_failsBeforeCrypto()
    {
        // The pinned RELEASE key (RWTk1…) has a different key_id than vector A's signature.
        var r = MinisignVerifier.Verify(TestMessage, VectorA, PinnedReleaseKey.Get(), expectedAssetFileName: "test");
        Assert.False(r.Ok);
        Assert.Equal(MinisignVerifyError.KeyIdMismatch, r.Error);
    }

    [Fact]
    public void Verify_mutatedTrustedComment_failsCommentSignature()
    {
        var mutated = VectorA.Replace("file:test", "file:evil");
        var r = MinisignVerifier.Verify(TestMessage, mutated, Key(), expectedAssetFileName: "evil");
        Assert.False(r.Ok);
        Assert.Equal(MinisignVerifyError.CommentSignatureInvalid, r.Error);
    }

    [Fact]
    public void Verify_assetNameMismatch_failsDowngradePolicy()
    {
        // Signatures valid, but the caller expected a different asset name than the (authenticated) file: token.
        var r = MinisignVerifier.Verify(TestMessage, VectorA, Key(), expectedAssetFileName: "dnscrypt-proxy-win64-9.9.9.zip");
        Assert.False(r.Ok);
        Assert.Equal(MinisignVerifyError.AssetNameMismatch, r.Error);
    }
}
