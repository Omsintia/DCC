using DnsCryptControl.Service.Supplychain;
using Xunit;

namespace DnsCryptControl.Service.Tests.Supplychain;

public class MinisignFormatTests
{
    // Vector A (research §[3]) — PREHASHED 'ED', message "test".
    private const string VectorAMinisig =
        "untrusted comment: signature from minisign secret key\n" +
        "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n" +
        "trusted comment: timestamp:1556193335\tfile:test\n" +
        "y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n";

    private const string VectorAPubKey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

    [Fact]
    public void TryParseSignature_vectorA_decodesLayout()
    {
        var ok = MinisignFormat.TryParseSignature(VectorAMinisig, out var parsed, out var error);
        Assert.True(ok);
        Assert.Equal(MinisignVerifyError.None, error);
        Assert.Equal(new byte[] { 0x45, 0x44 }, parsed.SigAlgo);   // 'ED' (prehashed)
        Assert.Equal(8, parsed.KeyId.Length);
        Assert.Equal(64, parsed.MessageSig.Length);
        Assert.Equal(64, parsed.GlobalSig.Length);
        Assert.Equal("timestamp:1556193335\tfile:test", parsed.TrustedCommentText);
    }

    [Fact]
    public void TryParseSignature_crlf_isTolerated()
    {
        var crlf = VectorAMinisig.Replace("\n", "\r\n");
        Assert.True(MinisignFormat.TryParseSignature(crlf, out var parsed, out _));
        Assert.Equal("timestamp:1556193335\tfile:test", parsed.TrustedCommentText);
    }

    [Fact]
    public void TryParseSignature_missingTrustedCommentPrefix_fails()
    {
        var bad = VectorAMinisig.Replace("trusted comment: ", "comment: ");
        Assert.False(MinisignFormat.TryParseSignature(bad, out _, out var error));
        Assert.Equal(MinisignVerifyError.MalformedSignature, error);
    }

    [Fact]
    public void TryParseSignature_tooFewLines_fails()
    {
        Assert.False(MinisignFormat.TryParseSignature("only one line", out _, out var error));
        Assert.Equal(MinisignVerifyError.MalformedSignature, error);
    }

    [Fact]
    public void TryParseSignature_nonBase64Line2_fails()
    {
        var bad = VectorAMinisig.Replace(
            "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=",
            "!!!not base64!!!");
        Assert.False(MinisignFormat.TryParseSignature(bad, out _, out var error));
        Assert.Equal(MinisignVerifyError.MalformedSignature, error);
    }

    [Fact]
    public void TryDecodePublicKey_pinnedShape_decodes42Bytes()
    {
        var ok = MinisignFormat.TryDecodePublicKey(VectorAPubKey, out var keyId, out var pk, out var error);
        Assert.True(ok);
        Assert.Equal(MinisignVerifyError.None, error);
        Assert.Equal(8, keyId.Length);
        Assert.Equal(32, pk.Length);
    }

    [Fact]
    public void TryDecodePublicKey_wrongLength_fails()
    {
        Assert.False(MinisignFormat.TryDecodePublicKey("QUJD", out _, out _, out var error)); // "ABC" -> 3 bytes
        Assert.Equal(MinisignVerifyError.MalformedKey, error);
    }
}
