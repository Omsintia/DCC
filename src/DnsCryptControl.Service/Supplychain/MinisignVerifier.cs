using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace DnsCryptControl.Service.Supplychain;

/// <summary>Result of a minisign verification. Ok==true only when EVERY step (research §[2]
/// 6,7,8) passed. Never thrown — a bad signature is a value, not an exception (IC-12).</summary>
internal readonly record struct MinisignVerifyResult(bool Ok, MinisignVerifyError Error)
{
    internal static MinisignVerifyResult Fail(MinisignVerifyError e) => new(false, e);
    internal static MinisignVerifyResult Pass() => new(true, MinisignVerifyError.None);
}

/// <summary>Implements the research §[2] 9-step verification over BouncyCastle primitives.
/// Prehashed (ED) ONLY; constant-time key_id guard; MANDATORY global-signature; trusted-comment
/// downgrade policy. Pure: takes bytes + text, no I/O, no exceptions on bad input.</summary>
internal static class MinisignVerifier
{
    internal static MinisignVerifyResult Verify(byte[] fileBytes, string minisigText, MinisignPublicKey pinnedKey, string expectedAssetFileName)
    {
        ArgumentNullException.ThrowIfNull(fileBytes);
        ArgumentNullException.ThrowIfNull(pinnedKey);

        // Step 1: pinned key shape (defensive — Get() already validated the constant).
        if (pinnedKey.KeyId.Length != 8 || pinnedKey.PublicKey.Length != 32)
            return MinisignVerifyResult.Fail(MinisignVerifyError.BadPinnedKey);

        // Step 2: parse the 4-line signature.
        if (!MinisignFormat.TryParseSignature(minisigText, out var sig, out var parseError))
            return MinisignVerifyResult.Fail(parseError);

        // Step 4: constant-time key_id guard (anti-confusion fast-fail). [Step 3 = parsing, done.]
        if (!CryptographicOperations.FixedTimeEquals(sig.KeyId, pinnedKey.KeyId))
            return MinisignVerifyResult.Fail(MinisignVerifyError.KeyIdMismatch);

        // Step 5: algorithm policy — prehashed ED only; reject legacy Ed (IC-1).
        if (sig.SigAlgo.AsSpan().SequenceEqual(MinisignFormat.AlgoLegacy))
            return MinisignVerifyResult.Fail(MinisignVerifyError.LegacyModeRejected);
        if (!sig.SigAlgo.AsSpan().SequenceEqual(MinisignFormat.AlgoPrehashed))
            return MinisignVerifyResult.Fail(MinisignVerifyError.UnknownAlgorithm);

        // Step 6: message signature over BLAKE2b-512(file) as a plain Ed25519 message (IC-2).
        var digest = Blake2b512(fileBytes);
        if (!Ed25519Verify(pinnedKey.PublicKey, digest, sig.MessageSig))
            return MinisignVerifyResult.Fail(MinisignVerifyError.MessageSignatureInvalid);

        // Step 7: MANDATORY global/comment signature (pure Ed25519) over msg_sig || utf8(trusted_comment) (IC-4).
        var commentBytes = Encoding.UTF8.GetBytes(sig.TrustedCommentText);
        var globalInput = new byte[sig.MessageSig.Length + commentBytes.Length];
        Buffer.BlockCopy(sig.MessageSig, 0, globalInput, 0, sig.MessageSig.Length);
        Buffer.BlockCopy(commentBytes, 0, globalInput, sig.MessageSig.Length, commentBytes.Length);
        if (!Ed25519Verify(pinnedKey.PublicKey, globalInput, sig.GlobalSig))
            return MinisignVerifyResult.Fail(MinisignVerifyError.CommentSignatureInvalid);

        // Step 8: trusted-comment downgrade policy — assert file:<expectedAssetFileName> (IC-6).
        if (!TrustedCommentHasFile(sig.TrustedCommentText, expectedAssetFileName))
            return MinisignVerifyResult.Fail(MinisignVerifyError.AssetNameMismatch);

        // Step 9: accept.
        return MinisignVerifyResult.Pass();
    }

    private static byte[] Blake2b512(byte[] data)
    {
        var d = new Blake2bDigest(512); // size in BITS => 64-byte output
        d.BlockUpdate(data, 0, data.Length);
        var outBuf = new byte[64];
        d.DoFinal(outBuf, 0);
        return outBuf;
    }

    private static bool Ed25519Verify(byte[] pk32, byte[] message, byte[] sig64)
    {
        var pub = new Ed25519PublicKeyParameters(pk32, 0);
        var signer = new Ed25519Signer();
        signer.Init(forSigning: false, parameters: pub);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.VerifySignature(sig64);
    }

    private static bool TrustedCommentHasFile(string trustedComment, string expectedAssetFileName)
    {
        // Schema: timestamp:<unix>\tfile:<asset>\thashed  (tabs separate tokens).
        foreach (var token in trustedComment.Split('\t'))
        {
            if (token.StartsWith("file:", StringComparison.Ordinal))
                return string.Equals(token.AsSpan(5).ToString(), expectedAssetFileName, StringComparison.Ordinal);
        }
        return false;
    }
}
