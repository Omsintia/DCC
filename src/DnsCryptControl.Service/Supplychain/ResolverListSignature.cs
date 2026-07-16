using System;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace DnsCryptControl.Service.Supplychain;

/// <summary>
/// Minisign verification for RESOLVER-LIST caches ONLY (public-resolvers.md, odoh-*.md and their
/// detached .minisig files). The DNSCrypt list repo signs in minisign LEGACY mode ('Ed': Ed25519
/// over the RAW file bytes), which the Go proxy accepts for lists — so this verifier REQUIRES
/// legacy mode. It is deliberately separate from <see cref="MinisignVerifier"/>, whose
/// prehashed-only policy (IC-1) is scoped to release-binary verification and must stay strict.
/// Never use this class to verify a dnscrypt-proxy release binary.
/// Pure: bytes + text in, bool out; no I/O; never throws on bad input.
/// </summary>
internal static class ResolverListSignature
{
    /// <summary>The DNSCrypt project's resolver-list minisign public key. Single in-assembly home;
    /// the shipped dnscrypt-proxy.toml pins the SAME key as minisign_key (a drift-lock test asserts
    /// the two stay equal), so any cache the proxy itself downloaded and verified also verifies here.</summary>
    internal const string PinnedResolverListKeyBase64 = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

    /// <summary>Verifies <paramref name="fileBytes"/> against a detached legacy-mode minisign
    /// signature from the pinned resolver-list key, including the mandatory global/comment
    /// signature and the trusted-comment <c>file:<paramref name="expectedAssetFileName"/></c>
    /// assertion (downgrade/rename guard). False on ANY mismatch or malformed input.</summary>
    internal static bool VerifiesWithPinnedKey(byte[] fileBytes, string minisigText, string expectedAssetFileName)
    {
        ArgumentNullException.ThrowIfNull(fileBytes);
        if (fileBytes.Length == 0 || string.IsNullOrEmpty(minisigText)) return false;

        if (!MinisignFormat.TryDecodePublicKey(PinnedResolverListKeyBase64, out var keyId, out var publicKey, out _))
            return false;
        if (!MinisignFormat.TryParseSignature(minisigText, out var sig, out _))
            return false;

        // key_id anti-confusion guard: the signature must name the pinned key.
        if (!sig.KeyId.AsSpan().SequenceEqual(keyId)) return false;

        // Lists are legacy-signed: Ed25519 over the raw file bytes, no prehash.
        if (!sig.SigAlgo.AsSpan().SequenceEqual(MinisignFormat.AlgoLegacy)) return false;
        if (!Ed25519Verify(publicKey, fileBytes, sig.MessageSig)) return false;

        // Mandatory global/comment signature: Ed25519 over msg_sig || utf8(trusted_comment).
        var commentBytes = Encoding.UTF8.GetBytes(sig.TrustedCommentText);
        var globalInput = new byte[sig.MessageSig.Length + commentBytes.Length];
        Buffer.BlockCopy(sig.MessageSig, 0, globalInput, 0, sig.MessageSig.Length);
        Buffer.BlockCopy(commentBytes, 0, globalInput, sig.MessageSig.Length, commentBytes.Length);
        if (!Ed25519Verify(publicKey, globalInput, sig.GlobalSig)) return false;

        // The trusted comment must name the asset (schema: timestamp:<unix>\tfile:<asset>[\t...]).
        foreach (var token in sig.TrustedCommentText.Split('\t'))
        {
            if (token.StartsWith("file:", StringComparison.Ordinal))
                return string.Equals(token["file:".Length..], expectedAssetFileName, StringComparison.Ordinal);
        }
        return false;
    }

    private static bool Ed25519Verify(byte[] pk32, byte[] message, byte[] sig64)
    {
        try
        {
            var pub = new Ed25519PublicKeyParameters(pk32, 0);
            var signer = new Ed25519Signer();
            signer.Init(forSigning: false, parameters: pub);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(sig64);
        }
        catch (ArgumentException)
        {
            return false; // malformed key/signature material is a verification failure, not a crash
        }
    }
}
