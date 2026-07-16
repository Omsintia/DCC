using System;

namespace DnsCryptControl.Service.Supplychain;

/// <summary>The decoded layout of a parsed .minisig (research §[0]). All byte arrays are
/// fixed-length and length-checked by the parser; TrustedCommentText has the 17-char
/// "trusted comment: " prefix stripped and no trailing newline.</summary>
internal readonly record struct ParsedSignature(
    byte[] SigAlgo, byte[] KeyId, byte[] MessageSig, byte[] GlobalSig, string TrustedCommentText);

/// <summary>Pure parsing/decoding of the minisign 4-line signature and the public-key string
/// (research §[0]). No crypto, no I/O. Fail-closed: returns false + an error code, never throws.</summary>
internal static class MinisignFormat
{
    private const string TrustedCommentPrefix = "trusted comment: "; // exactly 17 chars incl. trailing space
    internal static readonly byte[] AlgoPrehashed = { 0x45, 0x44 };  // 'E','D'
    internal static readonly byte[] AlgoLegacy = { 0x45, 0x64 };     // 'E','d'

    internal static bool TryParseSignature(string minisigText, out ParsedSignature parsed, out MinisignVerifyError error)
    {
        parsed = default;
        error = MinisignVerifyError.MalformedSignature;
        if (string.IsNullOrEmpty(minisigText)) return false;

        // LF-tolerant split; drop a trailing empty line. CRLF is normalised by stripping '\r'.
        var lines = minisigText.Replace("\r\n", "\n", StringComparison.Ordinal)
                               .Replace("\r", "\n", StringComparison.Ordinal)
                               .Split('\n');
        if (lines.Length < 4) return false;

        var line2 = lines[1];
        var line3 = lines[2];
        var line4 = lines[3];

        if (!line3.StartsWith(TrustedCommentPrefix, StringComparison.Ordinal)) return false;
        var trustedComment = line3.Substring(TrustedCommentPrefix.Length);

        if (!TryBase64(line2, out var sigBlob) || sigBlob.Length != 74) return false;
        if (!TryBase64(line4, out var globalSig) || globalSig.Length != 64) return false;

        var sigAlgo = sigBlob[..2];
        var keyId = sigBlob[2..10];
        var messageSig = sigBlob[10..74];

        parsed = new ParsedSignature(sigAlgo, keyId, messageSig, globalSig, trustedComment);
        error = MinisignVerifyError.None;
        return true;
    }

    internal static bool TryDecodePublicKey(string pubKeyBase64, out byte[] keyId, out byte[] publicKey, out MinisignVerifyError error)
    {
        keyId = Array.Empty<byte>();
        publicKey = Array.Empty<byte>();
        error = MinisignVerifyError.MalformedKey;
        if (string.IsNullOrEmpty(pubKeyBase64)) return false;
        if (!TryBase64(pubKeyBase64, out var blob) || blob.Length != 42) return false;

        // blob = sig_alg[2] || key_id[8] || ed25519_public_key[32]; the key's own algo tag is always 'Ed'.
        keyId = blob[2..10];
        publicKey = blob[10..42];
        error = MinisignVerifyError.None;
        return true;
    }

    private static bool TryBase64(string s, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(s.Trim());
            return true;
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }
}
