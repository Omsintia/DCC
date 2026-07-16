namespace DnsCryptControl.Service.Supplychain;

/// <summary>A decoded minisign public key: the 8-byte key_id (an anti-confusion hint) and the
/// 32-byte Ed25519 public key (the trust root). Decoded ONLY from a hardcoded constant — never
/// from a signature (research §[2] step 1, §[0]).</summary>
internal sealed record MinisignPublicKey(byte[] KeyId, byte[] PublicKey)
{
    internal static bool TryParse(string base64, out MinisignPublicKey key, out MinisignVerifyError error)
    {
        key = new MinisignPublicKey(System.Array.Empty<byte>(), System.Array.Empty<byte>());
        if (!MinisignFormat.TryDecodePublicKey(base64, out var keyId, out var pk, out error))
            return false;
        key = new MinisignPublicKey(keyId, pk);
        return true;
    }
}
