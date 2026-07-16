namespace DnsCryptControl.Service.Supplychain;

/// <summary>Machine-readable reason a minisign verification was rejected. None == success.
/// Every value is a fail-closed REJECT; the verifier never throws on a bad signature.</summary>
public enum MinisignVerifyError
{
    None,
    MalformedSignature,
    MalformedKey,
    KeyIdMismatch,
    LegacyModeRejected,
    UnknownAlgorithm,
    MessageSignatureInvalid,
    CommentSignatureInvalid,
    AssetNameMismatch,
    BadPinnedKey,
}
