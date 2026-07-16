namespace DnsCryptControl.Service.Supplychain;

/// <summary>The PINNED dnscrypt-proxy RELEASE-BINARY minisign public key (master spec §6,
/// research §[0]). key_id e4d715ea71338379. DISTINCT from the resolver-LISTS key RWQf6… which
/// must NEVER verify a binary. Hardcoded — the trust root is THIS key, not TLS.</summary>
internal static class PinnedReleaseKey
{
    internal const string Base64 = "RWTk1xXqcTODeYttYMCMLo0YJHaFEHn7a3akqHlb/7QvIQXHVPxKbjB5";

    internal static MinisignPublicKey Get() =>
        MinisignPublicKey.TryParse(Base64, out var key, out _)
            ? key
            : throw new System.InvalidOperationException("Pinned release key is malformed (build-time constant bug).");
}
