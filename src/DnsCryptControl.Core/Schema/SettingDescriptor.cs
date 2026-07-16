namespace DnsCryptControl.Core.Schema;

/// <summary>
/// Metadata for one dnscrypt-proxy.toml key: how to render, validate, and document it.
/// <see cref="Group"/> is the curated display group the Configuration tab's section nav
/// derives from — the group blocks are delimited by the comment banners in
/// <see cref="ConfigCatalog"/>, which are the source of truth for the grouping.
/// </summary>
/// <param name="Friendly">Optional plain-language second line rendered above the
/// technical <paramref name="Doc"/> — what the key means for a non-technical user,
/// in second person, ending with what they gain or risk. <paramref name="Doc"/>
/// stays the technical truth; <paramref name="Friendly"/> never replaces it.</param>
public sealed record SettingDescriptor(
    string KeyPath,
    string Section,
    SettingValueType Type,
    string DefaultDisplay,
    string Doc,
    string Group,
    bool Deprecated = false,
    string? ReplacedBy = null,
    string? Friendly = null);
