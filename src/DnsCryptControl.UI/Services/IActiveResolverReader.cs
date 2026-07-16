namespace DnsCryptControl.UI.Services;

/// <summary>
/// Best-effort reader of the currently-configured active resolver's display name, off
/// the on-disk <c>dnscrypt-proxy.toml</c> — purely informational (the Dashboard's
/// "connected to" line), never a source of protection truth.
/// </summary>
public interface IActiveResolverReader
{
    /// <summary>The first <c>server_names</c> entry, or <c>null</c> if the file is
    /// missing, empty, or fails to parse.</summary>
    string? ReadPrimaryName();
}
