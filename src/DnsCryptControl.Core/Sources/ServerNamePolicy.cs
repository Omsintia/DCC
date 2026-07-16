namespace DnsCryptControl.Core.Sources;

/// <summary>
/// The single home of the IC-7 server/relay-name allowlist: a name is allowed exactly when it is
/// 1..<see cref="MaxNameLength"/> characters drawn from <c>[A-Za-z0-9._-]</c>. Both gates that
/// enforce IC-7 - <c>ResolverListParser.IsSelectableName</c> (which names may be written into
/// config) and <c>AnonymizedDnsRoutes.IsBareName</c> (route server_name/via entries) - delegate
/// here so the two copies can never drift apart.
/// </summary>
public static class ServerNamePolicy
{
    /// <summary>The longest name the allowlist accepts.</summary>
    public const int MaxNameLength = 64;

    /// <summary>
    /// True when <paramref name="name"/> is 1..<see cref="MaxNameLength"/> characters, each in
    /// <c>[A-Za-z0-9._-]</c>.
    /// </summary>
    public static bool IsAllowedName(string name) =>
        name.Length is > 0 and <= MaxNameLength && name.All(static c =>
            c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or '-');
}
