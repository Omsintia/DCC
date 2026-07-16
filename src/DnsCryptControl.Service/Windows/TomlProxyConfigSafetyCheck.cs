using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Parses the active dnscrypt-proxy.toml (via <see cref="TomlConfigDocument"/> from DnsCryptControl.Core)
/// and returns Safe=true ONLY IF no <see cref="OpsecConcernSeverity.KillSwitchCritical"/> concern is
/// raised by <see cref="OpsecConfigRules.Evaluate"/> — the ONE place the OPSEC key rules live (IC-4),
/// shared with the helper write policy and the UI editor warnings so guard and editor never diverge:
/// <list type="number">
///   <item><c>netprobe_timeout == 0</c> — startup UDP/53 probe is disabled.</item>
///   <item><c>ignore_system_dns == true</c> — proxy never falls back to cleartext system DNS.</item>
///   <item>No <c>bootstrap_resolvers</c> entry ends in <c>:53</c> — no plaintext bootstrap. A present-but-
///   unreadable value (wrong type / mixed elements) fails CLOSED — a deliberate A3 tightening over the
///   pre-5b guard, which silently skipped it.</item>
/// </list>
/// ProtectionCritical/Advisory concerns (listen_addresses, netprobe_address) never gate enable.
/// A missing or unparseable config yields Safe=false (fail-closed: never enable the kill switch over
/// an unknown config). This is the production implementation of <see cref="IProxyConfigSafetyCheck"/>.
/// </summary>
internal sealed class TomlProxyConfigSafetyCheck : IProxyConfigSafetyCheck
{
    private readonly ProtectedPaths _paths;

    public TomlProxyConfigSafetyCheck(ProtectedPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        _paths = paths;
    }

    /// <inheritdoc/>
    public (bool Safe, string? Reason) IsSafeUnderPort53Block()
    {
        // Fail-closed: missing file.
        if (!File.Exists(_paths.ConfigFile))
            return (false, $"dnscrypt-proxy.toml not found at '{_paths.ConfigFile}'");

        TomlConfigDocument doc;
        try
        {
            var text = File.ReadAllText(_paths.ConfigFile);
            // TomlConfigDocument.Parse delegates to Tomlyn's SyntaxParser.Parse (non-strict variant),
            // which NEVER throws on malformed TOML — it always returns a DocumentSyntax with HasErrors=true
            // populated from diagnostics. Only ArgumentNullException (null text) is possible here, but
            // text is always non-null from File.ReadAllText. HasErrors is the sole parse-failure signal.
            doc = TomlConfigDocument.Parse(text);
        }
        catch (IOException ex)
        {
            return (false, $"failed to read/parse dnscrypt-proxy.toml: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            return (false, $"failed to read/parse dnscrypt-proxy.toml: {ex.Message}");
        }

        // Fail-closed: unparseable TOML (HasErrors is set by Tomlyn's SyntaxParser, never throws).
        if (doc.HasErrors)
            return (false, $"dnscrypt-proxy.toml has parse errors: {string.Join("; ", doc.Errors)}");

        // IC-4 delegation: the OPSEC key rules live ONLY in Core's OpsecConfigRules — the
        // same three checks as before, plus the documented A3 tightening (malformed
        // bootstrap_resolvers fails closed). The kill-switch enable gate rejects on the
        // FIRST KillSwitchCritical concern; ProtectionCritical (listen_addresses) and
        // Advisory (netprobe_address) concerns are the editor's business, never this gate's.
        foreach (var concern in OpsecConfigRules.Evaluate(doc))
        {
            if (concern.Severity == OpsecConcernSeverity.KillSwitchCritical)
                return (false, concern.Message);
        }

        return (true, null);
    }
}
