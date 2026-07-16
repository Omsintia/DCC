using System;
using System.IO;
using DnsCryptControl.Core.Toml;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Best-effort reader of the first configured <c>server_names</c> entry from the
/// on-disk <c>dnscrypt-proxy.toml</c>, via Core's <see cref="TomlConfigDocument"/> —
/// purely informational (the Dashboard's active-resolver display name), never a source
/// of protection truth. Fails closed to <c>null</c> on any missing file, empty array,
/// or parse error — this reader must never throw.
/// </summary>
public sealed class ActiveResolverReader : IActiveResolverReader
{
    private readonly string _configFilePath;

    /// <param name="configFilePath">Defaults to <see cref="UiPaths.ConfigFile"/> (the real
    /// <c>%ProgramData%</c> path). Tests inject a temp file path.</param>
    public ActiveResolverReader(string? configFilePath = null)
    {
        _configFilePath = configFilePath ?? UiPaths.ConfigFile;
    }

    public string? ReadPrimaryName()
    {
        try
        {
            if (!File.Exists(_configFilePath))
            {
                return null;
            }

            // A pathologically large config would balloon this reader's memory (StreamReader growing a
            // multi-GB string) — fail closed to null, exactly like a parse error, rather than read it.
            if (ConfigReadGuard.IsOversized(_configFilePath, out _))
            {
                return null;
            }

            var text = File.ReadAllText(_configFilePath);
            var document = TomlConfigDocument.Parse(text);
            if (document.HasErrors)
            {
                return null;
            }

            if (!document.TryGetStringArray("server_names", out var names) || names.Count == 0)
            {
                return null;
            }

            return names[0];
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }
}
