using System;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// Drift lock for the UI's own copy of the DNSCrypt resolver-list minisign key: the Add-ODoH flow
/// writes <c>ResolversViewModel.OdohMinisignKey</c> into the user's config as each odoh source's
/// minisign_key, and the SHIPPED packaging toml pins the same key for public-resolvers. If either
/// copy rotates without the other, the proxy rejects a seeded/bundled list against the stale key
/// and the source load goes FATAL. The shipped toml is the anchor both sides assert against
/// (the Service-side lock lives in ShippedConfigDriftLockTests).
/// </summary>
public sealed class OdohKeyDriftLockTests
{
    [Fact]
    public void ui_odoh_minisign_key_equals_the_shipped_toml_key()
    {
        // The constant is private by design (no public surface for a literal); reflection reads
        // the compile-time literal field so the lock needs no production API change.
        var field = typeof(ResolversViewModel).GetField(
            "OdohMinisignKey", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);
        var uiKey = Assert.IsType<string>(field!.GetRawConstantValue());

        var toml = ReadShippedToml();
        var m = Regex.Match(toml, @"minisign_key\s*=\s*'([^']+)'");
        Assert.True(m.Success, "shipped toml has no minisign_key");
        Assert.Equal(m.Groups[1].Value, uiKey);
    }

    private static string ReadShippedToml()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "DnsCryptControl.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        var path = Path.Combine(dir!.FullName, "tools", "packaging", "assets", "dnscrypt-proxy.toml");
        Assert.True(File.Exists(path), $"shipped toml not found at {path}");
        return File.ReadAllText(path);
    }
}
