using System;
using System.IO;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// H (Phase 5f): offline-by-construction. The BannedApi analyzer file (BannedSymbols.txt, wired via
/// Directory.Build.props with RS0030 at error level under TreatWarningsAsErrors) forbids every HTTP
/// client type, so no outbound HTTP can compile into the app — the build fails if one is ever added.
/// This test pins each banned type INDIVIDUALLY so a substring that already passes can't give a false
/// "offline proven".
/// </summary>
public sealed class OfflineByConstructionTests
{
    [Theory]
    [InlineData("T:System.Net.Http.HttpClient")]
    [InlineData("T:System.Net.WebClient")]
    [InlineData("T:System.Net.Http.SocketsHttpHandler")]
    [InlineData("T:System.Net.WebRequest")]
    public void BannedSymbols_bans_every_http_client_type(string bannedType)
    {
        var banned = File.ReadAllText(FindRepoFile("BannedSymbols.txt"));

        // Each ban entry is "T:Fully.Qualified.Type;justification" — assert the exact "T:...;" head so a
        // near-miss (or a comment mentioning the type) cannot satisfy the check.
        Assert.Contains(bannedType + ";", banned);
    }

    private static string FindRepoFile(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException($"could not locate {fileName} walking up from {AppContext.BaseDirectory}");
    }
}
