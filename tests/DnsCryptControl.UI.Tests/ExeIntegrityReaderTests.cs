using System.IO;
using System.Text;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>D: <see cref="ExeIntegrityReader"/> — offline path/version/SHA-256, fail-closed, display-only (no pin).
/// Version comes from the sibling <c>state\installed-binary.json</c> tag (the UI cannot execute the ACL-protected
/// proxy, and the Go binary has no PE VERSIONINFO).</summary>
public sealed class ExeIntegrityReaderTests
{
    [Fact]
    public void ComputeSha256_matchesKnownVector()
    {
        var path = Path.Combine(Path.GetTempPath(), "exeint-" + Path.GetRandomFileName());
        try
        {
            File.WriteAllBytes(path, Encoding.ASCII.GetBytes("abc"));

            var info = new ExeIntegrityReader().Read(path);

            // SHA-256("abc") — the canonical NIST vector, lowercase hex.
            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", info.Sha256Hex);
        }
        finally { TryDelete(path); }
    }

    [Fact]
    public void Read_existingFile_returnsPathAndHashAndExists()
    {
        var path = Path.Combine(Path.GetTempPath(), "exeint-" + Path.GetRandomFileName());
        try
        {
            File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4 });

            var info = new ExeIntegrityReader().Read(path);

            Assert.True(info.Exists);
            Assert.Equal(path, info.Path);
            Assert.NotNull(info.Sha256Hex);
        }
        finally { TryDelete(path); }
    }

    [Fact]
    public void Read_missingFile_returnsNotExistsAndNullHash_neverThrows()
    {
        var info = new ExeIntegrityReader().Read(
            Path.Combine(Path.GetTempPath(), "nope-" + Path.GetRandomFileName()));

        Assert.False(info.Exists);
        Assert.Null(info.Sha256Hex);
    }

    // ---- version = the installer-pinned tag from the sibling state\installed-binary.json ----

    [Fact]
    public void Read_pinnedTagRecord_readsTagAsVersion()
    {
        var dir = NewTempDir();
        try
        {
            var exe = WriteDummyExe(dir);
            WriteRecord(dir, "{ \"sha256Hex\": \"abc\", \"tag\": \"2.1.16\", \"installedUtc\": \"x\" }");

            var info = new ExeIntegrityReader().Read(exe);

            Assert.Equal("2.1.16", info.FileVersion);
            Assert.NotNull(info.Sha256Hex);
        }
        finally { TryDeleteDir(dir); }
    }

    [Fact]
    public void Read_noRecord_versionNull()
    {
        var dir = NewTempDir();
        try
        {
            var exe = WriteDummyExe(dir); // no state\installed-binary.json alongside it

            var info = new ExeIntegrityReader().Read(exe);

            Assert.Null(info.FileVersion);
            Assert.True(info.Exists);
        }
        finally { TryDeleteDir(dir); }
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("{ \"sha256Hex\": \"abc\" }")]        // no tag key
    [InlineData("{ \"tag\": \"has/slash:bad\" }")]    // tag present but not version-ish
    [InlineData("{ \"tag\": 12345 }")]                // tag not a string
    [InlineData("{ \"tag\": \"\" }")]                 // empty tag
    public void Read_badRecord_versionNull(string recordJson)
    {
        var dir = NewTempDir();
        try
        {
            var exe = WriteDummyExe(dir);
            WriteRecord(dir, recordJson);

            var info = new ExeIntegrityReader().Read(exe);

            Assert.Null(info.FileVersion);
        }
        finally { TryDeleteDir(dir); }
    }

    // ---- SanitizeVersion (used to validate the tag) ----

    [Theory]
    [InlineData("2.1.16", "2.1.16")]
    [InlineData("2.1.16\n", "2.1.16")]                  // trailing newline tolerated
    [InlineData("dnscrypt-proxy 2.1.16", "dnscrypt-proxy 2.1.16")] // spaces allowed
    public void SanitizeVersion_returnsTheVersionLine(string raw, string expected)
    {
        Assert.Equal(expected, ExeIntegrityReader.SanitizeVersion(raw));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \r\n  ")]
    [InlineData("has/slash:and*stuff")]  // punctuation outside the whitelist -> rejected
    [InlineData("no-digits-here")]       // no digit -> not version-ish
    public void SanitizeVersion_rejectsEmptyOrHostile(string? raw)
    {
        Assert.Null(ExeIntegrityReader.SanitizeVersion(raw));
    }

    [Fact]
    public void SanitizeVersion_capsRunawayLength()
    {
        var v = ExeIntegrityReader.SanitizeVersion(new string('9', 500));
        Assert.NotNull(v);
        Assert.Equal(48, v!.Length);
    }

    // ---- helpers ----

    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "exeint-" + Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string WriteDummyExe(string dir)
    {
        var exe = Path.Combine(dir, "dnscrypt-proxy.exe");
        File.WriteAllBytes(exe, new byte[] { 1, 2, 3, 4 }); // not a real PE -> PE version empty
        return exe;
    }

    private static void WriteRecord(string dir, string json)
    {
        var state = Path.Combine(dir, "state");
        Directory.CreateDirectory(state);
        File.WriteAllText(Path.Combine(state, "installed-binary.json"), json);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
    }

    private static void TryDeleteDir(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        catch (IOException) { }
    }
}
