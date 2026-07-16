using System.IO;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B3: the UI's off-disk reader for the authoritative "is protection on" intent — the
/// master toggle must reflect last-known state even when the helper is unreachable.
/// Matches the EXACT on-disk shape the Service actually writes
/// (<c>DnsCryptControl.Service.State.ProtectionStateStore</c> over the
/// <c>ProtectionState</c> record, camelCase, via
/// <c>ProtectedPaths.ProtectionStateFile</c> = <c>%ProgramData%\DnsCryptControl\state\protection.json</c>)
/// — verified by reading (not referencing) the Service project's source.
/// </summary>
public class ProtectionStateReaderTests
{
    [Fact]
    public void Read_returns_persisted_intent()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".json");
        try
        {
            File.WriteAllText(path,
                """
                {
                  "protectionEnabled": true,
                  "killSwitchEnabled": true,
                  "leakMitigationsEnabled": false
                }
                """);

            var reader = new ProtectionStateReader(path);

            var intent = reader.Read();

            Assert.True(intent.ProtectionEnabled);
            Assert.True(intent.KillSwitchEnabled);
            Assert.False(intent.LeakMitigationsEnabled);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Missing_file_returns_all_false()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".json");
        Assert.False(File.Exists(path));

        var reader = new ProtectionStateReader(path);

        var intent = reader.Read();

        Assert.False(intent.ProtectionEnabled);
        Assert.False(intent.KillSwitchEnabled);
        Assert.False(intent.LeakMitigationsEnabled);
    }

    [Fact]
    public void Malformed_file_returns_all_false()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".json");
        try
        {
            File.WriteAllText(path, "{ not valid json ]]]");

            var reader = new ProtectionStateReader(path);

            var intent = reader.Read();

            Assert.False(intent.ProtectionEnabled);
            Assert.False(intent.KillSwitchEnabled);
            Assert.False(intent.LeakMitigationsEnabled);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Guards against the UI reader drifting from the Service writer: this fixture is
    /// byte-for-byte what <c>ProtectionStateStore.Save</c> produces — camelCase property
    /// names via <c>JsonSourceGenerationOptions(WriteIndented = true,
    /// PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)</c> over the
    /// <c>ProtectionState(bool ProtectionEnabled, bool KillSwitchEnabled, bool LeakMitigationsEnabled)</c>
    /// record (verified in <c>src/DnsCryptControl.Service/State/ProtectionStateStore.cs</c>).
    /// </summary>
    [Fact]
    public void Reads_a_fixture_in_the_Service_write_shape()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".json");
        try
        {
            File.WriteAllText(path,
                "{\n  \"protectionEnabled\": true,\n  \"killSwitchEnabled\": false,\n  \"leakMitigationsEnabled\": true\n}");

            var reader = new ProtectionStateReader(path);

            var intent = reader.Read();

            Assert.True(intent.ProtectionEnabled);
            Assert.False(intent.KillSwitchEnabled);
            Assert.True(intent.LeakMitigationsEnabled);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
