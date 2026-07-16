using System.IO;
using DnsCryptControl.Service.State;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class InstalledBinaryRecordStoreTests
{
    private static string TempFile()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        return Path.Combine(dir, "state", "installed-binary.json");
    }

    [Fact]
    public void Load_absent_returnsNull()
    {
        Assert.Null(new InstalledBinaryRecordStore(TempFile()).Load());
    }

    [Fact]
    public void Record_thenLoad_roundTrips()
    {
        var store = new InstalledBinaryRecordStore(TempFile());
        store.Record("abc123", "2.1.16");
        var loaded = store.Load();
        Assert.NotNull(loaded);
        Assert.Equal("abc123", loaded!.Sha256Hex);
        Assert.Equal("2.1.16", loaded.Tag);
        Assert.False(string.IsNullOrEmpty(loaded.InstalledUtc));
    }

    [Fact]
    public void Load_corruptJson_returnsNull_doesNotThrow()
    {
        var path = TempFile();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "{ this is not json");
        Assert.Null(new InstalledBinaryRecordStore(path).Load());
    }
}
