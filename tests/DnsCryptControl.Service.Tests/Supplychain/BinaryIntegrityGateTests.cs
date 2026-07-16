using System.IO;
using System.Security.Cryptography;
using System.Text;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Supplychain;
using Xunit;

namespace DnsCryptControl.Service.Tests.Supplychain;

public class BinaryIntegrityGateTests
{
    private static (ProtectedPaths paths, InstalledBinaryRecordStore record) NewEnv()
    {
        var baseDir = Directory.CreateTempSubdirectory().FullName;
        var paths = new ProtectedPaths(baseDir);
        return (paths, new InstalledBinaryRecordStore(paths.InstalledBinaryRecordFile));
    }

    private static string WriteExe(ProtectedPaths paths, string content)
    {
        Directory.CreateDirectory(paths.BaseDir);
        File.WriteAllText(paths.ProxyExeFile, content);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
    }

    [Fact]
    public void Verify_noExe_noRecord_passes_freshInstall()
    {
        var (paths, record) = NewEnv();
        Assert.True(new BinaryIntegrityGate(paths, record).Verify().Success);
    }

    [Fact]
    public void Verify_exePresent_butNoRecord_failsClosed()
    {
        var (paths, record) = NewEnv();
        WriteExe(paths, "MZ");
        Assert.False(new BinaryIntegrityGate(paths, record).Verify().Success);
    }

    [Fact]
    public void Verify_matchingHash_passes()
    {
        var (paths, record) = NewEnv();
        var hash = WriteExe(paths, "MZ-good");
        record.Record(hash, "2.1.16");
        Assert.True(new BinaryIntegrityGate(paths, record).Verify().Success);
    }

    [Fact]
    public void Verify_tamperedExe_mismatch_failsClosed()
    {
        var (paths, record) = NewEnv();
        var hash = WriteExe(paths, "MZ-good");
        record.Record(hash, "2.1.16");
        File.WriteAllText(paths.ProxyExeFile, "MZ-tampered"); // swap after recording
        Assert.False(new BinaryIntegrityGate(paths, record).Verify().Success);
    }
}
