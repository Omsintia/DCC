using System.IO;
using DnsCryptControl.Service;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class ProtectedPathsStateTests
{
    [Fact]
    public void StateDir_isStateSubdirOfBase()
    {
        var paths = new ProtectedPaths(@"C:\ProgramData\DnsCryptControl");
        Assert.Equal(Path.Combine(@"C:\ProgramData\DnsCryptControl", "state"), paths.StateDir);
    }

    [Fact]
    public void BackupFile_isBackupJsonUnderStateDir()
    {
        var paths = new ProtectedPaths(@"C:\ProgramData\DnsCryptControl");
        Assert.Equal(Path.Combine(paths.StateDir, "backup.json"), paths.BackupFile);
    }

    [Fact]
    public void ProtectionStateFile_isProtectionJsonUnderStateDir()
    {
        var paths = new ProtectedPaths(@"C:\ProgramData\DnsCryptControl");
        Assert.Equal(Path.Combine(paths.StateDir, "protection.json"), paths.ProtectionStateFile);
    }
}
