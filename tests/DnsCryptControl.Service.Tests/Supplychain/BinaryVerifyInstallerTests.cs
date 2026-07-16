using System.IO;
using System.IO.Compression;
using System.Text;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Supplychain;
using Xunit;

namespace DnsCryptControl.Service.Tests.Supplychain;

public class BinaryVerifyInstallerTests
{
    private sealed class FakeProxy : IProxyServiceController
    {
        public System.Collections.Generic.List<string> Calls { get; } = new();
        public PlatformResult Stop() { Calls.Add("Stop"); return PlatformResult.Ok(); }
        public PlatformResult Uninstall() { Calls.Add("Uninstall"); return PlatformResult.Ok(); }
        public PlatformResult Install() { Calls.Add("Install"); return PlatformResult.Ok(); }
        public PlatformResult Start() { Calls.Add("Start"); return PlatformResult.Ok(); }
        public PlatformResult Restart() => PlatformResult.Ok();
        public PlatformResult<ProxyServiceState> GetState() => PlatformResult<ProxyServiceState>.Ok(ProxyServiceState.Stopped);
    }

    private static (string stageZip, string baseDir) StageZip(byte[] zipBytes)
    {
        var baseDir = Directory.CreateTempSubdirectory().FullName;
        var stage = Path.Combine(baseDir, "staging");
        Directory.CreateDirectory(stage);
        var zipPath = Path.Combine(stage, "dnscrypt-proxy-win64-2.1.16.zip");
        File.WriteAllBytes(zipPath, zipBytes);
        File.WriteAllText(zipPath + ".minisig", "untrusted comment: x\nSIG\ntrusted comment: file:dnscrypt-proxy-win64-2.1.16.zip\nGLOBAL\n");
        return (zipPath, baseDir);
    }

    private static byte[] ProxyZip() // a zip whose only meaningful entry is the proxy exe
    {
        using var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var s = z.CreateEntry("dnscrypt-proxy.exe").Open();
            var b = Encoding.ASCII.GetBytes("MZ-proxy");
            s.Write(b, 0, b.Length);
        }
        return ms.ToArray();
    }

    private static BinaryVerifyInstaller Build(string baseDir, FakeProxy proxy,
        System.Func<byte[], string, string, MinisignVerifyResult> verify)
    {
        var paths = new ProtectedPaths(baseDir);
        var record = new InstalledBinaryRecordStore(paths.InstalledBinaryRecordFile);
        return new BinaryVerifyInstaller(paths, proxy, record, verify);
    }

    [Fact]
    public void VerifyAndInstall_verificationFails_doesNotTouchService_orInstallBinary()
    {
        var (zip, baseDir) = StageZip(ProxyZip());
        var proxy = new FakeProxy();
        var installer = Build(baseDir, proxy,
            (_, _, _) => MinisignVerifyResult.Fail(MinisignVerifyError.MessageSignatureInvalid));

        var r = installer.VerifyAndInstall(zip, "2.1.16");

        Assert.False(r.Success);
        Assert.Empty(proxy.Calls); // fail-closed: no stop/uninstall before verification passes
        Assert.False(File.Exists(Path.Combine(baseDir, "dnscrypt-proxy.exe")));
    }

    [Fact]
    public void VerifyAndInstall_success_stopsUninstalls_extracts_reinstallsStarts_andRecords()
    {
        var (zip, baseDir) = StageZip(ProxyZip());
        var proxy = new FakeProxy();
        var installer = Build(baseDir, proxy, (_, _, _) => MinisignVerifyResult.Pass());

        var r = installer.VerifyAndInstall(zip, "2.1.16");

        Assert.True(r.Success, r.Message);
        Assert.Equal(new[] { "Stop", "Uninstall", "Install", "Start" }, proxy.Calls);
        Assert.Equal("MZ-proxy", File.ReadAllText(Path.Combine(baseDir, "dnscrypt-proxy.exe")));
        Assert.True(File.Exists(Path.Combine(baseDir, "state", "installed-binary.json")));
    }

    [Fact]
    public void VerifyAndInstall_pathOutsideStaging_isRejected()
    {
        var (_, baseDir) = StageZip(ProxyZip());
        var proxy = new FakeProxy();
        var installer = Build(baseDir, proxy, (_, _, _) => MinisignVerifyResult.Pass());

        var outside = Path.Combine(Path.GetTempPath(), "elsewhere.zip");
        File.WriteAllBytes(outside, ProxyZip());
        var r = installer.VerifyAndInstall(outside, "2.1.16");

        Assert.False(r.Success);
        Assert.Equal(PlatformErrorKind.InvalidArgument, r.Error);
        Assert.Empty(proxy.Calls);
    }

    [Fact]
    public void VerifyAndInstall_invalidTag_isRejectedBeforeAnyIo()
    {
        var (zip, baseDir) = StageZip(ProxyZip());
        var proxy = new FakeProxy();
        var installer = Build(baseDir, proxy, (_, _, _) => MinisignVerifyResult.Pass());

        var r = installer.VerifyAndInstall(zip, "2.1.16; rm -rf");
        Assert.False(r.Success);
        Assert.Equal(PlatformErrorKind.InvalidArgument, r.Error);
        Assert.Empty(proxy.Calls);
    }

    [Fact]
    public void VerifyAndInstall_missingMinisig_failsClosed()
    {
        var (zip, baseDir) = StageZip(ProxyZip());
        File.Delete(zip + ".minisig");
        var proxy = new FakeProxy();
        var installer = Build(baseDir, proxy, (_, _, _) => MinisignVerifyResult.Pass());

        var r = installer.VerifyAndInstall(zip, "2.1.16");
        Assert.False(r.Success);
        Assert.Empty(proxy.Calls);
    }
}
