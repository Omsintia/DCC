using System;
using System.Linq;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class CimDnsCacheFlusherTests
{
    private sealed class FakeBackend : ICacheFlushBackend
    {
        public int Calls { get; private set; }
        public Func<PlatformResult>? OnFlush { get; set; }

        public PlatformResult TryFlush()
        {
            Calls++;
            return OnFlush is null ? PlatformResult.Ok() : OnFlush();
        }
    }

    [Fact]
    public void PrimarySucceeds_fallbackNotInvoked()
    {
        var primary = new FakeBackend { OnFlush = () => PlatformResult.Ok() };
        var fallback = new FakeBackend();
        var flusher = new CimDnsCacheFlusher(primary, fallback);

        var result = flusher.Flush();

        Assert.True(result.Success);
        Assert.Equal(1, primary.Calls);
        Assert.Equal(0, fallback.Calls);
    }

    [Fact]
    public void PrimaryThrows_fallbackInvoked_andSucceeds()
    {
        var primary = new FakeBackend { OnFlush = () => throw new InvalidOperationException("CIM blew up") };
        var fallback = new FakeBackend { OnFlush = () => PlatformResult.Ok() };
        var flusher = new CimDnsCacheFlusher(primary, fallback);

        var result = flusher.Flush();

        Assert.True(result.Success);
        Assert.Equal(1, primary.Calls);
        Assert.Equal(1, fallback.Calls);
    }

    [Fact]
    public void PrimaryReturnsFailure_fallbackInvoked()
    {
        var primary = new FakeBackend { OnFlush = () => PlatformResult.Fail(PlatformErrorKind.OperationFailed, "rc=5") };
        var fallback = new FakeBackend { OnFlush = () => PlatformResult.Ok() };
        var flusher = new CimDnsCacheFlusher(primary, fallback);

        var result = flusher.Flush();

        Assert.True(result.Success);
        Assert.Equal(1, primary.Calls);
        Assert.Equal(1, fallback.Calls);
    }

    [Fact]
    public void BothFail_returnsOperationFailed_withBothMessages()
    {
        var primary = new FakeBackend { OnFlush = () => throw new InvalidOperationException("CIM blew up") };
        var fallback = new FakeBackend { OnFlush = () => PlatformResult.Fail(PlatformErrorKind.OperationFailed, "ipconfig exit 1") };
        var flusher = new CimDnsCacheFlusher(primary, fallback);

        var result = flusher.Flush();

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
        Assert.NotNull(result.Message);
        Assert.Contains("CIM blew up", result.Message!);
        Assert.Contains("ipconfig exit 1", result.Message!);
    }

    [Fact]
    public void PrimaryReturnsFailure_FallbackAlsoFails_returnsOperationFailed_withBothMessages()
    {
        var primary = new FakeBackend { OnFlush = () => PlatformResult.Fail(PlatformErrorKind.OperationFailed, "rc=5") };
        var fallback = new FakeBackend { OnFlush = () => PlatformResult.Fail(PlatformErrorKind.OperationFailed, "ipconfig exit 1") };
        var flusher = new CimDnsCacheFlusher(primary, fallback);
        var result = flusher.Flush();
        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
        Assert.Contains("rc=5", result.Message!);
        Assert.Contains("ipconfig exit 1", result.Message!);
        Assert.Equal(1, primary.Calls);
        Assert.Equal(1, fallback.Calls);
    }

    [Fact]
    public void IpconfigBackend_buildsAbsoluteSystem32Path_withArgumentList()
    {
        if (!OperatingSystem.IsWindows()) return;

        var psi = IpconfigCacheFlushBackend.BuildFlushCommand();

        Assert.True(System.IO.Path.IsPathFullyQualified(psi.FileName));
        Assert.EndsWith(@"\ipconfig.exe", psi.FileName, StringComparison.OrdinalIgnoreCase);
        Assert.False(psi.UseShellExecute);
        Assert.Equal(new[] { "/flushdns" }, psi.ArgumentList.ToArray());
        Assert.Empty(psi.Arguments); // never the concatenated form (CWE-78)
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void IpconfigBackend_flushesLiveCache()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Live: spawns C:\Windows\System32\ipconfig.exe /flushdns. Requires elevation.
        var result = new IpconfigCacheFlushBackend().TryFlush();
        Assert.True(result.Success, result.Message);
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void CimBackend_clearsLiveCache_verifyingClassNameCasing()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Live: invokes root\StandardCimv2:MSFT_DNSClientCache.Clear (capital DNS) on this machine.
        // Confirms the exact runtime class-name casing — a wrong case throws "class not found".
        var result = new CimCacheFlushBackend().TryFlush();
        Assert.True(result.Success, result.Message);
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void CimDnsCacheFlusher_endToEnd_flushesLiveCache()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Live end-to-end: CIM primary, ipconfig fallback. Requires elevation.
        var result = new CimDnsCacheFlusher().Flush();
        Assert.True(result.Success, result.Message);
    }
}
