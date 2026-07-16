using System;
using System.Linq;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class WindowsProxyServiceControllerTests
{
    [Fact]
    public void Ctor_rejectsNonAbsoluteExePath()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Throws<ArgumentException>(() => new WindowsProxyServiceController("dnscrypt-proxy.exe"));
    }

    [Fact]
    public void BuildServiceCommand_usesArgumentList_notConcatenation()
    {
        if (!OperatingSystem.IsWindows()) return;
        var psi = WindowsProxyServiceController.BuildServiceCommand(@"C:\pd\dnscrypt-proxy.exe", "install");
        Assert.Equal(@"C:\pd\dnscrypt-proxy.exe", psi.FileName);
        Assert.False(psi.UseShellExecute);
        Assert.Equal(new[] { "-service", "install" }, psi.ArgumentList.ToArray());
        Assert.Empty(psi.Arguments); // never the concatenated form
    }

    [Fact]
    public void BuildScConfigDemandStartCommand_usesAbsoluteScPath_argumentList_noShell_demandStart()
    {
        if (!OperatingSystem.IsWindows()) return;

        var psi = WindowsProxyServiceController.BuildScConfigDemandStartCommand("dnscrypt-proxy");

        var expectedSc = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe");
        Assert.Equal(expectedSc, psi.FileName);
        Assert.True(System.IO.Path.IsPathFullyQualified(psi.FileName));
        Assert.False(psi.UseShellExecute);
        Assert.True(psi.CreateNoWindow);
        Assert.Empty(psi.Arguments); // never the concatenated form (CWE-78)
        // sc.exe requires the "start=" token and the "demand" value as SEPARATE tokens.
        Assert.Equal(new[] { "config", "dnscrypt-proxy", "start=", "demand" }, psi.ArgumentList.ToArray());
    }

    [Fact]
    public void BuildScConfigDemandStartCommand_doesNotRedirectStdoutOrStderr()
    {
        if (!OperatingSystem.IsWindows()) return;

        // Mirror NetshFirewallRuleStore: redirecting without draining the pipes can deadlock the SYSTEM
        // service (sc blocks on a full pipe while we block on WaitForExit). CreateNoWindow + no shell suffice.
        var psi = WindowsProxyServiceController.BuildScConfigDemandStartCommand("dnscrypt-proxy");
        Assert.False(psi.RedirectStandardOutput);
        Assert.False(psi.RedirectStandardError);
    }

    [Fact]
    public void GetState_whenServiceAbsent_returnsNotInstalled()
    {
        if (!OperatingSystem.IsWindows()) return;
        var c = new WindowsProxyServiceController(@"C:\pd\dnscrypt-proxy.exe", serviceName: "DnsCryptControl_NoSuchSvc_XYZ");
        var state = c.GetState();
        Assert.True(state.Success);
        Assert.Equal(ProxyServiceState.NotInstalled, state.Value);
    }

    // ---- Start() idempotency (Phase 5b live-VM finding): every Save & apply leaves the proxy
    // ---- Running, so EnableProtection's Start(proxy) hit ERROR_SERVICE_ALREADY_RUNNING and
    // ---- rolled the whole enable back. Start must treat already-running as success.

    [Fact]
    public void IsAlreadyRunningRace_recognizes_ERROR_SERVICE_ALREADY_RUNNING_by_native_code()
    {
        if (!OperatingSystem.IsWindows()) return;
        var ex = new InvalidOperationException(
            "Cannot start service 'dnscrypt-proxy' on computer '.'.",
            new System.ComponentModel.Win32Exception(1056)); // ERROR_SERVICE_ALREADY_RUNNING
        Assert.True(WindowsProxyServiceController.IsAlreadyRunningRace(ex));
    }

    [Theory]
    [InlineData(1058)] // ERROR_SERVICE_DISABLED
    [InlineData(1060)] // ERROR_SERVICE_DOES_NOT_EXIST
    [InlineData(5)]    // ERROR_ACCESS_DENIED
    public void IsAlreadyRunningRace_rejects_other_win32_codes(int nativeCode)
    {
        if (!OperatingSystem.IsWindows()) return;
        var ex = new InvalidOperationException(
            "Cannot start service 'dnscrypt-proxy' on computer '.'.",
            new System.ComponentModel.Win32Exception(nativeCode));
        Assert.False(WindowsProxyServiceController.IsAlreadyRunningRace(ex));
    }

    [Fact]
    public void IsAlreadyRunningRace_rejects_exception_without_win32_inner()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Pure defensive coverage: on .NET 8 a missing service actually wraps Win32 code 1060
        // (pinned by the InlineData(1060) case above) - the innerless shape is not produced by
        // ServiceController, but the discriminator must still reject it.
        Assert.False(WindowsProxyServiceController.IsAlreadyRunningRace(
            new InvalidOperationException("Service dnscrypt-proxy was not found on computer '.'.")));
    }

    [Fact]
    public void Start_whenServiceAlreadyRunning_returnsOk()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Pins the exact live-VM escape: Start() while the service is ALREADY Running must be
        // success. Dnscache (DNS Client) is a protected, always-running Windows service, so the
        // skip-when-Running path is exercised against the REAL SCM with only SERVICE_QUERY_STATUS
        // rights - no elevation, no SCM mutation (in-idiom with GetState_whenServiceAbsent above).
        using var dnscache = new System.ServiceProcess.ServiceController("Dnscache");
        try
        {
            if (dnscache.Status != System.ServiceProcess.ServiceControllerStatus.Running) return;
        }
        catch (InvalidOperationException)
        {
            return; // no Dnscache on this box - nothing to pin
        }

        var c = new WindowsProxyServiceController(@"C:\pd\dnscrypt-proxy.exe", serviceName: "Dnscache");
        var result = c.Start();
        Assert.True(result.Success, result.Message);
    }

    // ---- ControlAndWait failure mapping (review follow-up): only a genuine 1060 (or the
    // ---- innerless legacy shape) may report NotFound - Restart() tolerates NotFound from its
    // ---- Stop leg, so any other mapping would swallow real control failures.

    [Fact]
    public void MapControlFailure_serviceDoesNotExist_1060_maps_to_NotFound()
    {
        if (!OperatingSystem.IsWindows()) return;
        var ex = new InvalidOperationException("Service dnscrypt-proxy was not found on computer '.'.",
            new System.ComponentModel.Win32Exception(1060)); // ERROR_SERVICE_DOES_NOT_EXIST
        Assert.Equal(PlatformErrorKind.NotFound, WindowsProxyServiceController.MapControlFailure(ex));
    }

    [Theory]
    [InlineData(5)]    // ERROR_ACCESS_DENIED
    [InlineData(1058)] // ERROR_SERVICE_DISABLED
    [InlineData(1069)] // ERROR_SERVICE_LOGON_FAILED
    public void MapControlFailure_other_win32_codes_map_to_OperationFailed(int nativeCode)
    {
        if (!OperatingSystem.IsWindows()) return;
        var ex = new InvalidOperationException("Cannot open service.",
            new System.ComponentModel.Win32Exception(nativeCode));
        Assert.Equal(PlatformErrorKind.OperationFailed, WindowsProxyServiceController.MapControlFailure(ex));
    }

    [Fact]
    public void MapControlFailure_without_win32_inner_keeps_NotFound()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal(PlatformErrorKind.NotFound, WindowsProxyServiceController.MapControlFailure(
            new InvalidOperationException("legacy innerless shape")));
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void Install_Start_Stop_Uninstall_roundTrip()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Requires: elevated, a real dnscrypt-proxy.exe at the path below. See Step 7 manual command.
        // Intentionally not asserting here in CI; the manual run validates the full lifecycle.
        // Live coverage must include: Start() while the service is ALREADY Running returns Ok
        // (idempotent ensure-running) - the Phase 5b VM checklist section 6 exercises it via
        // Save & apply (proxy left Running) followed by the Dashboard protection toggle.
    }
}
