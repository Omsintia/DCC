using System;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Real proxy service controller: queries/controls the dnscrypt-proxy Windows service via
/// System.ServiceProcess.ServiceController and registers/removes it via the proxy's own
/// "-service install|uninstall" CLI. All child processes use ProcessStartInfo + ArgumentList
/// with an absolute exe path (CWE-78). Runs as SYSTEM inside the helper service.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProxyServiceController : IProxyServiceController
{
    private readonly string _exePath;
    private readonly string _serviceName;
    private readonly TimeSpan _waitTimeout;

    public WindowsProxyServiceController(string proxyExePath, string serviceName = "dnscrypt-proxy", TimeSpan? waitTimeout = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(proxyExePath);
        if (!System.IO.Path.IsPathFullyQualified(proxyExePath))
            throw new ArgumentException("Proxy exe path must be absolute (CWE-78).", nameof(proxyExePath));
        ArgumentException.ThrowIfNullOrEmpty(serviceName);

        _exePath = proxyExePath;
        _serviceName = serviceName;
        _waitTimeout = waitTimeout ?? TimeSpan.FromSeconds(30);
    }

    /// <summary>
    /// Builds a <see cref="ProcessStartInfo"/> for the dnscrypt-proxy -service CLI.
    /// Uses ArgumentList (never a concatenated Arguments string) with an absolute exe path (CWE-78).
    /// Extracted as an internal static method so unit tests can verify the security-relevant shape
    /// without launching a real process.
    /// </summary>
    internal static ProcessStartInfo BuildServiceCommand(string exePath, string verb)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        psi.ArgumentList.Add("-service");
        psi.ArgumentList.Add(verb);
        return psi;
    }

    /// <inheritdoc/>
    public PlatformResult<ProxyServiceState> GetState()
    {
        try
        {
            using var sc = new ServiceController(_serviceName);
            sc.Refresh();
            return PlatformResult<ProxyServiceState>.Ok(Map(sc.Status));
        }
        catch (InvalidOperationException)
        {
            // Service does not exist on this machine.
            return PlatformResult<ProxyServiceState>.Ok(ProxyServiceState.NotInstalled);
        }
    }

    /// <summary>
    /// Builds a <see cref="ProcessStartInfo"/> for <c>sc.exe config &lt;svc&gt; start= demand</c>, which sets the
    /// proxy service to DEMAND_START (manual). Uses ArgumentList (never a concatenated string) with the absolute
    /// System32 sc.exe path (CWE-78). sc.exe's syntax requires the option name and value as SEPARATE tokens
    /// ("start=" then "demand"), so they are two ArgumentList elements.
    /// <para>Rationale: <c>-service install</c> registers the proxy as AUTO_START (kardianos default), which would
    /// let the SCM launch dnscrypt-proxy.exe on boot BEFORE the helper's launch-time integrity gate runs
    /// (inert-gate / TOCTOU). Forcing DEMAND_START makes the gated helper the SOLE launcher of the proxy.</para>
    /// <para>Like NetshFirewallRuleStore, we do NOT redirect stdout/stderr: the output is unused and a
    /// draining-less redirect can deadlock the SYSTEM service if sc fills the pipe before exit.</para>
    /// Extracted as an internal static method so unit tests can verify the security-relevant shape.
    /// </summary>
    internal static ProcessStartInfo BuildScConfigDemandStartCommand(string serviceName)
    {
        ArgumentException.ThrowIfNullOrEmpty(serviceName);
        var sc = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe");
        var psi = new ProcessStartInfo
        {
            FileName = sc,
            UseShellExecute = false,
            CreateNoWindow = true,
            // No RedirectStandardOutput/Error: output is unused and draining-less redirection can deadlock.
        };
        psi.ArgumentList.Add("config");
        psi.ArgumentList.Add(serviceName);
        psi.ArgumentList.Add("start=");   // sc.exe requires "start=" and "demand" as SEPARATE tokens
        psi.ArgumentList.Add("demand");
        return psi;
    }

    /// <inheritdoc/>
    public PlatformResult Install()
    {
        var install = RunCli("install");
        if (!install.Success) return install;

        // Force DEMAND_START so the SCM never auto-launches the proxy ahead of the helper's integrity gate.
        // If we cannot demand-start, the service must NOT be left auto-start -> fail-closed.
        return RunScConfigDemandStart();
    }

    /// <inheritdoc/>
    public PlatformResult Uninstall() => RunCli("uninstall");

    /// <inheritdoc/>
    /// <remarks>Idempotent ensure-running, mirroring <see cref="Stop"/>'s <c>CanStop</c> guard: a
    /// proxy that is ALREADY Running is the desired state, not an error. Without this, every
    /// Save &amp; apply (which leaves the proxy Running) made the next EnableProtection fail its
    /// Start(proxy) step with ERROR_SERVICE_ALREADY_RUNNING and roll the whole enable back —
    /// stopping the running proxy in the process (Phase 5b live-VM finding).</remarks>
    public PlatformResult Start() => ControlAndWait(
        sc =>
        {
            if (sc.Status == ServiceControllerStatus.Running) return;
            try
            {
                sc.Start();
            }
            catch (InvalidOperationException ex) when (IsAlreadyRunningRace(ex))
            {
                // Lost the refresh->start race to another starter: the SCM reports 1056 for any
                // non-STOPPED state (StartPending, Running, and also StopPending — the latter
                // burns the WaitForStatus timeout below and fails Timeout, which is the correct
                // fail-closed outcome for "someone is concurrently stopping the proxy").
            }
        },
        ServiceControllerStatus.Running);

    private const int ErrorServiceAlreadyRunning = 1056; // winerror.h ERROR_SERVICE_ALREADY_RUNNING
    private const int ErrorServiceDoesNotExist = 1060;   // winerror.h ERROR_SERVICE_DOES_NOT_EXIST

    /// <summary>True iff the exception wraps Win32 ERROR_SERVICE_ALREADY_RUNNING — the only start
    /// failure that means the desired state already holds. Discriminated by NATIVE ERROR CODE,
    /// never message text (localized). Note: on .NET 8 a missing service ALSO throws
    /// InvalidOperationException wrapping a Win32Exception — NativeErrorCode 1060 — so the
    /// discrimination genuinely rests on the code compare, not on the presence of an inner.</summary>
    internal static bool IsAlreadyRunningRace(InvalidOperationException ex) =>
        ex.InnerException is System.ComponentModel.Win32Exception w
        && w.NativeErrorCode == ErrorServiceAlreadyRunning;

    /// <summary>Maps a wrapped SCM control failure to the right error kind: only a genuine
    /// ERROR_SERVICE_DOES_NOT_EXIST (1060) — or the innerless legacy shape — is
    /// <see cref="PlatformErrorKind.NotFound"/>. Every other wrapped code (access denied,
    /// service disabled, logon failure, …) is <see cref="PlatformErrorKind.OperationFailed"/>,
    /// so it can never masquerade as "not installed" — <see cref="Restart"/> deliberately
    /// tolerates NotFound from its Stop leg and must not swallow real control failures.</summary>
    internal static PlatformErrorKind MapControlFailure(InvalidOperationException ex) =>
        ex.InnerException is System.ComponentModel.Win32Exception w
        && w.NativeErrorCode != ErrorServiceDoesNotExist
            ? PlatformErrorKind.OperationFailed
            : PlatformErrorKind.NotFound;

    /// <inheritdoc/>
    public PlatformResult Stop() => ControlAndWait(sc => { if (sc.CanStop) sc.Stop(); }, ServiceControllerStatus.Stopped);

    /// <inheritdoc/>
    public PlatformResult Restart()
    {
        var stop = Stop();
        // Tolerate NotFound from the Stop leg (nothing to stop; Start below will surface it
        // if the service is truly absent). Any other failure - including Timeout - is a hard
        // failure and propagates.
        if (!stop.Success && stop.Error != PlatformErrorKind.NotFound) return stop;
        return Start();
    }

    private PlatformResult ControlAndWait(Action<ServiceController> control, ServiceControllerStatus target)
    {
        try
        {
            using var sc = new ServiceController(_serviceName);
            sc.Refresh();
            control(sc);
            sc.WaitForStatus(target, _waitTimeout);
            return PlatformResult.Ok();
        }
        catch (InvalidOperationException ex)
        {
            return PlatformResult.Fail(MapControlFailure(ex), ex.Message);
        }
        catch (System.ServiceProcess.TimeoutException ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.Timeout, ex.Message);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message);
        }
    }

    private PlatformResult RunCli(string verb)
    {
        try
        {
            using var proc = Process.Start(BuildServiceCommand(_exePath, verb));
            if (proc is null)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed, "failed to start proxy CLI");

            if (!proc.WaitForExit((int)_waitTimeout.TotalMilliseconds))
            {
                try { proc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                return PlatformResult.Fail(PlatformErrorKind.Timeout, $"proxy -service {verb} timed out");
            }

            return proc.ExitCode == 0
                ? PlatformResult.Ok()
                : PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"proxy -service {verb} exit {proc.ExitCode}");
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message);
        }
    }

    /// <summary>Runs <c>sc.exe config &lt;svc&gt; start= demand</c> with a bounded wait (kill-on-timeout). No
    /// stdout/stderr redirect (draining-less redirect can deadlock the SYSTEM service — mirrors netsh).</summary>
    private PlatformResult RunScConfigDemandStart()
    {
        try
        {
            using var proc = Process.Start(BuildScConfigDemandStartCommand(_serviceName));
            if (proc is null)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed, "failed to start sc.exe");

            if (!proc.WaitForExit((int)_waitTimeout.TotalMilliseconds))
            {
                try { proc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                return PlatformResult.Fail(PlatformErrorKind.Timeout, "sc config start= demand timed out");
            }

            return proc.ExitCode == 0
                ? PlatformResult.Ok()
                : PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"sc config start= demand exit {proc.ExitCode}");
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message);
        }
    }

    private static ProxyServiceState Map(ServiceControllerStatus status) => status switch
    {
        ServiceControllerStatus.Stopped => ProxyServiceState.Stopped,
        ServiceControllerStatus.StartPending => ProxyServiceState.StartPending,
        ServiceControllerStatus.Running => ProxyServiceState.Running,
        ServiceControllerStatus.StopPending => ProxyServiceState.StopPending,
        _ => ProxyServiceState.Unknown,
    };
}
