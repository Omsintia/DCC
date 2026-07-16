using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using DnsCryptControl.Platform;
using Microsoft.Management.Infrastructure;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Flushes the Windows DNS resolver cache — the same routine maintenance action performed by the
/// built-in Clear-DnsClientCache cmdlet / "ipconfig /flushdns". Primary path is the documented CIM
/// static method root\StandardCimv2:MSFT_DNSClientCache.Clear (no child process, quieter to EDR);
/// fallback is ipconfig.exe /flushdns launched via ProcessStartInfo + ArgumentList with an absolute
/// System32 path (CWE-78). Runs as SYSTEM inside the helper service.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CimDnsCacheFlusher : IDnsCacheFlusher
{
    private readonly ICacheFlushBackend _primary;
    private readonly ICacheFlushBackend _fallback;

    /// <summary>Production ctor: CIM primary, ipconfig fallback.</summary>
    public CimDnsCacheFlusher()
        : this(new CimCacheFlushBackend(), new IpconfigCacheFlushBackend())
    {
    }

    /// <summary>Test ctor: inject fake backends to exercise the fallback coordinator logic.</summary>
    internal CimDnsCacheFlusher(ICacheFlushBackend primary, ICacheFlushBackend fallback)
    {
        ArgumentNullException.ThrowIfNull(primary);
        ArgumentNullException.ThrowIfNull(fallback);
        _primary = primary;
        _fallback = fallback;
    }

    /// <inheritdoc/>
    public PlatformResult Flush()
    {
        string? primaryError;
        try
        {
            var primary = _primary.TryFlush();
            if (primary.Success)
                return PlatformResult.Ok();
            primaryError = primary.Message ?? "primary flush failed";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            // CIM is the OPSEC-preferred path but can throw (mi.dll/WMI hiccups, class-not-found on a
            // mis-cased name); fall back to the always-present ipconfig mechanism instead of failing.
            primaryError = ex.Message;
        }

        try
        {
            var fallback = _fallback.TryFlush();
            if (fallback.Success)
                return PlatformResult.Ok();
            return PlatformResult.Fail(
                PlatformErrorKind.OperationFailed,
                $"DNS cache flush failed. primary: {primaryError}; fallback: {fallback.Message ?? "ipconfig flush failed"}");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            return PlatformResult.Fail(
                PlatformErrorKind.OperationFailed,
                $"DNS cache flush failed. primary: {primaryError}; fallback: {ex.Message}");
        }
    }
}

/// <summary>Seam for the two flush mechanisms so the coordinator's fallback logic is unit-testable.</summary>
internal interface ICacheFlushBackend
{
    /// <summary>Attempt one flush. Returns Ok on success; Fail on a handled error. May throw on an
    /// unexpected native/runtime failure (the coordinator treats a throw as "try the fallback").</summary>
    PlatformResult TryFlush();
}

/// <summary>
/// Primary backend: the documented CIM static method root\StandardCimv2:MSFT_DNSClientCache.Clear,
/// invoked via Microsoft.Management.Infrastructure (mi.dll). Identical to Clear-DnsClientCache. No
/// process spawn, no banned API. Class name is MSFT_DNSClientCache (capital DNS) — exact runtime
/// casing matters; a wrong case yields "class not found".
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class CimCacheFlushBackend : ICacheFlushBackend
{
    private const string CimNamespace = @"root\StandardCimv2";
    private const string CimClassName = "MSFT_DNSClientCache";
    private const string CimMethodName = "Clear";

    public PlatformResult TryFlush()
    {
        using var session = CimSession.Create(null); // local session, runs in LocalSystem context
        using CimMethodResult result = session.InvokeMethod(
            CimNamespace,
            CimClassName,
            CimMethodName,
            new CimMethodParametersCollection());

        // MSFT_DNSClientCache.Clear has no [out] return code on some Windows builds (the Win11
        // dev-environment image among them): a successful InvokeMethod with a NULL ReturnValue means the
        // method ran and the cache was cleared. Treat null OR a zero code as success; only a non-zero code
        // is a failure. (Guards a NullReferenceException surfaced by the live ManualIntegration run; a
        // genuine CIM error still throws from InvokeMethod, which the coordinator maps to the fallback.)
        var rc = result?.ReturnValue?.Value as uint?;
        return rc is null or 0u
            ? PlatformResult.Ok()
            : PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"MSFT_DNSClientCache.Clear returned {rc.Value}");
    }
}

/// <summary>
/// Fallback backend: ipconfig.exe /flushdns. Absolute System32 path (never trust PATH, CWE-78);
/// ProcessStartInfo.FileName + ArgumentList (not the banned Process.Start(string) / Arguments string).
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class IpconfigCacheFlushBackend : ICacheFlushBackend
{
    private static readonly TimeSpan WaitTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Builds the ProcessStartInfo for "ipconfig /flushdns" with an absolute System32 path and
    /// ArgumentList. Extracted as an internal static method so a unit test can verify the
    /// security-relevant shape without launching a real process.
    /// </summary>
    internal static ProcessStartInfo BuildFlushCommand()
    {
        string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string ipconfig = Path.Combine(system32, "ipconfig.exe");
        var psi = new ProcessStartInfo
        {
            FileName = ipconfig,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("/flushdns");
        return psi;
    }

    public PlatformResult TryFlush()
    {
        using var proc = Process.Start(BuildFlushCommand());
        if (proc is null)
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, "failed to start ipconfig.exe");

        if (!proc.WaitForExit((int)WaitTimeout.TotalMilliseconds))
        {
            try { proc.Kill(entireProcessTree: true); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            return PlatformResult.Fail(PlatformErrorKind.Timeout, "ipconfig /flushdns timed out");
        }

        return proc.ExitCode == 0
            ? PlatformResult.Ok()
            : PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"ipconfig /flushdns exit {proc.ExitCode}");
    }
}
