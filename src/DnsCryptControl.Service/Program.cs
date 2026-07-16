using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using DnsCryptControl.Service;
using DnsCryptControl.Service.Windows;

// High-performance log delegates (CA1848 — no string-interpolation at call site).
Action<ILogger, Exception?> logPlaceholderThumbprint =
    LoggerMessage.Define(
        LogLevel.Warning,
        new EventId(2, "PlaceholderThumbprint"),
        "Signer allow-list contains a placeholder thumbprint; ALL callers will be rejected " +
        "until it is replaced with the real Authenticode thumbprint.");

Action<ILogger, Exception?> logUnsupportedOsVersion =
    LoggerMessage.Define(
        LogLevel.Critical,
        new EventId(3, "UnsupportedOsVersion"),
        "The DnsCryptControl helper requires Windows 10 build 19041 or later (the static DNS " +
        "adapter API). The host will not start on this OS version.");

Action<ILogger, string, Exception?> logIntegrityFailure =
    LoggerMessage.Define<string>(
        LogLevel.Critical,
        new EventId(4, "BinaryIntegrityFailure"),
        "Installed dnscrypt-proxy.exe failed launch-time integrity verification ({Reason}); " +
        "the helper will NOT start the pipe server (fail-closed). Reinstall a verified binary.");

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "DnsCryptControlHelper");

// Resolve the interactive user DYNAMICALLY, not once: the pipe accept loop calls this on EVERY
// iteration and rebuilds the pipe DACL from its result, so a helper that auto-started at boot before
// login grants the interactive user as soon as a session becomes active (console or RDP) — without a
// service restart. A null result keeps the DACL SYSTEM-only (fail closed; BuiltinUsers is NEVER used
// as a fallback — too broad, spec §5.1). This is the Phase-5 "retry logic" the old startup-only
// resolution lacked (which is why the helper was unreachable after every reboot until restarted).
Func<SecurityIdentifier?> resolveInteractiveUser =
    static () => ConsoleSessionUser.TryResolveActiveInteractiveUser(out var s) ? s : null;

// Fail closed on unsupported OS: the static DNS adapter API (WindowsDnsAdapterConfigurator) requires
// Windows 10 build 19041+. Below that, build a minimal host only to surface a Critical Event Log
// entry, then exit without composing the privileged graph.
if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041))
{
    using var bootstrap = builder.Build();
    var bootLogger = bootstrap.Services.GetRequiredService<ILoggerFactory>()
        .CreateLogger("DnsCryptControl.Service");
    logUnsupportedOsVersion(bootLogger, null);
    return;
}

ServiceComposition.ConfigureServices(builder.Services, resolveInteractiveUser);

var host = builder.Build();

// Obtain a logger backed by the Windows Event Log (via AddWindowsService) for startup warnings.
var logger = host.Services.GetRequiredService<ILoggerFactory>()
    .CreateLogger("DnsCryptControl.Service");

// MSI uninstall custom action (IC-PKG): `--teardown` reverts every protection artifact via the same
// tested paths the live verbs use, then exits. It MUST run BEFORE the integrity gate (teardown has to
// work even with a broken/missing proxy binary) and INSTEAD of boot reconciliation (Reconcile would
// RE-assert protection from the intent this teardown is clearing). The MSI stops the helper service
// before invoking this, so the CLI process has exclusive access to the state stores.
if (args.Contains("--teardown", StringComparer.OrdinalIgnoreCase))
{
    Environment.ExitCode = host.Services.GetRequiredService<UninstallTeardown>().Run();
    return;
}

if (ServiceComposition.AllowedSignerThumbprints.Any(
        t => t.StartsWith("REPLACE_", StringComparison.OrdinalIgnoreCase)))
{
    logPlaceholderThumbprint(logger, null);
}

// Launch-time supply-chain integrity (Phase 4, IC-10): the verified-binary state MUST dominate every
// launch, so this gate runs BEFORE boot reconciliation (which would otherwise start the proxy). On
// failure: log Critical, defensively Stop any running proxy (with demand-start this is normally a
// no-op/NotFound, which is fine), then exit WITHOUT reconciling or running the host. The decorated
// IProxyServiceController also blocks the proxy at every Start/Restart, so this is defence-in-depth.
var integrity = host.Services.GetRequiredService<DnsCryptControl.Service.Supplychain.BinaryIntegrityGate>().Verify();
if (!integrity.Success)
{
    logIntegrityFailure(logger, integrity.Message ?? "unknown", null);
    _ = host.Services.GetRequiredService<DnsCryptControl.Platform.IProxyServiceController>().Stop();
    return; // do NOT reconcile, do NOT run the host / pipe server.
}

// Fail-closed + auto-recover startup reconciliation (contracts §7). Runs once, synchronously, only
// AFTER the integrity gate passes, before the host (pipe server / network-change watcher) starts. Never
// throws; a failing subsystem is logged via ILogger (reaches the Event Log under AddWindowsService).
host.Services.GetRequiredService<BootReconciler>().Reconcile();

host.Run();
