using DnsCryptControl.Platform;
using Microsoft.Extensions.Logging;

namespace DnsCryptControl.Service;

/// <summary>The MSI uninstall's fail-safe teardown (IC-PKG, phase-6 packaging design): invoked as
/// <c>DnsCryptControl.Service.exe --teardown</c> by an elevated uninstall custom action BEFORE the
/// services and files are removed. Reverts every protection artifact via the SAME tested code paths
/// the live verbs use — <see cref="IProtectionOrchestrator.DisableProtection"/> (kill-switch rules,
/// leak-mitigation registry exact-revert, adapter DNS restore from backup, proxy stop, intent cleared
/// last) plus the browser-DoH HKLM policy revert (a separate Settings-owned toggle the orchestrator
/// does not manage). Continue-on-failure: every step always runs so a partly-broken install still
/// tears down as much as possible; the exit code only reports whether ALL steps succeeded.</summary>
public sealed class UninstallTeardown
{
    private static readonly Action<ILogger, string, string, Exception?> LogStepFailed =
        LoggerMessage.Define<string, string>(
            LogLevel.Error,
            new EventId(20, "UninstallTeardownStepFailed"),
            "Uninstall teardown: step failed (continuing): {Step} — {Detail}.");

    private static readonly Action<ILogger, Exception?> LogCompletedClean =
        LoggerMessage.Define(
            LogLevel.Information,
            new EventId(21, "UninstallTeardownCompleted"),
            "Uninstall teardown completed: protection disabled, browser-DoH policy reverted.");

    private readonly IProtectionOrchestrator _orchestrator;
    private readonly IBrowserDohPolicy _browserDoh;
    private readonly ILogger<UninstallTeardown> _logger;

    public UninstallTeardown(
        IProtectionOrchestrator orchestrator,
        IBrowserDohPolicy browserDoh,
        ILogger<UninstallTeardown> logger)
    {
        ArgumentNullException.ThrowIfNull(orchestrator);
        ArgumentNullException.ThrowIfNull(browserDoh);
        ArgumentNullException.ThrowIfNull(logger);
        _orchestrator = orchestrator;
        _browserDoh = browserDoh;
        _logger = logger;
    }

    /// <summary>Runs the full teardown. Returns 0 iff every step succeeded; 1 if any step failed
    /// (the remaining steps still ran — the MSI logs the code but does not abort the uninstall, the
    /// dumb fallback custom action mops up what is left).</summary>
    public int Run()
    {
        var allOk = true;

        // DisableProtection is itself ordered + continue-on-failure and is a no-op when protection
        // was never enabled (each step tolerates absent state).
        var disable = _orchestrator.DisableProtection();
        if (!disable.Success)
        {
            LogStepFailed(_logger, "DisableProtection", disable.Message ?? disable.Error.ToString(), null);
            allOk = false;
        }

        // The browser-DoH block is Settings-owned (not part of protection), so revert it explicitly.
        // SetBrowserDohPolicy(false) exact-reverts the Chrome/Edge/Firefox HKLM values from backup.
        var doh = _browserDoh.SetBrowserDohPolicy(false);
        if (!doh.Success)
        {
            LogStepFailed(_logger, "SetBrowserDohPolicy(false)", doh.Message ?? doh.Error.ToString(), null);
            allOk = false;
        }

        if (allOk) LogCompletedClean(_logger, null);
        return allOk ? 0 : 1;
    }
}
