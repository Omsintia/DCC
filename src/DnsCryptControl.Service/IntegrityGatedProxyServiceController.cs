using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.Supplychain;

namespace DnsCryptControl.Service;

/// <summary>
/// Integrity-gating decorator over <see cref="IProxyServiceController"/>: the SINGLE enforcement point that
/// makes the verified-binary state DOMINATE every launch. Every consumer (BootReconciler, the
/// StartProxy/RestartProxy IPC handlers, the installer) resolves <see cref="IProxyServiceController"/> and
/// therefore goes through this gate. <see cref="Start"/>/<see cref="Restart"/> run the
/// <see cref="BinaryIntegrityGate"/> FIRST; on failure they log Critical and return Fail WITHOUT touching the
/// inner controller, so a tampered dnscrypt-proxy.exe is never launched as the SYSTEM DNS proxy.
/// <para>Being the single launch chokepoint, <see cref="Start"/>/<see cref="Restart"/> also seed the bundled
/// default source cache (<see cref="IConfigStore.EnsureDefaultSourceCaches"/>) after the integrity gate and
/// before the inner launch — so no start path (a UI config-apply restart, the dashboard restart, the
/// installer's post-install start) can launch the proxy against a config whose only source has no loadable
/// cache, which dnscrypt-proxy treats as FATAL under the shipped off-53 bootstrap (the fresh-install DNS
/// brick).</para>
/// <para><see cref="Stop"/>/<see cref="Uninstall"/>/<see cref="GetState"/> are NOT gated: tearing down or
/// querying a possibly-bad binary must always be permitted. <see cref="Install"/> re-verifies separately
/// (the installer records the hash before its own Start, so that Start re-verifies against the fresh record —
/// no circularity, the gate only reads files).</para>
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class IntegrityGatedProxyServiceController : IProxyServiceController
{
    private readonly IProxyServiceController _inner;
    private readonly BinaryIntegrityGate _gate;
    private readonly IConfigStore _configStore;
    private readonly ILogger<IntegrityGatedProxyServiceController> _logger;

    private static readonly Action<ILogger, string, string, Exception?> LogLaunchBlocked =
        LoggerMessage.Define<string, string>(LogLevel.Critical, new EventId(20, "ProxyLaunchBlocked"),
            "Refusing to {Operation} dnscrypt-proxy.exe: installed binary failed launch-time integrity " +
            "verification ({Reason}). The proxy will NOT be launched (fail-closed). Reinstall a verified binary.");

    public IntegrityGatedProxyServiceController(
        IProxyServiceController inner,
        BinaryIntegrityGate gate,
        IConfigStore configStore,
        ILogger<IntegrityGatedProxyServiceController> logger)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(configStore);
        ArgumentNullException.ThrowIfNull(logger);
        _inner = inner;
        _gate = gate;
        _configStore = configStore;
        _logger = logger;
    }

    /// <inheritdoc/>
    public PlatformResult Start() => Gate(nameof(Start), _inner.Start);

    /// <inheritdoc/>
    public PlatformResult Restart() => Gate(nameof(Restart), _inner.Restart);

    /// <summary>Verify integrity first, then seed the default source cache; only delegate to the
    /// inner launch when both succeed.</summary>
    private PlatformResult Gate(string operation, Func<PlatformResult> launch)
    {
        var integrity = _gate.Verify();
        if (!integrity.Success)
        {
            var reason = integrity.Message ?? "unknown";
            LogLaunchBlocked(_logger, operation, reason, null);
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                $"launch blocked: installed binary failed integrity verification ({reason})");
        }

        // Fail-closed like the integrity gate: launching without a loadable default cache is a
        // guaranteed post-start FATAL under the shipped config, so failing fast here is strictly
        // more honest than a start that "succeeds" and then dies.
        var seed = _configStore.EnsureDefaultSourceCaches();
        if (!seed.Success)
        {
            return PlatformResult.Fail(seed.Error,
                $"launch blocked: could not seed the default resolver-list cache ({seed.Message ?? "unknown"})");
        }

        return launch();
    }

    // Tear-down / query paths are intentionally NOT gated: a bad binary must still be stoppable,
    // removable, and queryable. Install re-verifies separately (records the hash before its own Start).
    /// <inheritdoc/>
    public PlatformResult Stop() => _inner.Stop();

    /// <inheritdoc/>
    public PlatformResult Install() => _inner.Install();

    /// <inheritdoc/>
    public PlatformResult Uninstall() => _inner.Uninstall();

    /// <inheritdoc/>
    public PlatformResult<ProxyServiceState> GetState() => _inner.GetState();
}
