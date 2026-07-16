namespace DnsCryptControl.Platform;

/// <summary>
/// Controls the <c>dnscrypt-proxy</c> Windows service. Concrete impl runs as SYSTEM
/// and uses System.ServiceProcess.ServiceController plus the proxy's own
/// <c>-service install|uninstall|start|stop|restart</c> CLI (absolute path, ArgumentList).
/// Defined as an interface so handlers are unit-testable with a fake.
/// </summary>
public interface IProxyServiceController
{
    /// <summary>Current lifecycle state, or NotInstalled if the service is absent.</summary>
    PlatformResult<ProxyServiceState> GetState();

    /// <summary>Register the service from the pinned binary in the protected dir.</summary>
    PlatformResult Install();

    /// <summary>Stop (if running) and remove the service definition.</summary>
    PlatformResult Uninstall();

    /// <summary>Start the service and wait (bounded) for Running.</summary>
    PlatformResult Start();

    /// <summary>Stop the service and wait (bounded) for Stopped.</summary>
    PlatformResult Stop();

    /// <summary>Stop then start (or start if stopped); waits (bounded) for Running.</summary>
    PlatformResult Restart();
}
