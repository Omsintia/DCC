using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Tests;

internal sealed class FakeProxyServiceController : IProxyServiceController
{
    public ProxyServiceState State { get; set; } = ProxyServiceState.Stopped;
    public List<string> Calls { get; } = new();
    public PlatformErrorKind? FailWith { get; set; }
    public bool FailGetState { get; set; }

    private PlatformResult Run(string op, ProxyServiceState onSuccess)
    {
        Calls.Add(op);
        if (FailWith is { } kind) return PlatformResult.Fail(kind, $"{op} failed");
        State = onSuccess;
        return PlatformResult.Ok();
    }

    public PlatformResult<ProxyServiceState> GetState()
    {
        Calls.Add(nameof(GetState));
        return FailGetState
            ? PlatformResult<ProxyServiceState>.Fail(PlatformErrorKind.OperationFailed, "query failed")
            : PlatformResult<ProxyServiceState>.Ok(State);
    }

    public PlatformResult Install() => Run(nameof(Install), ProxyServiceState.Stopped);
    public PlatformResult Uninstall() => Run(nameof(Uninstall), ProxyServiceState.NotInstalled);
    public PlatformResult Start() => Run(nameof(Start), ProxyServiceState.Running);
    public PlatformResult Stop() => Run(nameof(Stop), ProxyServiceState.Stopped);
    public PlatformResult Restart() => Run(nameof(Restart), ProxyServiceState.Running);
}
