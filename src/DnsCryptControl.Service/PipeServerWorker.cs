using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using DnsCryptControl.Ipc.Transport;

namespace DnsCryptControl.Service;

/// <summary>BackgroundService that drives the ACL'd named-pipe accept loop for the lifetime
/// of the Windows service.</summary>
[SupportedOSPlatform("windows")]
public sealed class PipeServerWorker : BackgroundService
{
    private readonly IpcPipeServer _server;

    public PipeServerWorker(IpcPipeServer server)
    {
        ArgumentNullException.ThrowIfNull(server);
        _server = server;
    }

    // Note: IpcPipeServer implements IAsyncDisposable. The generic host's DI container calls
    // DisposeAsync on all registered singletons during shutdown, so IpcPipeServer is disposed
    // correctly without any explicit disposal here. Do NOT add a redundant dispose call.
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _server.RunAsync(stoppingToken);
}
