using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>ApplyDnsToAllAdapters: pins every eligible network interface to the loopback proxy
/// (127.0.0.1 + ::1) statically, capturing prior DNS into the backup. Carries no payload; returns
/// the non-generic Result. Fails closed by recording protection intent BEFORE applying loopback so
/// a crash mid-apply still re-asserts on boot; denies the apply entirely if intent cannot be persisted.</summary>
public sealed class ApplyDnsToAllAdaptersHandler : ICommandHandler
{
    private readonly IDnsAdapterConfigurator _configurator;
    private readonly IProtectionStateWriter _protectionWriter;

    public ApplyDnsToAllAdaptersHandler(IDnsAdapterConfigurator configurator, IProtectionStateWriter protectionWriter)
    {
        ArgumentNullException.ThrowIfNull(configurator);
        ArgumentNullException.ThrowIfNull(protectionWriter);
        _configurator = configurator;
        _protectionWriter = protectionWriter;
    }

    public IpcCommandType Command => IpcCommandType.ApplyDnsToAllAdapters;

    public string Handle(IpcRequest request)
    {
        // Record intent BEFORE applying: a crash mid-apply must still re-assert loopback on boot (fail-closed).
        // If we cannot even persist intent, deny rather than apply without durable protection.
        var intent = _protectionWriter.EnableProtection();
        if (!intent.Success)
            return IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(intent.Error), intent.Message ?? "record protection intent failed"));

        // If the apply fails after this, ProtectionEnabled stays true on purpose: boot re-asserts (fail-closed).
        var op = _configurator.ApplyLoopbackToAllAdapters();
        return op.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(op.Error), op.Message ?? "apply DNS failed"));
    }
}

/// <summary>RestoreDns: replays the per-interface DNS backup (prior static servers, or revert to
/// DHCP/automatic if it was DHCP) on every modified adapter, then clears the interface slice.
/// Carries no payload; returns the non-generic Result. This is the user's escape hatch. Intent is
/// cleared AFTER a confirmed restore so a crash mid-restore still re-asserts loopback on boot (fail-closed).</summary>
public sealed class RestoreDnsHandler : ICommandHandler
{
    private readonly IDnsAdapterConfigurator _configurator;
    private readonly IProtectionStateWriter _protectionWriter;

    public RestoreDnsHandler(IDnsAdapterConfigurator configurator, IProtectionStateWriter protectionWriter)
    {
        ArgumentNullException.ThrowIfNull(configurator);
        ArgumentNullException.ThrowIfNull(protectionWriter);
        _configurator = configurator;
        _protectionWriter = protectionWriter;
    }

    public IpcCommandType Command => IpcCommandType.RestoreDns;

    public string Handle(IpcRequest request)
    {
        // Restore first; only clear intent AFTER a confirmed restore so a crash mid-restore re-asserts (fail-closed).
        var op = _configurator.RestoreDns();
        if (!op.Success)
            return IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(op.Error), op.Message ?? "restore DNS failed"));

        var intent = _protectionWriter.DisableProtection();
        return intent.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(intent.Error), intent.Message ?? "clear protection intent failed"));
    }
}
