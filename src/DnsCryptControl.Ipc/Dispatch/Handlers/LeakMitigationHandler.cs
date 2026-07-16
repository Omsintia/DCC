using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>SetLeakMitigations: toggles the SMHNR + parallel-A/AAAA registry mitigations via
/// ILeakMitigationPolicy and reports whether a reboot is recommended for the change to fully apply.
/// A missing/invalid payload is rejected as ValidationFailed and the policy is never touched. Intent
/// is persisted AFTER a successful policy call so recorded state always matches reality.</summary>
public sealed class LeakMitigationHandler : ICommandHandler
{
    private readonly ILeakMitigationPolicy _policy;
    private readonly IProtectionStateWriter _protectionWriter;

    public LeakMitigationHandler(ILeakMitigationPolicy policy, IProtectionStateWriter protectionWriter)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(protectionWriter);
        _policy = policy;
        _protectionWriter = protectionWriter;
    }

    public IpcCommandType Command => IpcCommandType.SetLeakMitigations;

    public string Handle(IpcRequest request)
    {
        if (request.PayloadJson is null
            || IpcSerializer.DeserializePayload<SetTogglePayload>(request.PayloadJson) is not { } payload)
        {
            return IpcSerializer.SerializePayload(
                Result<LeakMitigationResponse>.Fail(IpcErrorCode.ValidationFailed,
                    "SetLeakMitigations requires an Enable payload."));
        }

        var op = _policy.SetLeakMitigations(payload.Enable);
        if (!op.Success)
        {
            return IpcSerializer.SerializePayload(
                Result<LeakMitigationResponse>.Fail(
                    PlatformResultMapping.ToIpc(op.Error), op.Message ?? "leak mitigation toggle failed"));
        }

        var intent = _protectionWriter.SetLeakMitigationsEnabled(payload.Enable);
        if (!intent.Success)
            return IpcSerializer.SerializePayload(
                Result<LeakMitigationResponse>.Fail(
                    PlatformResultMapping.ToIpc(intent.Error), intent.Message ?? "record leak-mitigation intent failed"));

        var response = new LeakMitigationResponse(
            Enabled: payload.Enable,
            RebootRecommended: op.Value == RebootAdvisory.Recommended);
        return IpcSerializer.SerializePayload(Result<LeakMitigationResponse>.Ok(response));
    }
}
