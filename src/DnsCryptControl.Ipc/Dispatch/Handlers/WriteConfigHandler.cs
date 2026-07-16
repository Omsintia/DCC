using System.Linq;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// WriteConfig v2 (Phase 5b B4, IC-3 fail-closed ordering): payload-validate → parse →
/// catalog schema-check → OPSEC write policy → compare-and-swap store write. Every reject
/// path returns BEFORE the store is touched, so the on-disk config is provably unchanged
/// on rejection. The policy check is the server-side trust-boundary enforcement of
/// P5b-U1 (the UI's mirrored check is UX only); its refusal message reaches the UI
/// verbatim (IC-10). The CAS write (B2) makes a stale <c>BaseSha256</c> surface as
/// <see cref="IpcErrorCode.Conflict"/> instead of silently overwriting a concurrent
/// on-disk change.
/// </summary>
public sealed class WriteConfigHandler : ICommandHandler
{
    private readonly IConfigStore _store;
    private readonly IConfigWritePolicy _policy;

    public WriteConfigHandler(IConfigStore store, IConfigWritePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(policy);
        _store = store;
        _policy = policy;
    }

    public IpcCommandType Command => IpcCommandType.WriteConfig;

    public string Handle(IpcRequest request)
    {
        if (request.PayloadJson is null
            || IpcSerializer.DeserializePayload<WriteConfigPayload>(request.PayloadJson) is not { } payload
            || payload.TomlText is null
            || string.IsNullOrEmpty(payload.BaseSha256))
        {
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.ValidationFailed, "WriteConfig requires TomlText and BaseSha256."));
        }

        var doc = TomlConfigDocument.Parse(payload.TomlText);
        var report = ConfigValidator.Validate(doc);
        if (!report.IsValid)
        {
            var firstError = report.Issues.FirstOrDefault(i => i.Severity == ValidationSeverity.Error);
            var message = firstError is null
                ? "Configuration is invalid."
                : $"Invalid config: {firstError.KeyPath}: {firstError.Message}";
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.ValidationFailed, message));
        }

        // P5b-U1 save gate, consulted only for schema-clean candidates (IC-3 ordering) and
        // strictly before the store: a refusal maps InvalidArgument → ValidationFailed with
        // the "OPSEC guard: " message shown verbatim by the UI (IC-10). Conflict stays
        // reserved for the CAS race below, never for a policy refusal.
        var check = _policy.Check(payload.TomlText);
        if (!check.Success)
        {
            return IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(check.Error), check.Message ?? "config write refused"));
        }

        var write = _store.WriteConfigIfBaseMatches(payload.TomlText, payload.BaseSha256);
        return write.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(write.Error), write.Message ?? "config write failed"));
    }
}
