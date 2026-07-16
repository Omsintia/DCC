using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// WriteRuleFile: parses the untrusted Kind string into the closed RuleFileKind enum (the
/// string never becomes a path component — CWE-22 closed by construction), line-validates
/// the content (per-line length cap, no embedded NUL), then delegates the SafePath-confined
/// atomic write + backup to IConfigStore.
/// </summary>
public sealed class WriteRuleFileHandler : ICommandHandler
{
    private const int MaxLineLength = 4096;
    private readonly IConfigStore _store;

    public WriteRuleFileHandler(IConfigStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    public IpcCommandType Command => IpcCommandType.WriteRuleFile;

    public string Handle(IpcRequest request)
    {
        if (request.PayloadJson is null
            || IpcSerializer.DeserializePayload<WriteRuleFilePayload>(request.PayloadJson) is not { } payload
            || payload.Kind is null || payload.Content is null)
        {
            return Fail("WriteRuleFile requires Kind and Content.");
        }

        // Reject numeric ordinals (e.g. "0", "6"): only exact RuleFileKind member names are valid;
        // TryParse would otherwise accept the underlying integer value.
        if (int.TryParse(payload.Kind, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out _))
            return Fail($"Unknown rule-file kind '{payload.Kind}'.");

        if (!System.Enum.TryParse<RuleFileKind>(payload.Kind, ignoreCase: true, out var kind)
            || !System.Enum.IsDefined(kind))
        {
            return Fail($"Unknown rule-file kind '{payload.Kind}'.");
        }

        if (payload.Content.Contains('\0', System.StringComparison.Ordinal))
            return Fail("Rule content may not contain NUL.");

        foreach (var line in payload.Content.Split('\n'))
        {
            if (line.TrimEnd('\r').Length > MaxLineLength)
                return Fail($"A rule line exceeds the {MaxLineLength}-character cap.");
        }

        var write = _store.WriteRuleFile(kind, payload.Content);
        return write.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(write.Error), write.Message ?? "rule write failed"));
    }

    private static string Fail(string message) =>
        IpcSerializer.SerializePayload(Result.Fail(IpcErrorCode.ValidationFailed, message));
}
