namespace DnsCryptControl.Ipc.Commands;

/// <summary>Envelope: a command plus an optional JSON-encoded payload (one of the
/// payload records below). Kept flat and string-typed so the serializer never has to
/// resolve polymorphic types from the wire (CWE-502 hardening).</summary>
public sealed record IpcRequest(IpcCommandType Command, string? PayloadJson);

/// <summary>BE-6 optimistic concurrency: <c>BaseSha256</c> is the REQUIRED lowercase-hex
/// SHA-256 of the on-disk config file BYTES the editor loaded (IC-9); the helper refuses
/// the write with <c>IpcErrorCode.Conflict</c> when the current file no longer matches.</summary>
public sealed record WriteConfigPayload(string TomlText, string BaseSha256);
public sealed record WriteRuleFilePayload(string Kind, string Content);
public sealed record SetTogglePayload(bool Enable);
public sealed record VerifyAndInstallBinaryPayload(string TempPath, string ExpectedTag);

public sealed record StatusResponse(
    bool ProxyRunning,
    string? ActiveResolver,
    bool KillSwitchEnabled,
    bool LeakMitigationsEnabled,
    int ProtocolVersion,
    string HelperBuild);

/// <summary>Response carrying the proxy service's lifecycle state as a string
/// (the name of <c>Platform.ProxyServiceState</c>), keeping the wire contract decoupled
/// from the enum's numeric layout.</summary>
public sealed record ServiceLifecycleResponse(string State);

/// <summary>Result of a leak-mitigation toggle: whether a reboot is recommended for it to fully apply.</summary>
public sealed record LeakMitigationResponse(bool Enabled, bool RebootRecommended);

public sealed record EnableProtectionPayload(bool WithKillSwitch);

/// <summary>Outcome of the atomic helper-owned enable/disable protection operation (BE-8).</summary>
public sealed record ProtectionResponse(
    bool ProtectionEnabled,
    bool KillSwitchEnabled,
    bool LeakMitigationsEnabled,
    bool RebootRecommended,
    string? KillSwitchAdvisory);
