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

/// <summary>GetDnsAttributions cursor (v1.3.0): return only ring entries with
/// <c>Seq &gt; AfterSeq</c> — the UI passes back the last <see cref="DnsAttributionBatch.LastSeq"/>
/// so each attribution crosses the pipe exactly once. A null/absent payload means
/// <c>AfterSeq = 0</c> (everything the ring still holds); the handler never rejects it —
/// this is a read-only verb with nothing to validate.</summary>
public sealed record DnsAttributionsPayload(long AfterSeq);

/// <summary>One GetDnsAttributions read: the ring's current high-water sequence number (the
/// caller's next-poll cursor, advanced even when the matching entries were already evicted so a
/// slow poller skips ahead instead of replaying) plus the entries newer than the caller's cursor,
/// oldest → newest.</summary>
public sealed record DnsAttributionBatch(long LastSeq, IReadOnlyList<DnsAttributionEntry> Entries);

/// <summary>One attributed DNS lookup on the wire (mirrors <c>Platform.DnsAttributionRecord</c>
/// field-for-field, keeping the wire contract decoupled from the Platform type): the ETW header's
/// originating <paramref name="ProcessId"/> plus the queried name, with the process image name
/// resolved AT CAPTURE (PIDs are reused; a later lookup could name the wrong process) —
/// <paramref name="ProcessName"/> is null when the process had already exited. Best-effort
/// observability data, never trust-bearing.</summary>
/// <param name="Seq">The ring sequence number (the per-entry cursor position).</param>
/// <param name="UnixTimeMs">Capture time (Unix milliseconds, UTC) for time-window correlation.</param>
/// <param name="ProcessId">The originating process's PID from the ETW event header.</param>
/// <param name="QueryName">The looked-up name, verbatim from the event payload.</param>
/// <param name="ProcessName">The image name resolved at capture, or null if the process had exited.</param>
public sealed record DnsAttributionEntry(
    long Seq, long UnixTimeMs, int ProcessId, string QueryName, string? ProcessName);
