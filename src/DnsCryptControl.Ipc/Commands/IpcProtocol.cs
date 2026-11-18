namespace DnsCryptControl.Ipc.Commands;

/// <summary>Version handshake constant (F20): the UI compares this against the
/// helper-reported <c>StatusResponse.ProtocolVersion</c> to detect a UI/helper
/// version mismatch before trusting any other field in the response.</summary>
public static class IpcProtocol
{
    // v2 (Phase 5b, P5b-E1): WriteConfigPayload gained a required BaseSha256 — a v1
    // helper would silently ignore it (no CAS, no OPSEC write policy), so mixed pairs
    // must be refused by the handshake instead of failing open on the save path.
    //
    // v3 (post-5j ODoH fix): added the PlaceOdohCache verb (the helper places bundled,
    // minisign-signed ODoH source caches so the proxy never does the fatal boot-time
    // download). A v2 helper lacks the verb and would answer UnsupportedHandler; the
    // handshake refuses a mixed pair up front so the UI never issues a verb the helper
    // can't honour. This ends the Phase-5x "frozen wire" discipline (deliberate, reviewed).
    //
    // v4 (v1.2.0, FIX #1): added the VerifyResolution verb (post-apply real-name resolve
    // check — the local .test self-check false-greens on a dead anonymized route). Additive,
    // same mixed-pair rationale as v3: a v3 helper would answer UnsupportedHandler, so the
    // handshake refuses the pair up front.
    //
    // v5 (v1.3.0): the FRAMING contract changed — IpcSerializer.MaxBytes rose 1 MiB → 16 MiB
    // so a big community blocklist fits one WriteRuleFile request. Not additive: a v4 helper
    // would silently REJECT a legal v5 frame at the transport (a lost reply, indistinguishable
    // from a dead helper), so mixed pairs must be refused by the handshake, not left to fail
    // confusingly on the first large save — BOTH write paths (ConfigFileService.SaveAndApplyAsync
    // and RuleFileService.WriteRuleFileAsync) run the pre-write GetStatus version compare and
    // refuse a mixed pair before sending. v5 ALSO carries the GetDnsAttributions verb (per-app
    // query attribution — the Query Monitor's App column): both shipped in the same release, so
    // the verb RIDES the framing bump rather than costing a v6 of its own.
    public const int Version = 5;
}
