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
    public const int Version = 4;
}
