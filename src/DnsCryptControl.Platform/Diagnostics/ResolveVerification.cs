namespace DnsCryptControl.Platform.Diagnostics;

/// <summary>Result of the on-demand upstream-resolution verification (the post-apply route check):
/// whether ONE real, randomly-labelled name under a delegated zone resolved through the loopback
/// proxy within the probe's retry budget. Unlike <see cref="ActiveResolveCheck"/> (whose
/// undelegated .test self-check name is answered LOCALLY by dnscrypt-proxy's block_undelegated and
/// therefore only proves listener liveness), <see cref="Resolved"/>=true proves the query egressed
/// through the proxy's CONFIGURED ROUTE and came back — a structurally-valid but dead
/// anonymized-DNS route yields <see cref="Resolved"/>=false. <see cref="ElapsedMs"/> is the total
/// time across all attempts; <see cref="Detail"/> carries the last attempt's RCODE/timeout note.</summary>
public sealed record ResolveVerification(bool Resolved, int ElapsedMs, string Detail);
