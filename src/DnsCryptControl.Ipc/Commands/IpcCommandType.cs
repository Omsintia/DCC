namespace DnsCryptControl.Ipc.Commands;

/// <summary>
/// The complete, fixed privileged-operation vocabulary the helper service exposes
/// (design spec §5.4). There is deliberately no generic "run" verb.
/// </summary>
public enum IpcCommandType
{
    GetStatus,
    InstallProxyService,
    UninstallProxyService,
    StartProxy,
    StopProxy,
    RestartProxy,
    WriteConfig,
    WriteRuleFile,
    ApplyDnsToAllAdapters,
    RestoreDns,
    SetLeakMitigations,
    SetKillSwitch,
    SetBrowserDohPolicy,
    FlushDnsCache,
    VerifyAndInstallBinary,
    RunDiagnostics,
    EnableProtection,
    DisableProtection,

    /// <summary>Places the helper's bundled, minisign-signed ODoH source-list cache files
    /// (odoh-servers.md/.minisig, odoh-relays.md/.minisig) into the proxy's protected dir,
    /// byte-exact. This lets the proxy load ODoH sources FROM CACHE at startup instead of
    /// attempting the boot-time download that dnscrypt-proxy treats as FATAL when it can't
    /// resolve the list URL yet (the bootstrap chicken-and-egg) — which otherwise bricks the
    /// whole proxy. No payload; non-generic <see cref="Result"/> response.</summary>
    PlaceOdohCache,

    /// <summary>Resolves ONE random real-delegated name (&lt;8-hex&gt;.example.com) through the
    /// loopback proxy to prove the CONFIGURED UPSTREAM ROUTE actually resolves (protocol v4).
    /// The continuous RunDiagnostics self-check queries an undelegated .test name that
    /// dnscrypt-proxy answers LOCALLY (block_undelegated), so it false-greens on a
    /// structurally-valid but DEAD anonymized route — this verb is the honest post-apply check.
    /// Bounded (≤ ~5 s in the helper, inside the 30 s client cap); invoked by the UI only after
    /// an explicit Save &amp; apply, never on the badge poll. No payload;
    /// <c>Result&lt;ResolveVerification&gt;</c> response (a dead route is Success=true with
    /// Resolved=false — Fail means the probe itself could not run).</summary>
    VerifyResolution,
}
