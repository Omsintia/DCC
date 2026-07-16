using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Ipc.Security;
using DnsCryptControl.Ipc.Transport;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Supplychain;
using DnsCryptControl.Service.Windows;
using DnsCryptControl.Service.Windows.Registry;

namespace DnsCryptControl.Service;

/// <summary>Composition root for the DnsCryptControl helper service. Exposed as a static
/// class so the test suite can build the object graph without starting the Windows service
/// host (no SCM, no pipe listen).</summary>
internal static class ServiceComposition
{
    // Publisher allow-list thumbprint(s). Populated at build/sign time; placeholder here.
    // Exposed as public so Program.cs can check for placeholder values at startup and emit
    // a warning via ILogger (reaches the Windows Event Log under AddWindowsService).
    public static readonly IReadOnlyList<string> AllowedSignerThumbprints = new[]
    {
        "REPLACE_WITH_OUR_AUTHENTICODE_THUMBPRINT",
    };

    /// <summary>Registers all production services into <paramref name="services"/>.
    /// <paramref name="resolveInteractiveUser"/> is called on every pipe accept-loop iteration to
    /// resolve the currently-active interactive user's SID (or null if none is active yet); the pipe
    /// DACL is rebuilt from its result each iteration (see <see cref="IpcPipeServer"/>). At runtime it
    /// is <see cref="ConsoleSessionUser.TryResolveActiveInteractiveUser"/>; tests pass a fixed lambda.
    /// Annotated 19041+ because it constructs <see cref="Windows.WindowsDnsAdapterConfigurator"/>,
    /// which wraps the Win10 19041 DNS adapter API; callers guard with
    /// <c>OperatingSystem.IsWindowsVersionAtLeast(10,0,19041)</c>.</summary>
    [SupportedOSPlatform("windows10.0.19041")]
    public static void ConfigureServices(IServiceCollection services, Func<SecurityIdentifier?> resolveInteractiveUser)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(resolveInteractiveUser);

        var paths = ProtectedPaths.Default();
        var proxyExe = paths.ProxyExeFile;

        services.AddSingleton(paths);
        services.AddSingleton<IConfigStore>(new FileSystemConfigStore(paths));

        // Proxy controller is exposed ONLY through the integrity-gating decorator so the verified-binary
        // state dominates every launch. The real controller is constructed INSIDE the decorator factory and
        // is NOT registered as a resolvable service — so no other code can GetRequiredService the concrete
        // controller and bypass the launch-time gate. The IProxyServiceController everyone resolves is the
        // decorator wrapping the real controller + the integrity gate.
        services.AddSingleton<IProxyServiceController>(sp =>
            new IntegrityGatedProxyServiceController(
                new WindowsProxyServiceController(proxyExe),
                sp.GetRequiredService<BinaryIntegrityGate>(),
                sp.GetRequiredService<IConfigStore>(),
                sp.GetRequiredService<ILogger<IntegrityGatedProxyServiceController>>()));

        services.AddSingleton(new SignerAllowList(AllowedSignerThumbprints));
        services.AddSingleton<ICallerVerifier>(sp =>
            new WinVerifyTrustCallerVerifier(sp.GetRequiredService<SignerAllowList>()));

        // -----------------------------------------------------------------------------------
        // Phase 3 state stores (atomic + ACL'd JSON under %ProgramData%\DnsCryptControl\state\).
        // ONE shared instance each: the backup store is read/written by every OPSEC subsystem;
        // the protection-state store is shared by the boot reconciler + network-change watcher.
        // -----------------------------------------------------------------------------------
        services.AddSingleton(new DnsBackupStore(paths.BackupFile));
        services.AddSingleton(new ProtectionStateStore(paths.ProtectionStateFile));
        services.AddSingleton<IProtectionStateWriter>(sp =>
            new ProtectionStateWriter(sp.GetRequiredService<ProtectionStateStore>()));

        // Stateless HKLM 64-bit registry seam — one shared singleton (leak / browser / diagnostics).
        services.AddSingleton<IRegistryRoot>(new Registry64Root());

        // Firewall backend: COM primary with a netsh fallback for the mutating paths (D2 composite).
        services.AddSingleton<IFirewallRuleStore>(new ComOrNetshFirewallRuleStore());

        // Off-53 safety guard gating the kill switch (reads the active dnscrypt-proxy.toml).
        services.AddSingleton<IProxyConfigSafetyCheck>(new TomlProxyConfigSafetyCheck(paths));

        // -----------------------------------------------------------------------------------
        // Phase 3 OPSEC subsystems (the only place with P/Invoke / COM / Registry / CIM).
        // -----------------------------------------------------------------------------------
        services.AddSingleton<IDnsAdapterConfigurator>(sp =>
            new WindowsDnsAdapterConfigurator(sp.GetRequiredService<DnsBackupStore>()));
        services.AddSingleton<ILeakMitigationPolicy>(sp =>
            new RegistryLeakMitigationPolicy(
                sp.GetRequiredService<IRegistryRoot>(),
                sp.GetRequiredService<DnsBackupStore>()));
        services.AddSingleton<IFirewallKillSwitch>(sp =>
            new FirewallKillSwitch(
                sp.GetRequiredService<IFirewallRuleStore>(),
                sp.GetRequiredService<DnsBackupStore>(),
                sp.GetRequiredService<IProxyConfigSafetyCheck>()));
        services.AddSingleton<IBrowserDohPolicy>(sp =>
            new BrowserDohPolicy(
                sp.GetRequiredService<IRegistryRoot>(),
                sp.GetRequiredService<DnsBackupStore>()));
        services.AddSingleton<IDnsCacheFlusher>(new CimDnsCacheFlusher());
        services.AddSingleton<IDiagnosticsProbe>(sp =>
            new WindowsDiagnosticsProbe(
                sp.GetRequiredService<IFirewallKillSwitch>(),
                sp.GetRequiredService<IBrowserDohPolicy>(),
                sp.GetRequiredService<IRegistryRoot>()));

        // -----------------------------------------------------------------------------------
        // Phase 4 supply chain: minisign verifier + verify/install orchestration + launch gate.
        // BouncyCastle lives ONLY in this assembly (IC-11).
        // -----------------------------------------------------------------------------------
        services.AddSingleton(new InstalledBinaryRecordStore(paths.InstalledBinaryRecordFile));
        // MinisignVerifier.Verify is static (stateless; pinned key passed as a param) — not registered/injected.
        services.AddSingleton<IBinaryVerifyInstaller>(sp =>
            new BinaryVerifyInstaller(
                paths,
                sp.GetRequiredService<IProxyServiceController>(),
                sp.GetRequiredService<InstalledBinaryRecordStore>()));
        services.AddSingleton(sp =>
            new BinaryIntegrityGate(paths, sp.GetRequiredService<InstalledBinaryRecordStore>()));

        // Phase 5a (BE-8): the atomic master-toggle enable/disable orchestrator backing
        // EnableProtection/DisableProtection. Reuses BootReconciler's leak-safe invariants.
        services.AddSingleton<IProtectionOrchestrator, ProtectionOrchestrator>();

        // Phase 6 (packaging, IC-PKG): the `--teardown` CLI mode's fail-safe uninstall revert —
        // DisableProtection + the browser-DoH policy revert via the same tested singletons above.
        services.AddSingleton<UninstallTeardown>();

        // Phase 5b (B4): the OPSEC-aware save gate for WriteConfig v2 (P5b-U1) — server-side
        // trust-boundary enforcement over the SHARED ProtectionStateStore singleton (the UI's
        // mirrored check is UX only and never replaces it).
        services.AddSingleton<IConfigWritePolicy, ProtectionAwareConfigWritePolicy>();

        services.AddSingleton(sp => new CommandDispatcher(HandlerRegistry.Build(
            sp.GetRequiredService<IProxyServiceController>(),
            sp.GetRequiredService<IConfigStore>(),
            sp.GetRequiredService<IDnsAdapterConfigurator>(),
            sp.GetRequiredService<ILeakMitigationPolicy>(),
            sp.GetRequiredService<IFirewallKillSwitch>(),
            sp.GetRequiredService<IBrowserDohPolicy>(),
            sp.GetRequiredService<IDnsCacheFlusher>(),
            sp.GetRequiredService<IDiagnosticsProbe>(),
            sp.GetRequiredService<IProtectionStateWriter>(),
            sp.GetRequiredService<IBinaryVerifyInstaller>(),
            sp.GetRequiredService<IProtectionOrchestrator>(),
            sp.GetRequiredService<IConfigWritePolicy>())));

        services.AddSingleton(sp => new IpcPipeServer(
            sp.GetRequiredService<CommandDispatcher>(),
            sp.GetRequiredService<ICallerVerifier>(),
            resolveInteractiveUser,
            PipeNames.Helper,
            NativeMethods.ResolveClient));

        // Boot reconciliation (fail-closed + auto-recover) — resolved and invoked from Program.cs.
        services.AddSingleton(sp => new BootReconciler(
            sp.GetRequiredService<ProtectionStateStore>(),
            sp.GetRequiredService<IDnsAdapterConfigurator>(),
            sp.GetRequiredService<IFirewallKillSwitch>(),
            sp.GetRequiredService<ILeakMitigationPolicy>(),
            sp.GetRequiredService<IProxyServiceController>(),
            sp.GetRequiredService<IConfigStore>(),
            sp.GetRequiredService<ILogger<BootReconciler>>()));

        services.AddHostedService<PipeServerWorker>();
        // Sticky-DNS watcher — registered ONCE (it uses a static [UnmanagedCallersOnly] callback slot).
        services.AddHostedService<NetworkChangeWatcher>();
    }
}
