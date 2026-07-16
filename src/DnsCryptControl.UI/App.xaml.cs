using System;
using System.Collections.Generic;
using System.Threading;
using System.Windows;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;
using DnsCryptControl.UI.Views;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DnsCryptControl.UI;

public partial class App : Application, IDisposable
{
    private IHost? _host;
    private SingleInstanceGuard? _guard;
    private bool _disposed;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _guard = new SingleInstanceGuard();
        if (!_guard.IsFirstInstance)
        {
            _guard.SignalExistingInstance();
            Shutdown();
            return; // _host stays null; OnExit becomes a no-op for the host.
        }

        try
        {
            var builder = Host.CreateApplicationBuilder();
            builder.Services.AddSingleton<IUiDispatcher, WpfDispatcher>();
            builder.Services.AddSingleton<IHelperClient, HelperClient>();
            builder.Services.AddSingleton<IProtectionStateReader, ProtectionStateReader>();
            // C1 registers its services here.
            builder.Services.AddSingleton<IActiveResolverReader, ActiveResolverReader>();
            builder.Services.AddSingleton<IConfigFileService, ConfigFileService>();
            // Phase 5c (Group D): the Resolvers + Anonymized DNS tabs and the services they need.
            builder.Services.AddSingleton<IResolverListReader, ResolverListReader>();
            builder.Services.AddSingleton<IUiStateStore, UiStateStore>();
            builder.Services.AddSingleton<IProbeGate, AlwaysOnlineProbeGate>();
            builder.Services.AddSingleton<ILatencyProber, TcpConnectProber>();
            // Phase 5d (Group D): the Filtering tab, its rule-file service, and the six family codecs.
            builder.Services.AddSingleton<IRuleFileService, RuleFileService>();
            builder.Services.AddSingleton<IReadOnlyList<IRuleFamilyCodec>>(_ => new IRuleFamilyCodec[]
            {
                new NameRuleFamilyCodec(RuleFileKind.BlockedNames),
                new NameRuleFamilyCodec(RuleFileKind.AllowedNames),
                new IpRuleFamilyCodec(RuleFileKind.BlockedIps),
                new IpRuleFamilyCodec(RuleFileKind.AllowedIps),
                new CloakRuleFamilyCodec(),
                new ForwardRuleFamilyCodec(),
            });
            // Phase 5e (Group D): the Query Monitor (read-and-shred query-log tail) + Logs & Diagnostics
            // tabs. The reader defaults to the per-user %LOCALAPPDATA% query.log (IC-QM3); the poller
            // marshals ticks onto the UI thread; nothing here touches the privileged wire (IC-2).
            builder.Services.AddSingleton<IQueryLogReader>(_ => new QueryLogReader());
            builder.Services.AddSingleton<IQueryPoller, PeriodicTimerQueryPoller>();
            builder.Services.AddSingleton<ILogTailReader, LogTailReader>();
            // Phase 5f (Settings): theme applier, startup registration (HKCU Run), offline integrity reader.
            builder.Services.AddSingleton<IThemeApplier, WpfThemeApplier>();
            builder.Services.AddSingleton<IRunKeyAccess, HkcuRunKeyAccess>();
            builder.Services.AddSingleton<IStartupRegistration, StartupRegistration>();
            builder.Services.AddSingleton<IExeIntegrityReader, ExeIntegrityReader>();
            builder.Services.AddSingleton<DashboardViewModel>();
            builder.Services.AddSingleton<ConfigurationViewModel>();
            builder.Services.AddSingleton<ResolversViewModel>();
            builder.Services.AddSingleton<AnonymizedDnsViewModel>();
            builder.Services.AddSingleton<FilteringViewModel>();
            builder.Services.AddSingleton<QueryMonitorViewModel>();
            // Phase 5i: the QueryMonitorViewModel IS the shared per-session query-log source; the Dashboard
            // reads live counts + recent queries from it via IQueryLogSession (one shredder, one buffer).
            builder.Services.AddSingleton<IQueryLogSession>(sp => sp.GetRequiredService<QueryMonitorViewModel>());
            builder.Services.AddSingleton<LogsDiagnosticsViewModel>();
            builder.Services.AddSingleton<SettingsViewModel>();
            builder.Services.AddSingleton<MainWindowViewModel>();
            builder.Services.AddSingleton<MainWindow>();
            _host = builder.Build();
            _host.Start(); // synchronous start; DI is ready

            // Phase 5f: MainWindow applies the persisted theme in its ctor (with the window attached so the
            // applier coordinates SystemThemeWatcher). Applying it HERE, before the window exists, fought the
            // watcher and left default-foreground text invisible across every tab.
            _host.Services.GetRequiredService<MainWindow>().Show();
            // Phase 5f: a second launch must RESTORE a tray-hidden window, not just Activate() it (a bare
            // Activate on a hidden window silently no-ops). ShowFromTray does Show + un-minimise + focus.
            // Guarded: a late activation during/after shutdown invokes on an aborting dispatcher
            // (OperationCanceledException) on a threadpool thread — unguarded that would crash the process.
            _guard.WaitForActivation(() =>
            {
                try
                {
                    Dispatcher.Invoke(
                        () => (MainWindow as DnsCryptControl.UI.Views.MainWindow)?.ShowFromTray());
                }
                catch (Exception)
                {
                    // A second-instance activation racing shutdown must never crash the first instance.
                }
            });
        }
        catch (Exception)
        {
            // Clear the tray icon on a startup crash that already made it visible — the rethrow terminates
            // the process before OnExit runs, so the shell icon would otherwise linger.
            (MainWindow as DnsCryptControl.UI.Views.MainWindow)?.DisposeTrayIcon();
            Shutdown();
            throw; // async-void would swallow; keep sync + rethrow
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // WPF does not await OnExit — drive async disposal to completion synchronously.
        if (_host is not null)
        {
            // FIX HIGH-1 (per-session query logging): on a CLEAN exit, best-effort STOP the proxy writing
            // the query log before we tear the host down — so the closed-window during which the LocalSystem
            // proxy could keep appending browsing history is as small as possible. This is only a shrink of
            // that window: the real guarantee is InitializeAtLaunchAsync, which hard-resets logging OFF (and
            // purges) at the next launch regardless of how we exited. So this is bounded + fail-closed: a
            // slow or failed helper can never hang shutdown, and any fault is swallowed.
            try
            {
                var queryMonitor = _host.Services.GetService<QueryMonitorViewModel>();
                if (queryMonitor is { LoggingEnabled: true })
                {
                    using var disableCts = new CancellationTokenSource();
                    queryMonitor.DisableAsync(disableCts.Token).Wait(TimeSpan.FromSeconds(6));
                }
            }
            catch (Exception)
            {
                // Best-effort only — the launch-reset is the backstop. Never let a shutdown-time disable
                // failure escape OnExit.
            }

            _host.StopAsync().GetAwaiter().GetResult();
            ((IAsyncDisposable)_host).DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        // Phase 5f backstop: remove the WinForms tray icon even if the process wound down without routing
        // through the shown window's Closed handler. Idempotent + best-effort (a NotifyIcon needs an
        // explicit Dispose to clear the shell icon).
        try
        {
            (MainWindow as DnsCryptControl.UI.Views.MainWindow)?.DisposeTrayIcon();
        }
        catch (Exception)
        {
            // best-effort tray cleanup only
        }

        Dispose();

        base.OnExit(e);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _guard?.Dispose();
        GC.SuppressFinalize(this);
    }
}
