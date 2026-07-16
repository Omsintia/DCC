using System.Collections.Generic;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// Verifies the B1/C1/F2 DI wiring (the same registrations <c>App.OnStartup</c> makes)
/// resolves headlessly. Deliberately does NOT register or resolve <c>MainWindow</c>
/// (a <c>FluentWindow</c>/<c>DispatcherObject</c>) since xUnit runs non-STA.
/// </summary>
public class HostWiringTests
{
    /// <summary>
    /// The full App service graph, exactly as <c>App.OnStartup</c> wires it (minus
    /// <c>MainWindow</c>) — proves <see cref="IHelperClient"/>,
    /// <see cref="IProtectionStateReader"/>, <see cref="IActiveResolverReader"/>,
    /// <see cref="IConfigFileService"/>, and <see cref="IUiDispatcher"/> all resolve
    /// end-to-end into <see cref="DashboardViewModel"/> and
    /// <see cref="ConfigurationViewModel"/> and, via constructor injection (C2/F2),
    /// into <see cref="MainWindowViewModel"/>. Uses the REAL <see cref="WpfDispatcher"/> —
    /// constructing it headlessly is safe; only its <c>Post</c> method touches
    /// <c>Application.Current</c>, which this test never calls.
    /// </summary>
    private static ServiceProvider BuildFullAppProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IUiDispatcher, WpfDispatcher>();
        services.AddSingleton<IHelperClient, HelperClient>();
        services.AddSingleton<IProtectionStateReader, ProtectionStateReader>();
        services.AddSingleton<IActiveResolverReader, ActiveResolverReader>();
        services.AddSingleton<IConfigFileService, ConfigFileService>();
        services.AddSingleton<IResolverListReader, ResolverListReader>();
        services.AddSingleton<IUiStateStore, UiStateStore>();
        services.AddSingleton<IProbeGate, AlwaysOnlineProbeGate>();
        services.AddSingleton<ILatencyProber, TcpConnectProber>();
        services.AddSingleton<IRuleFileService, RuleFileService>();
        services.AddSingleton<IReadOnlyList<IRuleFamilyCodec>>(_ => new IRuleFamilyCodec[]
        {
            new NameRuleFamilyCodec(RuleFileKind.BlockedNames),
            new NameRuleFamilyCodec(RuleFileKind.AllowedNames),
            new IpRuleFamilyCodec(RuleFileKind.BlockedIps),
            new IpRuleFamilyCodec(RuleFileKind.AllowedIps),
            new CloakRuleFamilyCodec(),
            new ForwardRuleFamilyCodec(),
        });
        // Phase 5e: the Query Monitor + Logs & Diagnostics services and view-models.
        services.AddSingleton<IQueryLogReader>(_ => new QueryLogReader());
        services.AddSingleton<IQueryPoller, PeriodicTimerQueryPoller>();
        services.AddSingleton<ILogTailReader, LogTailReader>();
        // Phase 5f (Settings): theme applier, startup registration, offline integrity reader.
        services.AddSingleton<IThemeApplier, WpfThemeApplier>();
        services.AddSingleton<IRunKeyAccess, HkcuRunKeyAccess>();
        services.AddSingleton<IStartupRegistration, StartupRegistration>();
        services.AddSingleton<IExeIntegrityReader, ExeIntegrityReader>();
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<ConfigurationViewModel>();
        services.AddSingleton<ResolversViewModel>();
        services.AddSingleton<AnonymizedDnsViewModel>();
        services.AddSingleton<FilteringViewModel>();
        services.AddSingleton<QueryMonitorViewModel>();
        // Phase 5i: the QueryMonitorViewModel IS the shared per-session query-log source the Dashboard reads.
        services.AddSingleton<IQueryLogSession>(sp => sp.GetRequiredService<QueryMonitorViewModel>());
        services.AddSingleton<LogsDiagnosticsViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<MainWindowViewModel>();
        return services.BuildServiceProvider();
    }

    [Fact]
    public void MainWindowViewModel_resolves()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<MainWindowViewModel>();

        Assert.NotNull(viewModel);
        Assert.NotNull(viewModel.Dashboard);
        Assert.NotNull(viewModel.Configuration);
        Assert.NotNull(viewModel.Resolvers);
        Assert.NotNull(viewModel.AnonymizedDns);
        Assert.NotNull(viewModel.Filtering);
        Assert.NotNull(viewModel.QueryMonitor);
        Assert.NotNull(viewModel.LogsDiagnostics);
        Assert.NotNull(viewModel.Settings);
    }

    /// <summary>Phase 5f: the Settings tab's view-model resolves from the full App graph, and the shell VM
    /// exposes the SAME singleton instance the graph holds (DataContext ≡ container).</summary>
    [Fact]
    public void SettingsViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<SettingsViewModel>();

        Assert.NotNull(viewModel);
        Assert.Same(viewModel, provider.GetRequiredService<MainWindowViewModel>().Settings);
    }

    /// <summary>Phase 5f: the Settings tab's services resolve to their production concretes from the full App graph.</summary>
    [Fact]
    public void Settings_services_resolve_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        Assert.IsType<StartupRegistration>(provider.GetRequiredService<IStartupRegistration>());
        Assert.IsType<HkcuRunKeyAccess>(provider.GetRequiredService<IRunKeyAccess>());
        Assert.IsType<ExeIntegrityReader>(provider.GetRequiredService<IExeIntegrityReader>());
    }

    /// <summary>Phase 5f: the Settings theme applier resolves to its production concrete from the full App graph.</summary>
    [Fact]
    public void IThemeApplier_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        Assert.IsType<WpfThemeApplier>(provider.GetRequiredService<IThemeApplier>());
    }

    [Fact]
    public void IUiDispatcher_resolves_to_WpfDispatcher()
    {
        var provider = BuildFullAppProvider();

        var dispatcher = provider.GetRequiredService<IUiDispatcher>();

        Assert.IsType<WpfDispatcher>(dispatcher);
    }

    [Fact]
    public void DashboardViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<DashboardViewModel>();

        Assert.NotNull(viewModel);
        Assert.IsType<HelperClient>(provider.GetRequiredService<IHelperClient>());
        Assert.IsType<ProtectionStateReader>(provider.GetRequiredService<IProtectionStateReader>());
        Assert.IsType<ActiveResolverReader>(provider.GetRequiredService<IActiveResolverReader>());
        Assert.IsType<WpfDispatcher>(provider.GetRequiredService<IUiDispatcher>());
    }

    /// <summary>D2: the Configuration editor's read/save path must resolve from the full
    /// App graph (its optional path/interval/timeout ctor params take their production
    /// defaults, exactly like <see cref="DashboardViewModel"/>'s poll interval).</summary>
    [Fact]
    public void IConfigFileService_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var service = provider.GetRequiredService<IConfigFileService>();

        Assert.IsType<ConfigFileService>(service);
    }

    /// <summary>F2: the Configuration tab's view-model resolves from the full App graph
    /// (its optional debounce-interval/validation-gate ctor params take their production
    /// defaults), and the shell VM exposes the SAME singleton instance the graph holds —
    /// the tab's DataContext and the DI container can never disagree.</summary>
    [Fact]
    public void ConfigurationViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<ConfigurationViewModel>();

        Assert.NotNull(viewModel);
        Assert.Same(viewModel, provider.GetRequiredService<MainWindowViewModel>().Configuration);
    }

    /// <summary>D1: the Resolvers tab's services all resolve to their production concretes from the
    /// full App graph (their optional ctor params take production defaults).</summary>
    [Fact]
    public void Resolvers_services_resolve_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        Assert.IsType<ResolverListReader>(provider.GetRequiredService<IResolverListReader>());
        Assert.IsType<UiStateStore>(provider.GetRequiredService<IUiStateStore>());
        Assert.IsType<AlwaysOnlineProbeGate>(provider.GetRequiredService<IProbeGate>());
        Assert.IsType<TcpConnectProber>(provider.GetRequiredService<ILatencyProber>());
    }

    /// <summary>D1: the Resolvers tab's view-model resolves from the full App graph, and the shell VM
    /// exposes the SAME singleton instance the graph holds (DataContext ≡ container).</summary>
    [Fact]
    public void ResolversViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<ResolversViewModel>();

        Assert.NotNull(viewModel);
        Assert.Same(viewModel, provider.GetRequiredService<MainWindowViewModel>().Resolvers);
    }

    /// <summary>D2: the Anonymized DNS tab's view-model resolves from the full App graph, and the shell
    /// VM exposes the SAME singleton instance the graph holds.</summary>
    [Fact]
    public void AnonymizedDnsViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<AnonymizedDnsViewModel>();

        Assert.NotNull(viewModel);
        Assert.Same(viewModel, provider.GetRequiredService<MainWindowViewModel>().AnonymizedDns);
    }

    /// <summary>D1 (Phase 5d): the Filtering tab's rule-file service + the six family codecs resolve to
    /// their production concretes from the full App graph.</summary>
    [Fact]
    public void Filtering_services_resolve_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        Assert.IsType<RuleFileService>(provider.GetRequiredService<IRuleFileService>());
        var codecs = provider.GetRequiredService<IReadOnlyList<IRuleFamilyCodec>>();
        Assert.Equal(6, codecs.Count);
    }

    /// <summary>D1 (Phase 5d): the Filtering tab's view-model resolves from the full App graph, and the
    /// shell VM exposes the SAME singleton instance the graph holds (DataContext ≡ container).</summary>
    [Fact]
    public void FilteringViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<FilteringViewModel>();

        Assert.NotNull(viewModel);
        Assert.Same(viewModel, provider.GetRequiredService<MainWindowViewModel>().Filtering);
    }

    /// <summary>Phase 5e: the Query Monitor tab's services (read-and-shred reader + UI-thread poller)
    /// resolve to their production concretes; the reader defaults to the per-user query-log path.</summary>
    [Fact]
    public void QueryMonitor_services_resolve_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        Assert.IsType<QueryLogReader>(provider.GetRequiredService<IQueryLogReader>());
        Assert.IsType<PeriodicTimerQueryPoller>(provider.GetRequiredService<IQueryPoller>());
        Assert.IsType<LogTailReader>(provider.GetRequiredService<ILogTailReader>());
    }

    /// <summary>Phase 5e: the Query Monitor tab's view-model resolves from the full App graph (its
    /// optional poll-interval ctor param takes the production default), and the shell VM exposes the SAME
    /// singleton instance the graph holds.</summary>
    [Fact]
    public void QueryMonitorViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<QueryMonitorViewModel>();

        Assert.NotNull(viewModel);
        Assert.Same(viewModel, provider.GetRequiredService<MainWindowViewModel>().QueryMonitor);
    }

    /// <summary>Phase 5i: the shared per-session query-log source (<see cref="IQueryLogSession"/>) resolves
    /// to the SAME singleton instance as the Query Monitor view-model — one read-and-shred reader, one
    /// in-memory buffer, read by BOTH the Query Monitor and the Dashboard.</summary>
    [Fact]
    public void IQueryLogSession_is_the_same_singleton_as_the_QueryMonitorViewModel()
    {
        var provider = BuildFullAppProvider();

        var session = provider.GetRequiredService<IQueryLogSession>();

        Assert.Same(provider.GetRequiredService<QueryMonitorViewModel>(), session);
    }

    /// <summary>Phase 5e: the Logs &amp; Diagnostics tab's view-model resolves from the full App graph, and
    /// the shell VM exposes the SAME singleton instance the graph holds.</summary>
    [Fact]
    public void LogsDiagnosticsViewModel_resolves_from_the_full_App_service_graph()
    {
        var provider = BuildFullAppProvider();

        var viewModel = provider.GetRequiredService<LogsDiagnosticsViewModel>();

        Assert.NotNull(viewModel);
        Assert.Same(viewModel, provider.GetRequiredService<MainWindowViewModel>().LogsDiagnostics);
    }
}
