using CommunityToolkit.Mvvm.ComponentModel;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// Root shell view-model. Pure POCO (zero WPF type references) so it can be
/// constructed and unit-tested headlessly. Exposes the tab view-models the shell binds
/// to: <see cref="Dashboard"/> (C2), <see cref="Configuration"/> (F2), the Phase 5c
/// tabs <see cref="Resolvers"/> and <see cref="AnonymizedDns"/>, the Phase 5d
/// <see cref="Filtering"/> tab, the Phase 5e <see cref="QueryMonitor"/> +
/// <see cref="LogsDiagnostics"/> tabs, and the Phase 5f <see cref="Settings"/> tab.
/// </summary>
public partial class MainWindowViewModel : ObservableObject
{
    public MainWindowViewModel(
        DashboardViewModel dashboard,
        ConfigurationViewModel configuration,
        ResolversViewModel resolvers,
        AnonymizedDnsViewModel anonymizedDns,
        FilteringViewModel filtering,
        QueryMonitorViewModel queryMonitor,
        LogsDiagnosticsViewModel logsDiagnostics,
        SettingsViewModel settings)
    {
        ArgumentNullException.ThrowIfNull(dashboard);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(resolvers);
        ArgumentNullException.ThrowIfNull(anonymizedDns);
        ArgumentNullException.ThrowIfNull(filtering);
        ArgumentNullException.ThrowIfNull(queryMonitor);
        ArgumentNullException.ThrowIfNull(logsDiagnostics);
        ArgumentNullException.ThrowIfNull(settings);
        Dashboard = dashboard;
        Configuration = configuration;
        Resolvers = resolvers;
        AnonymizedDns = anonymizedDns;
        Filtering = filtering;
        QueryMonitor = queryMonitor;
        LogsDiagnostics = logsDiagnostics;
        Settings = settings;
    }

    public DashboardViewModel Dashboard { get; }

    public ConfigurationViewModel Configuration { get; }

    public ResolversViewModel Resolvers { get; }

    public AnonymizedDnsViewModel AnonymizedDns { get; }

    public FilteringViewModel Filtering { get; }

    public QueryMonitorViewModel QueryMonitor { get; }

    public LogsDiagnosticsViewModel LogsDiagnostics { get; }

    public SettingsViewModel Settings { get; }
}
