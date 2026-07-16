using System.Windows;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Dashboard tab's view. Bound via <c>DataContext</c> to the injected
/// <c>DashboardViewModel</c> from <c>MainWindowViewModel.Dashboard</c> (set in
/// <c>MainWindow.xaml</c>). Code-behind is view PLUMBING only: the poll-loop
/// start/stop lifecycle is driven by <c>MainWindow</c>'s tab-selection forwarding, and the
/// only handler here is the 5g-4 "Open Query Monitor" navigation — window/tab reaching is
/// view code-behind territory (MVVM boundary: the VM never sees the window).
/// </summary>
public partial class DashboardView
{
    public DashboardView()
    {
        InitializeComponent();
    }

    /// <summary>
    /// 5g-4: both "Open Query Monitor" links (under the KPI grid and in the LIVE ACTIVITY
    /// card) route to the shell's <see cref="MainWindow.NavigateToQueryMonitor"/>, which runs
    /// the full tab lifecycle. Null-safe: design-time hosts and view-level tests have no
    /// <see cref="MainWindow"/> ancestor — the click is then a no-op. Navigation never
    /// enables query logging; the consent gate lives in the Query Monitor tab.
    /// </summary>
    private void OpenQueryMonitor_Click(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            mainWindow.NavigateToQueryMonitor();
        }
    }
}
