using System.Windows;
using System.Windows.Controls;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Settings tab view (Phase 5f). Look-only; the code-behind's sole job is to kick the integrity
/// panel's first read when the tab loads (the verdict needs a live GetStatus). The command is idempotent
/// and fail-closed, so firing it on each load is safe.
/// </summary>
public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsViewModel vm && vm.RefreshIntegrityCommand.CanExecute(null))
        {
            vm.RefreshIntegrityCommand.Execute(null);
        }
    }
}
