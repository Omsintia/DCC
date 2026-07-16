using System.Windows;
using System.Windows.Threading;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Production <see cref="IUiDispatcher"/> that marshals onto the WPF UI thread
/// via <see cref="Application.Current"/>'s <see cref="Dispatcher"/>.
/// </summary>
public sealed class WpfDispatcher : IUiDispatcher
{
    // Application.Current can be null during shutdown (e.g. a poll-loop continuation
    // resuming after OnExit has torn down the Application) — a null-conditional guard
    // makes a late Post a silent no-op instead of an NRE.
    public void Post(Action action) => Application.Current?.Dispatcher.BeginInvoke(action);
}
