namespace DnsCryptControl.UI.Services;

/// <summary>
/// Abstraction over UI-thread marshalling so view-models remain pure POCOs
/// (no WPF <c>Dispatcher</c>/<c>DispatcherObject</c> reference) and are
/// therefore unit-testable headlessly on a non-STA xUnit thread.
/// </summary>
public interface IUiDispatcher
{
    void Post(Action action);
}
