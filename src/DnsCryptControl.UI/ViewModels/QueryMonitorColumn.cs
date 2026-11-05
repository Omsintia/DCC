namespace DnsCryptControl.UI.ViewModels;

/// <summary>The Query Monitor's six fixed, user-resizable columns. The Name column is star-sized
/// (absorbs the remaining width) and is deliberately not resizable — shrinking every fixed column
/// is how the user gives Name more room.</summary>
public enum QueryMonitorColumn
{
    Time,
    Type,
    Action,
    Latency,
    Server,

    /// <summary>The originating-app column (v1.3.0 per-app attribution), between Server and Name.</summary>
    App,
}
