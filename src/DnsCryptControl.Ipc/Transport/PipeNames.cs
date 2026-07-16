namespace DnsCryptControl.Ipc.Transport;

/// <summary>Canonical local pipe name shared by the helper server and the UI client so
/// the two endpoints can never drift. No network listener exists anywhere.</summary>
public static class PipeNames
{
    public const string Helper = "DnsCryptControl.Helper";
}
