namespace DnsCryptControl.Ipc.Security;

/// <summary>Identity of a connected pipe client, as observed by the server: the client's
/// process id and the full path to its on-disk image. The verifier inspects this to decide
/// whether the caller is one of our trusted, signed executables.</summary>
public readonly record struct CallerIdentity(int ProcessId, string ImagePath);
