using DnsCryptControl.Ipc.Security;

namespace DnsCryptControl.Ipc.Tests;

internal sealed class FakeCallerVerifier : ICallerVerifier
{
    public bool Allow { get; set; } = true;
    public CallerIdentity? LastSeen { get; private set; }

    public bool IsTrusted(CallerIdentity caller)
    {
        LastSeen = caller;
        return Allow;
    }
}
