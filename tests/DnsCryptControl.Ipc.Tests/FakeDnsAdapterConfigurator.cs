using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Tests;

internal sealed class FakeDnsAdapterConfigurator : IDnsAdapterConfigurator
{
    public List<string> Calls { get; } = new();
    public PlatformErrorKind? FailApply { get; set; }
    public PlatformErrorKind? FailRestore { get; set; }
    public bool Applied { get; set; }

    public PlatformResult ApplyLoopbackToAllAdapters()
    {
        Calls.Add(nameof(ApplyLoopbackToAllAdapters));
        if (FailApply is { } kind) return PlatformResult.Fail(kind, "apply failed");
        Applied = true;
        return PlatformResult.Ok();
    }

    public PlatformResult ReassertLoopback()
    {
        Calls.Add(nameof(ReassertLoopback));
        return PlatformResult.Ok();
    }

    public PlatformResult RestoreDns()
    {
        Calls.Add(nameof(RestoreDns));
        if (FailRestore is { } kind) return PlatformResult.Fail(kind, "restore failed");
        Applied = false;
        return PlatformResult.Ok();
    }

    public bool IsLoopbackApplied() => Applied;
}
