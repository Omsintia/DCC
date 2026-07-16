using DnsCryptControl.Ipc.Commands;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class IpcMessagesTests
{
    [Fact]
    public void CommandType_coversTheFixedVocabulary()
    {
        // Spec §5.4 — exactly these verbs, no generic "run".
        foreach (var expected in new[]
        {
            IpcCommandType.GetStatus, IpcCommandType.InstallProxyService, IpcCommandType.UninstallProxyService,
            IpcCommandType.StartProxy, IpcCommandType.StopProxy, IpcCommandType.RestartProxy,
            IpcCommandType.WriteConfig, IpcCommandType.WriteRuleFile,
            IpcCommandType.ApplyDnsToAllAdapters, IpcCommandType.RestoreDns,
            IpcCommandType.SetLeakMitigations, IpcCommandType.SetKillSwitch, IpcCommandType.SetBrowserDohPolicy,
            IpcCommandType.FlushDnsCache, IpcCommandType.VerifyAndInstallBinary, IpcCommandType.RunDiagnostics,
            IpcCommandType.EnableProtection, IpcCommandType.DisableProtection,
            // v3 (post-5j ODoH fix): places the bundled signed ODoH source caches so the proxy loads
            // them from cache instead of the boot-time download it treats as FATAL (which bricks DNS).
            IpcCommandType.PlaceOdohCache,
            // v4 (v1.2.0, FIX #1): the post-apply real-name resolve check — the local .test
            // self-check false-greens on a dead anonymized route; this verb proves the route.
            IpcCommandType.VerifyResolution,
        })
        {
            Assert.True(System.Enum.IsDefined(expected));
        }
        // Exactly these verbs — a 21st member would silently widen the privileged surface. Any change
        // here is a deliberate wire change: bump IpcProtocol.Version and update this pin in lockstep.
        Assert.Equal(20, System.Enum.GetValues<IpcCommandType>().Length);
    }

    [Fact]
    public void Request_holdsCommandAndPayload()
    {
        var req = new IpcRequest(IpcCommandType.WriteConfig, "{\"TomlText\":\"max_clients = 1\"}");
        Assert.Equal(IpcCommandType.WriteConfig, req.Command);
        Assert.Contains("max_clients", req.PayloadJson);
    }

    [Fact]
    public void Payloads_constructAndExposeValues()
    {
        var writeConfig = new WriteConfigPayload("max_clients = 1", TestSha.Of("old = 1\n"));
        Assert.Equal("max_clients = 1", writeConfig.TomlText);
        Assert.Equal(TestSha.Of("old = 1\n"), writeConfig.BaseSha256);
        Assert.Equal("blocked_names", new WriteRuleFilePayload("blocked_names", "ads.example").Kind);
        Assert.True(new SetTogglePayload(true).Enable);
        Assert.Equal("2.1.16", new VerifyAndInstallBinaryPayload(@"C:\tmp\x.zip", "2.1.16").ExpectedTag);
    }
}
