using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class ProtectionDtoTests
{
    [Fact]
    public void ResultOfProtectionResponse_roundTrips_advisoryAndReboot()
    {
        var ok = Result<ProtectionResponse>.Ok(new ProtectionResponse(
            ProtectionEnabled: true,
            KillSwitchEnabled: false,
            LeakMitigationsEnabled: true,
            RebootRecommended: true,
            KillSwitchAdvisory: "kill switch could not be enabled on this network profile"));

        var json = IpcSerializer.SerializePayload(ok);
        var back = IpcSerializer.DeserializePayload<Result<ProtectionResponse>>(json);

        Assert.NotNull(back);
        Assert.True(back!.Success);
        Assert.NotNull(back.Value);
        Assert.Equal("kill switch could not be enabled on this network profile", back.Value!.KillSwitchAdvisory);
        Assert.True(back.Value.RebootRecommended);
    }

    // Genuine wire pins: the numeric enum values ride the frames, so a reorder of
    // IpcCommandType would silently change the wire meaning of these verbs. Pin the numbers.

    [Fact]
    public void EnableProtection_wireValue_isPinned()
    {
        Assert.Equal(16, (int)IpcCommandType.EnableProtection);
    }

    [Fact]
    public void DisableProtection_wireValue_isPinned()
    {
        Assert.Equal(17, (int)IpcCommandType.DisableProtection);
    }
}
