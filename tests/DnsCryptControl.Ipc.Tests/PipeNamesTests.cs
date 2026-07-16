using DnsCryptControl.Ipc.Transport;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class PipeNamesTests
{
    [Fact]
    public void Helper_isTheCanonicalName()
    {
        Assert.Equal("DnsCryptControl.Helper", PipeNames.Helper);
    }
}
