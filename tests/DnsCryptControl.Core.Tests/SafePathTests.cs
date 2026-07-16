using System;
using DnsCryptControl.Core.Security;
using Xunit;

namespace DnsCryptControl.Core.Tests;

public class SafePathTests
{
    private const string Base = @"C:\ProgramData\DnsCryptControl";

    [Fact]
    public void ResolveWithinBase_simpleName_returnsCombinedPath()
    {
        var p = SafePath.ResolveWithinBase(Base, "dnscrypt-proxy.toml");
        Assert.Equal(@"C:\ProgramData\DnsCryptControl\dnscrypt-proxy.toml", p);
    }

    [Theory]
    [InlineData("..\\..\\Windows\\System32\\evil.dll")]
    [InlineData("../secrets.txt")]
    [InlineData("sub\\..\\..\\escape.txt")]
    [InlineData("C:\\Windows\\System32\\drivers\\etc\\hosts")] // rooted
    [InlineData("\\\\server\\share\\file")]                    // UNC
    [InlineData("CON")]                                         // device name
    [InlineData("name:stream")]                                 // alternate data stream
    [InlineData("NUL")]
    [InlineData("LPT1")]
    [InlineData("CON.txt")]
    [InlineData("sub\\CON\\x.txt")]
    public void ResolveWithinBase_maliciousInput_throws(string evil)
    {
        Assert.Throws<ArgumentException>(() => SafePath.ResolveWithinBase(Base, evil));
    }

    [Fact]
    public void IsWithinBase_prefixSibling_isRejected()
    {
        // "C:\base-evil" must NOT count as inside "C:\base"
        Assert.False(SafePath.IsWithinBase(@"C:\base", @"C:\base-evil\x.txt"));
        Assert.True(SafePath.IsWithinBase(@"C:\base", @"C:\base\sub\x.txt"));
        Assert.True(SafePath.IsWithinBase(@"C:\base", @"C:\base")); // the base itself is "within"
    }
}
