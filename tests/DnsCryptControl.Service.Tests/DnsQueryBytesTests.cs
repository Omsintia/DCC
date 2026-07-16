using System;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class DnsQueryBytesTests
{
    [Fact]
    public void BuildAQuery_hasHeaderWithIdAndSingleQuestion()
    {
        var bytes = DnsQueryBytes.BuildAQuery("a.test", id: 0x1234);

        // 12-byte header.
        Assert.True(bytes.Length > 12);
        Assert.Equal(0x12, bytes[0]);              // ID high
        Assert.Equal(0x34, bytes[1]);              // ID low
        Assert.Equal(0x01, bytes[2]);              // flags high: RD=1
        Assert.Equal(0x00, bytes[3]);              // flags low
        Assert.Equal(0x00, bytes[4]); Assert.Equal(0x01, bytes[5]); // QDCOUNT=1
        Assert.Equal(0x00, bytes[6]); Assert.Equal(0x00, bytes[7]); // ANCOUNT=0
        Assert.Equal(0x00, bytes[8]); Assert.Equal(0x00, bytes[9]); // NSCOUNT=0
        Assert.Equal(0x00, bytes[10]); Assert.Equal(0x00, bytes[11]); // ARCOUNT=0
    }

    [Fact]
    public void BuildAQuery_encodesQnameLabelsAndTerminatesWithZero()
    {
        var bytes = DnsQueryBytes.BuildAQuery("a.test", id: 1);

        // QNAME begins at offset 12: [1]'a' [4]'t''e''s''t' [0]
        Assert.Equal(0x01, bytes[12]);
        Assert.Equal((byte)'a', bytes[13]);
        Assert.Equal(0x04, bytes[14]);
        Assert.Equal((byte)'t', bytes[15]);
        Assert.Equal((byte)'e', bytes[16]);
        Assert.Equal((byte)'s', bytes[17]);
        Assert.Equal((byte)'t', bytes[18]);
        Assert.Equal(0x00, bytes[19]); // root label

        // QTYPE=A(1), QCLASS=IN(1) follow.
        Assert.Equal(0x00, bytes[20]); Assert.Equal(0x01, bytes[21]);
        Assert.Equal(0x00, bytes[22]); Assert.Equal(0x01, bytes[23]);
        Assert.Equal(24, bytes.Length);
    }

    [Fact]
    public void BuildAQuery_rejectsEmptyName()
    {
        Assert.Throws<ArgumentException>(() => DnsQueryBytes.BuildAQuery("", id: 1));
    }

    [Fact]
    public void BuildAQuery_rejectsOverlongLabel()
    {
        var longLabel = new string('x', 64); // > 63
        Assert.Throws<ArgumentException>(() => DnsQueryBytes.BuildAQuery(longLabel + ".test", id: 1));
    }

    // Fix 3: consecutive dots produce an empty label and must be rejected, not silently dropped.
    [Theory]
    [InlineData("a..test")]          // consecutive dots → empty label
    [InlineData(".leading")]         // leading dot → empty first label
    [InlineData("a..b.test")]        // double dot mid-name
    public void BuildAQuery_rejectsEmptyLabel(string name)
    {
        Assert.Throws<ArgumentException>(() => DnsQueryBytes.BuildAQuery(name, id: 1));
    }

    [Fact]
    public void BuildAQuery_acceptsValidMultiLabelName()
    {
        // Baseline: the production self-check name must still work after the empty-label guard.
        var bytes = DnsQueryBytes.BuildAQuery("dnscrypt-resolver-selfcheck.test", id: 0x0001);
        Assert.True(bytes.Length > 12);
    }
}
