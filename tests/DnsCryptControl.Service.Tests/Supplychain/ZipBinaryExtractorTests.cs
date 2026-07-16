using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using DnsCryptControl.Service.Supplychain;
using Xunit;

namespace DnsCryptControl.Service.Tests.Supplychain;

public class ZipBinaryExtractorTests
{
    private static byte[] Zip(params (string name, byte[] content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var e = z.CreateEntry(name);
                using var s = e.Open();
                s.Write(content, 0, content.Length);
            }
        }
        return ms.ToArray();
    }

    [Fact]
    public void ExtractEntry_writesNamedEntry_intoConfinedDir()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var bytes = Zip(("dnscrypt-proxy.exe", Encoding.ASCII.GetBytes("MZfake")),
                        ("LICENSE", Encoding.ASCII.GetBytes("x")));
        var dest = Path.Combine(dir, "dnscrypt-proxy.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", dest, dir);
        Assert.True(r.Ok, r.Error);
        Assert.Equal("MZfake", File.ReadAllText(dest));
    }

    [Fact]
    public void ExtractEntry_returnsSha256_ofWrittenBytes()
    {
        // The post-verify hash must be computed over the exact bytes streamed to disk (closes the
        // install TOCTOU): a disk re-read could observe a swapped file. Assert the returned hash
        // equals SHA-256 of the entry's plaintext content.
        var dir = Directory.CreateTempSubdirectory().FullName;
        var content = Encoding.ASCII.GetBytes("MZ-proxy-bytes");
        var bytes = Zip(("dnscrypt-proxy.exe", content));
        var dest = Path.Combine(dir, "dnscrypt-proxy.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", dest, dir);
        Assert.True(r.Ok, r.Error);

        var expected = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        Assert.Equal(expected, r.Sha256Hex);
        // And it must equal the SHA-256 of the file actually on disk.
        Assert.Equal(expected, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(dest))).ToLowerInvariant());
    }

    [Fact]
    public void ExtractEntry_failure_hasNullSha256()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var bytes = Zip(("LICENSE", Encoding.ASCII.GetBytes("x")));
        var dest = Path.Combine(dir, "dnscrypt-proxy.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", dest, dir);
        Assert.False(r.Ok);
        Assert.Null(r.Sha256Hex);
    }

    [Fact]
    public void ExtractEntry_missingEntry_fails()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var bytes = Zip(("LICENSE", Encoding.ASCII.GetBytes("x")));
        var dest = Path.Combine(dir, "dnscrypt-proxy.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", dest, dir);
        Assert.False(r.Ok);
    }

    [Fact]
    public void ExtractEntry_matchesByLeafName_ignoringInnerFolder()
    {
        // dnscrypt-proxy releases nest files under a top folder; match on the leaf.
        var dir = Directory.CreateTempSubdirectory().FullName;
        var bytes = Zip(("win64/dnscrypt-proxy.exe", Encoding.ASCII.GetBytes("MZ")));
        var dest = Path.Combine(dir, "dnscrypt-proxy.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", dest, dir);
        Assert.True(r.Ok, r.Error);
        Assert.Equal("MZ", File.ReadAllText(dest));
    }

    [Fact]
    public void ExtractEntry_destOutsideBase_isRejected_zipSlip()
    {
        // A caller-supplied destination that climbs out of the base must be rejected by the
        // genuine confinement check (GetRelativePath -> ".." -> ResolveWithinBase throws).
        var dir = Directory.CreateTempSubdirectory().FullName;
        var bytes = Zip(("dnscrypt-proxy.exe", Encoding.ASCII.GetBytes("MZ")));
        var escaped = Path.Combine(dir, "..", "escape.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", escaped, dir);
        Assert.False(r.Ok);
        Assert.Contains("zip-slip", r.Error, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.GetFullPath(escaped))); // nothing written outside the base
    }

    [Fact]
    public void ExtractEntry_maliciousEntryName_climbingOutOfBase_isRejected_zipSlip()
    {
        // The attacker-controlled value is the ENTRY name. An entry whose FullName escapes the base
        // is rejected even though its leaf matches — confinement is against match.FullName, not the leaf.
        var dir = Directory.CreateTempSubdirectory().FullName;
        var bytes = Zip(("../dnscrypt-proxy.exe", Encoding.ASCII.GetBytes("MZ")));
        var dest = Path.Combine(dir, "dnscrypt-proxy.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", dest, dir);
        Assert.False(r.Ok);
        Assert.Contains("zip-slip", r.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExtractEntry_oversizedEntry_isRejected_decompressionBomb()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var big = new byte[ZipBinaryExtractor.MaxUnzippedBytes + 1];
        var bytes = Zip(("dnscrypt-proxy.exe", big));
        var dest = Path.Combine(dir, "dnscrypt-proxy.exe");
        var r = ZipBinaryExtractor.ExtractEntry(bytes, "dnscrypt-proxy.exe", dest, dir);
        Assert.False(r.Ok);
        Assert.False(File.Exists(dest)); // nothing committed
    }
}
