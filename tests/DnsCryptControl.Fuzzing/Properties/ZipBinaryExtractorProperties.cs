using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using CsCheck;
using DnsCryptControl.Service.Supplychain;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for ZipBinaryExtractor - the single-entry extractor that writes the
/// verified dnscrypt-proxy.exe to disk as LocalSystem. Oracles: it NEVER throws on arbitrary bytes (a
/// corrupt/hostile archive fails to a typed result); it NEVER accepts fuzzed garbage; a benign entry
/// extracts within the base; and a zip-slip entry (whose path escapes the base) is REJECTED (the underlying
/// SafePath confinement is separately fuzzed). See the fuzzing design notes.
/// </summary>
public class ZipBinaryExtractorProperties
{
    // Garbage bytes never form a valid archive, so ExtractEntry rejects them before any file I/O and this
    // base path (a string, may not exist) is never written to.
    private static readonly string ScratchBase = Path.Combine(Path.GetTempPath(), "dcc-fuzz-zip-scratch");

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ExtractEntry_never_throws_and_never_accepts_arbitrary_bytes() =>
        Gen.Byte.Array.Sample(bytes =>
        {
            var result = ZipBinaryExtractor.ExtractEntry(
                bytes, "dnscrypt-proxy.exe", Path.Combine(ScratchBase, "dnscrypt-proxy.exe"), ScratchBase);
            // A corrupt/garbage archive fails to a typed result - never a throw, never Ok.
            return !result.Ok;
        }, iter: Fuzz.Iter);

    [Fact]
    public void ExtractEntry_extracts_a_benign_entry_within_the_base()
    {
        var baseDir = NewTempDir();
        try
        {
            var content = Encoding.UTF8.GetBytes("hello dnscrypt");
            var zip = MakeZip("dnscrypt-proxy.exe", content);
            var dest = Path.Combine(baseDir, "dnscrypt-proxy.exe");

            var result = ZipBinaryExtractor.ExtractEntry(zip, "dnscrypt-proxy.exe", dest, baseDir);

            Assert.True(result.Ok);
            Assert.True(File.Exists(dest));
            Assert.Equal(content, File.ReadAllBytes(dest));
        }
        finally
        {
            Directory.Delete(baseDir, recursive: true);
        }
    }

    [Fact]
    public void ExtractEntry_rejects_a_zip_slip_entry()
    {
        var baseDir = NewTempDir();
        try
        {
            // An entry whose FullName escapes the base ('../') is refused (CWE-22), even though its leaf
            // name matches the requested entry and nothing outside the base is written.
            var zip = MakeZip("../evil.exe", Encoding.UTF8.GetBytes("x"));
            var dest = Path.Combine(baseDir, "evil.exe");

            var result = ZipBinaryExtractor.ExtractEntry(zip, "evil.exe", dest, baseDir);

            Assert.False(result.Ok);
            Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(baseDir)!, "evil.exe")));
        }
        finally
        {
            Directory.Delete(baseDir, recursive: true);
        }
    }

    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dcc-fuzz-zip-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static byte[] MakeZip(string entryName, byte[] content)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry(entryName);
            using var s = entry.Open();
            s.Write(content, 0, content.Length);
        }

        return ms.ToArray();
    }
}
