using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using DnsCryptControl.Core.Security;

namespace DnsCryptControl.Service.Supplychain;

/// <summary>Outcome of <see cref="ZipBinaryExtractor.ExtractEntry"/>. On success, <see cref="Sha256Hex"/>
/// is the SHA-256 (lowercase hex) of the EXACT bytes streamed to disk — so the caller records the hash
/// of the verified bytes it just wrote, never a disk re-read that an attacker could have swapped (TOCTOU).</summary>
internal sealed record ExtractResult(bool Ok, string? Error, string? Sha256Hex)
{
    internal static ExtractResult Pass(string sha256Hex) => new(true, null, sha256Hex);
    internal static ExtractResult Fail(string error) => new(false, error, null);
}

/// <summary>Extracts a single named entry from ALREADY-VERIFIED zip bytes (IC-7: bytes are passed
/// in, never re-read by path) into a path-confined destination (zip-slip guard, CWE-22) with a
/// cumulative decompression-bomb cap (CWE-400). Two DISTINCT checks: (1) the entry is SELECTED by
/// leaf name (so nested release folders are tolerated); (2) the chosen target is CONFINED by
/// resolving the requested <c>destFilePath</c> leaf AND the entry's full name under the base dir —
/// an entry whose FullName escapes the base (e.g. "..\evil") or a destFilePath leaf that escapes is
/// REJECTED. Streams through a temp file and commits atomically; cleans up on any error.</summary>
internal static class ZipBinaryExtractor
{
    internal const long MaxUnzippedBytes = 64L * 1024 * 1024; // 64 MiB cap (dnscrypt-proxy.exe is ~10 MiB)

    internal static ExtractResult ExtractEntry(byte[] verifiedZipBytes, string entryLeafName, string destFilePath, string confineBaseDir)
    {
        ArgumentNullException.ThrowIfNull(verifiedZipBytes);

        string? temp = null;
        try
        {
            using var ms = new MemoryStream(verifiedZipBytes, writable: false);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);

            // (1) SELECT the entry by leaf name (release archives nest under a top folder).
            ZipArchiveEntry? match = null;
            foreach (var entry in archive.Entries)
            {
                if (string.Equals(Path.GetFileName(entry.FullName), entryLeafName, StringComparison.OrdinalIgnoreCase))
                {
                    match = entry;
                    break;
                }
            }
            if (match is null)
                return ExtractResult.Fail($"entry '{entryLeafName}' not found in archive");

            // (2) CONFINE — genuine zip-slip guard. ResolveWithinBase THROWS on any "..", rooted,
            // UNC, device, or escaping path, so it rejects (a) a malicious entry whose FullName tries
            // to climb out of the base, and (b) a caller-supplied destFilePath whose leaf escapes.
            // We must pass the UNSTRIPPED names here — Path.GetFileName would defeat the check.
            string confinedDest;
            try
            {
                // Confine the entry's own path first (the attacker-controlled value).
                _ = SafePath.ResolveWithinBase(confineBaseDir, match.FullName);
                // Then resolve the actual write target from the requested destFilePath, also confined.
                var relativeDest = Path.IsPathRooted(destFilePath)
                    ? Path.GetRelativePath(confineBaseDir, destFilePath)   // yields ".." if destFilePath escapes -> rejected below
                    : destFilePath;
                confinedDest = SafePath.ResolveWithinBase(confineBaseDir, relativeDest);
            }
            catch (ArgumentException ex)
            {
                return ExtractResult.Fail($"zip-slip: extraction target escapes base: {ex.Message}");
            }

            Directory.CreateDirectory(confineBaseDir);
            temp = confinedDest + ".tmp";

            // Hash the EXACT bytes written (same buffer) so the recorded SHA-256 is of the verified bytes,
            // not a later disk re-read an attacker could have swapped (closes the install TOCTOU, IC-10).
            string sha256Hex;
            long written = 0;
            using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                using (var entryStream = match.Open())
                using (var outStream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var buffer = new byte[81920];
                    int read;
                    while ((read = entryStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        written += read;
                        if (written > MaxUnzippedBytes)
                            return ExtractResult.Fail("decompressed size exceeds cap (possible zip bomb)");
                        outStream.Write(buffer, 0, read);
                        sha.AppendData(buffer, 0, read);
                    }
                }
                sha256Hex = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            }

            if (File.Exists(confinedDest))
                File.Replace(temp, confinedDest, destinationBackupFileName: null);
            else
                File.Move(temp, confinedDest, overwrite: true);
            temp = null;
            return ExtractResult.Pass(sha256Hex);
        }
        catch (InvalidDataException ex) { return ExtractResult.Fail($"corrupt archive: {ex.Message}"); }
        catch (IOException ex) { return ExtractResult.Fail(ex.Message); }
        catch (UnauthorizedAccessException ex) { return ExtractResult.Fail(ex.Message); }
        finally
        {
            try { if (temp is not null && File.Exists(temp)) File.Delete(temp); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
