using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Service.Windows;

namespace DnsCryptControl.Service.State;

/// <summary>The SHA-256 (hex) of the dnscrypt-proxy.exe that was installed AFTER a successful
/// minisign verification, plus the tag + install timestamp. Launch-time integrity re-hashes the
/// installed exe and compares against Sha256Hex (IC-10).</summary>
public sealed record InstalledBinaryRecord(string Sha256Hex, string Tag, string InstalledUtc);

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(InstalledBinaryRecord))]
internal sealed partial class InstalledBinaryRecordJsonContext : JsonSerializerContext
{
}

/// <summary>Atomic, ACL'd JSON store for the installed-binary record. Load never throws (returns
/// null on absent/unreadable/corrupt). Same discipline as ProtectionStateStore.</summary>
[SupportedOSPlatform("windows")]
public sealed class InstalledBinaryRecordStore
{
    private readonly string _path;
    private readonly object _gate = new();

    public InstalledBinaryRecordStore(string recordFilePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(recordFilePath);
        _path = recordFilePath;
    }

    public InstalledBinaryRecord? Load()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(_path)) return null;
                if (JsonStateReadGuard.IsOversized(_path)) return null;             // OOM/amplification guard
                var json = File.ReadAllText(_path);
                if (!JsonStateReadGuard.IsWellFormedWithinDepth(json)) return null;  // depth/malformed guard
                return JsonSerializer.Deserialize(json, InstalledBinaryRecordJsonContext.Default.InstalledBinaryRecord);
            }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            catch (JsonException) { return null; }
        }
    }

    public void Record(string sha256Hex, string tag)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha256Hex);
        ArgumentException.ThrowIfNullOrEmpty(tag);
        var record = new InstalledBinaryRecord(sha256Hex, tag, System.DateTime.UtcNow.ToString("O"));
        lock (_gate)
        {
            var dir = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(dir);
            AclHelper.TryHardenAcl(dir);

            var json = JsonSerializer.Serialize(record, InstalledBinaryRecordJsonContext.Default.InstalledBinaryRecord);
            var temp = _path + ".tmp";
            File.WriteAllText(temp, json);
            AclHelper.TryHardenAcl(temp);

            if (File.Exists(_path))
                File.Replace(temp, _path, destinationBackupFileName: null);
            else
                File.Move(temp, _path, overwrite: true);

            AclHelper.TryHardenAcl(_path);
        }
    }
}
