using DnsCryptControl.Platform;

namespace DnsCryptControl.Service;

/// <summary>Resolves the protected %ProgramData%\DnsCryptControl\ directory and the fixed
/// file names the helper owns. Rule-file kinds map to fixed names so an untrusted IPC
/// string is never a path component.</summary>
public sealed class ProtectedPaths
{
    public ProtectedPaths(string baseDir)
    {
        ArgumentException.ThrowIfNullOrEmpty(baseDir);
        BaseDir = baseDir;
    }

    public static ProtectedPaths Default() =>
        new(System.IO.Path.Combine(
            System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData),
            "DnsCryptControl"));

    public string BaseDir { get; }
    public string ConfigFile => System.IO.Path.Combine(BaseDir, "dnscrypt-proxy.toml");
    public string BackupsDir => System.IO.Path.Combine(BaseDir, "backups");
    public string StateDir => System.IO.Path.Combine(BaseDir, "state");
    public string BackupFile => System.IO.Path.Combine(StateDir, "backup.json");
    public string ProtectionStateFile => System.IO.Path.Combine(StateDir, "protection.json");

    public string ProxyExeFile => System.IO.Path.Combine(BaseDir, "dnscrypt-proxy.exe");
    public string ExampleConfigFile => System.IO.Path.Combine(BaseDir, "example-dnscrypt-proxy.toml");
    public string InstalledBinaryRecordFile => System.IO.Path.Combine(StateDir, "installed-binary.json");
    public string DownloadStagingDir => System.IO.Path.Combine(BaseDir, "staging");

    public string RuleFilePath(RuleFileKind kind) =>
        System.IO.Path.Combine(BaseDir, kind switch
        {
            RuleFileKind.BlockedNames => "blocked-names.txt",
            RuleFileKind.AllowedNames => "allowed-names.txt",
            RuleFileKind.BlockedIps => "blocked-ips.txt",
            RuleFileKind.AllowedIps => "allowed-ips.txt",
            RuleFileKind.Cloaking => "cloaking-rules.txt",
            RuleFileKind.Forwarding => "forwarding-rules.txt",
            RuleFileKind.CaptivePortals => "captive-portals.txt",
            _ => throw new System.ArgumentOutOfRangeException(nameof(kind)),
        });
}
