using System.IO;
using System.Text;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B2: <see cref="RuleFileService"/> is the Filtering tab's read/write path for the six rule
/// <c>.txt</c> files. Reads mirror <see cref="ResolverListReader"/> — shared
/// (ReadWrite|Delete) access so a concurrent helper replace never throws, fail-closed to a
/// typed <see cref="RuleFileState"/> (Present/Missing/Unreadable), never a throw. Writes run
/// the 1 MiB pre-check (IC-14) then map the helper reply into a typed
/// <see cref="RuleFileWriteOutcome"/> (Applied/Rejected/HelperUnavailable/TooLarge) with
/// verbatim messages (IC-10). Nothing here touches a real pipe or the real %ProgramData%.
/// </summary>
public class RuleFileServiceTests
{
    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rulefilesvc-" + Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        return dir;
    }

    // Must equal ProtectedPaths.RuleFilePath(kind)'s leaf (the E1 gate pins it globally).
    private static string LeafFor(RuleFileKind kind) => kind switch
    {
        RuleFileKind.BlockedNames => "blocked-names.txt",
        RuleFileKind.AllowedNames => "allowed-names.txt",
        RuleFileKind.BlockedIps => "blocked-ips.txt",
        RuleFileKind.AllowedIps => "allowed-ips.txt",
        RuleFileKind.Cloaking => "cloaking-rules.txt",
        RuleFileKind.Forwarding => "forwarding-rules.txt",
        RuleFileKind.CaptivePortals => "captive-portals.txt",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static string PathIn(string dir, RuleFileKind kind) => Path.Combine(dir, LeafFor(kind));

    // ---- ReadRuleFile ----------------------------------------------------------------

    [Fact]
    public void ReadRuleFile_present_returns_content_and_mtime()
    {
        var dir = NewTempDir();
        try
        {
            const string content = "# blocklist\n*.ads.example\n=exact.example\n";
            File.WriteAllText(PathIn(dir, RuleFileKind.BlockedNames), content);

            var snap = new RuleFileService(new FakeHelperClient(), dir).ReadRuleFile(RuleFileKind.BlockedNames);

            Assert.Equal(RuleFileState.Present, snap.State);
            Assert.Equal(content, snap.Content);
            Assert.NotNull(snap.LastWriteUtc);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ReadRuleFile_empty_file_is_Present_with_empty_content()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(PathIn(dir, RuleFileKind.AllowedNames), string.Empty);

            var snap = new RuleFileService(new FakeHelperClient(), dir).ReadRuleFile(RuleFileKind.AllowedNames);

            Assert.Equal(RuleFileState.Present, snap.State);
            Assert.Equal(string.Empty, snap.Content);
            Assert.NotNull(snap.LastWriteUtc);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ReadRuleFile_missing_returns_Missing_with_null_mtime()
    {
        var dir = NewTempDir();
        try
        {
            var snap = new RuleFileService(new FakeHelperClient(), dir).ReadRuleFile(RuleFileKind.BlockedIps);

            Assert.Equal(RuleFileState.Missing, snap.State);
            Assert.Equal(string.Empty, snap.Content);
            Assert.Null(snap.LastWriteUtc);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ReadRuleFile_utf8_bom_is_stripped_from_content()
    {
        var dir = NewTempDir();
        try
        {
            const string content = "*.tracker.example\n";
            var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(content)).ToArray();
            File.WriteAllBytes(PathIn(dir, RuleFileKind.BlockedNames), bytes);

            var snap = new RuleFileService(new FakeHelperClient(), dir).ReadRuleFile(RuleFileKind.BlockedNames);

            Assert.Equal(RuleFileState.Present, snap.State);
            Assert.Equal(content, snap.Content); // StreamReader consumed the BOM
            Assert.NotEqual('﻿', snap.Content[0]);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ReadRuleFile_locked_but_shared_readable_still_reads()
    {
        var dir = NewTempDir();
        try
        {
            const string content = "10.0.0.0/8\n";
            var path = PathIn(dir, RuleFileKind.BlockedIps);
            File.WriteAllText(path, content);

            // Hold a second WRITE handle open with ReadWrite|Delete sharing — exactly how the
            // proxy/helper touches the file mid-operation. The shared read must still succeed.
            using var concurrentWriter = new FileStream(
                path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);

            var snap = new RuleFileService(new FakeHelperClient(), dir).ReadRuleFile(RuleFileKind.BlockedIps);

            Assert.Equal(RuleFileState.Present, snap.State);
            Assert.Equal(content, snap.Content);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ReadRuleFile_exclusively_locked_fails_closed_to_Unreadable()
    {
        var dir = NewTempDir();
        try
        {
            var path = PathIn(dir, RuleFileKind.Cloaking);
            File.WriteAllText(path, "example.com 10.0.0.1\n");

            // No sharing at all — a non-shared reader must fail closed, not throw.
            using var exclusive = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);

            var snap = new RuleFileService(new FakeHelperClient(), dir).ReadRuleFile(RuleFileKind.Cloaking);

            Assert.Equal(RuleFileState.Unreadable, snap.State);
            Assert.Equal(string.Empty, snap.Content);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ReadRuleFile_outOfRangeKind_failsClosed_neverThrows()
    {
        // B2 carried finding: PathFor(kind) was evaluated BEFORE the fail-closed try/catch, so an
        // out-of-range RuleFileKind cast (an invalid enum value) threw ArgumentOutOfRangeException,
        // violating the "never throws" contract. It must now fail closed to Missing.
        var dir = NewTempDir();
        try
        {
            var svc = new RuleFileService(new FakeHelperClient(), dir);
            var bogus = (RuleFileKind)9999;

            var snap = svc.ReadRuleFile(bogus); // must not throw
            Assert.Equal(RuleFileState.Missing, snap.State);
            Assert.Null(svc.TryGetMtime(bogus)); // must not throw
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ReadRuleFile_overSizedFile_failsClosed_to_Unreadable()
    {
        // Symmetric with the 1 MiB WRITE cap: a pathologically large file fails closed to Unreadable
        // rather than buffering an unbounded string. The bound is 8x IpcSerializer.MaxBytes.
        var dir = NewTempDir();
        try
        {
            var path = PathIn(dir, RuleFileKind.BlockedNames);
            var bytes = new byte[8L * IpcSerializer.MaxBytes + 1024];
            Array.Fill(bytes, (byte)'a');
            File.WriteAllBytes(path, bytes);

            var snap = new RuleFileService(new FakeHelperClient(), dir).ReadRuleFile(RuleFileKind.BlockedNames);
            Assert.Equal(RuleFileState.Unreadable, snap.State);
            Assert.Equal(string.Empty, snap.Content);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // ---- TryGetMtime (IC-13 staleness) -----------------------------------------------

    [Fact]
    public void TryGetMtime_missing_is_null()
    {
        var dir = NewTempDir();
        try
        {
            Assert.Null(new RuleFileService(new FakeHelperClient(), dir).TryGetMtime(RuleFileKind.Forwarding));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void TryGetMtime_tracks_the_on_disk_write_time()
    {
        var dir = NewTempDir();
        try
        {
            var path = PathIn(dir, RuleFileKind.Forwarding);
            var svc = new RuleFileService(new FakeHelperClient(), dir);

            File.WriteAllText(path, "example.com 9.9.9.9\n");
            var first = svc.TryGetMtime(RuleFileKind.Forwarding);
            Assert.NotNull(first);

            // Re-stamp the file's mtime forward and confirm the reader observes the change —
            // the IC-13 staleness anchor: a changed mtime since load => "changed on disk".
            var later = DateTime.UtcNow.AddMinutes(5);
            File.SetLastWriteTimeUtc(path, later);
            var second = svc.TryGetMtime(RuleFileKind.Forwarding);

            Assert.NotNull(second);
            Assert.True(second > first);
            Assert.Equal(later, second!.Value, TimeSpan.FromSeconds(1));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // ---- WriteRuleFileAsync outcome map ----------------------------------------------

    [Fact]
    public async Task Write_success_maps_to_Applied_and_forwards_the_enum_name()
    {
        var fake = new FakeHelperClient();
        var svc = new RuleFileService(fake, NewTempDir());

        var outcome = await svc.WriteRuleFileAsync(RuleFileKind.BlockedNames, "*.ads.example\n", CancellationToken.None);

        Assert.Equal(RuleFileWriteOutcomeKind.Applied, outcome.Kind);
        var (kind, content) = Assert.Single(fake.WriteRuleFileCalls);
        Assert.Equal("BlockedNames", kind); // the ordinal member NAME, never a path
        Assert.Equal("*.ads.example\n", content);
    }

    [Fact]
    public async Task Write_helper_refusal_maps_to_Rejected_verbatim()
    {
        var fake = new FakeHelperClient
        {
            WriteRuleFileHandler = (_, _, _) =>
                Task.FromResult<Result?>(Result.Fail(IpcErrorCode.ValidationFailed, "A rule line exceeds the 4096-character cap.")),
        };
        var svc = new RuleFileService(fake, NewTempDir());

        var outcome = await svc.WriteRuleFileAsync(RuleFileKind.BlockedNames, "x\n", CancellationToken.None);

        Assert.Equal(RuleFileWriteOutcomeKind.Rejected, outcome.Kind);
        Assert.Equal("A rule line exceeds the 4096-character cap.", outcome.Message); // verbatim (IC-10)
    }

    [Fact]
    public async Task Write_null_helper_reply_maps_to_HelperUnavailable()
    {
        var fake = new FakeHelperClient
        {
            WriteRuleFileHandler = (_, _, _) => Task.FromResult<Result?>(null),
        };
        var svc = new RuleFileService(fake, NewTempDir());

        var outcome = await svc.WriteRuleFileAsync(RuleFileKind.AllowedIps, "10.0.0.1\n", CancellationToken.None);

        Assert.Equal(RuleFileWriteOutcomeKind.HelperUnavailable, outcome.Kind);
        Assert.NotNull(outcome.Message);
    }

    [Fact]
    public async Task Write_oversize_content_maps_to_TooLarge_without_calling_the_helper()
    {
        var fake = new FakeHelperClient();
        var svc = new RuleFileService(fake, NewTempDir());
        // > 1 MiB of body guarantees the serialized frame exceeds IpcSerializer.MaxBytes.
        var huge = new string('a', 1_048_576 + 64);

        var outcome = await svc.WriteRuleFileAsync(RuleFileKind.BlockedNames, huge, CancellationToken.None);

        Assert.Equal(RuleFileWriteOutcomeKind.TooLarge, outcome.Kind);
        Assert.NotNull(outcome.Message);
        Assert.Empty(fake.WriteRuleFileCalls); // pre-check short-circuits — pipe never touched
    }

    [Fact]
    public async Task Write_null_content_throws_ArgumentNullException()
    {
        var svc = new RuleFileService(new FakeHelperClient(), NewTempDir());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => svc.WriteRuleFileAsync(RuleFileKind.BlockedNames, null!, CancellationToken.None));
    }
}
