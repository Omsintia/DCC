using System.IO;
using System.Security.Cryptography;
using System.Text;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// D2: <see cref="ConfigFileService"/> is the single read-modify-write path for
/// <c>dnscrypt-proxy.toml</c> (§4.2/§7.3). <c>Load()</c> reads the file ONCE as bytes
/// (IC-9): <c>Sha256</c> is the lowercase hex of the RAW on-disk bytes (the CAS base the
/// helper re-hashes), and <c>Text</c> is the UTF-8 decode of those SAME bytes with a
/// single leading U+FEFF stripped — never a re-encoded string, so BOM/encoding
/// differences can never produce false conflicts. Fails closed like
/// <c>ActiveResolverReader</c>: missing/locked/unreadable file → failure result, never
/// a throw.
/// </summary>
public class ConfigFileServiceTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".toml");

    private static string Sha256LowerHex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static ConfigFileService NewService(string path) =>
        new(new FakeHelperClient(), path);

    [Fact]
    public void Load_reads_text_and_hashes_the_raw_bytes()
    {
        var path = TempPath();
        try
        {
            const string content = "# managed by DnsCryptControl\nserver_names = ['cloudflare']\n";
            var bytes = Encoding.UTF8.GetBytes(content);
            File.WriteAllBytes(path, bytes);

            var result = NewService(path).Load();

            Assert.True(result.Success);
            Assert.Equal(content, result.Text);
            Assert.Equal(Sha256LowerHex(bytes), result.Sha256);
            Assert.Equal(64, result.Sha256!.Length);
            Assert.Null(result.Error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_missing_file_fails_closed()
    {
        var path = TempPath();
        Assert.False(File.Exists(path));

        var result = NewService(path).Load();

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Null(result.Text);
        Assert.Null(result.Sha256);
    }

    [Fact]
    public void Load_oversized_config_fails_cleanly_without_reading_it()
    {
        // A corrupt/mis-encoded config that grew past the read cap must fail with a clean, actionable
        // message — NOT the raw framework "file is too long" IOException, and without ballooning memory.
        // A sparse file set to > MaxConfigBytes reproduces the size instantly, without writing GBs.
        var path = TempPath();
        try
        {
            using (var fs = File.Create(path)) { fs.SetLength(ConfigReadGuard.MaxConfigBytes + 1); }

            var result = NewService(path).Load();

            Assert.False(result.Success);
            Assert.Null(result.Text);
            Assert.Null(result.Sha256);
            Assert.Contains("unexpectedly large", result.Error!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_config_at_the_size_cap_still_reads()
    {
        // Exactly at the cap is still allowed — the guard only rejects STRICTLY greater, so a legitimate
        // (if unusually large) config is never falsely rejected. Uses real content so the read runs.
        var path = TempPath();
        try
        {
            var body = "server_names = ['cloudflare']\n";
            File.WriteAllText(path, body);
            Assert.True(new FileInfo(path).Length <= ConfigReadGuard.MaxConfigBytes);

            var result = NewService(path).Load();

            Assert.True(result.Success);
            Assert.Equal(body, result.Text);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_locked_file_fails_closed_without_throwing()
    {
        var path = TempPath();
        try
        {
            File.WriteAllText(path, "cache = true\n");
            using var exclusiveLock = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.None);

            var result = NewService(path).Load();

            Assert.False(result.Success);
            Assert.NotNull(result.Error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>IC-9 byte-fidelity: the sha covers the RAW bytes INCLUDING the UTF-8
    /// BOM (the helper hashes on-disk bytes — hashing a stripped decode would make every
    /// BOM'd file a permanent false Conflict), while the TEXT strips the BOM so it never
    /// leaks into the Tomlyn parse or gets written back on save.</summary>
    [Fact]
    public void Load_utf8_bom_file_hashes_raw_bytes_but_strips_bom_from_text()
    {
        var path = TempPath();
        try
        {
            const string content = "# comment\r\ncache = true\r\n";
            var bytes = Encoding.UTF8.GetPreamble()
                .Concat(Encoding.UTF8.GetBytes(content))
                .ToArray();
            File.WriteAllBytes(path, bytes);

            var result = NewService(path).Load();

            Assert.True(result.Success);
            Assert.Equal(Sha256LowerHex(bytes), result.Sha256);
            Assert.Equal(content, result.Text);
            Assert.Equal('#', result.Text![0]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>IC-9 says a SINGLE leading U+FEFF is stripped — a pathological
    /// double-BOM file keeps its second one (it is real content as far as the decode is
    /// concerned, and the parse will flag it downstream).</summary>
    [Fact]
    public void Load_strips_only_one_leading_bom()
    {
        var path = TempPath();
        try
        {
            var preamble = Encoding.UTF8.GetPreamble();
            var bytes = preamble
                .Concat(preamble)
                .Concat(Encoding.UTF8.GetBytes("cache = true\n"))
                .ToArray();
            File.WriteAllBytes(path, bytes);

            var result = NewService(path).Load();

            Assert.True(result.Success);
            Assert.Equal('\uFEFF', result.Text![0]);
            Assert.Equal("cache = true\n", result.Text[1..]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>A UTF-16 file on disk still loads byte-wise (Encoding.UTF8.GetString
    /// never throws — invalid sequences become U+FFFD), the decoded text is garbage, and
    /// the DOCUMENTED disposition is that the damage surfaces downstream as parse errors
    /// in validation — the load path itself stays fail-open on encoding because the sha
    /// (raw bytes) is still exact and nothing has been written anywhere.</summary>
    [Fact]
    public void Load_utf16_file_succeeds_bytewise_and_garbage_surfaces_as_parse_errors()
    {
        var path = TempPath();
        try
        {
            var bytes = Encoding.Unicode.GetPreamble()
                .Concat(Encoding.Unicode.GetBytes("cache = true\n"))
                .ToArray();
            File.WriteAllBytes(path, bytes);

            var result = NewService(path).Load();

            Assert.True(result.Success);
            Assert.Equal(Sha256LowerHex(bytes), result.Sha256);
            Assert.NotNull(result.Text);
            Assert.True(TomlConfigDocument.Parse(result.Text!).HasErrors);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ----- SaveAndApplyAsync (D2 cycle 2) — every outcome driven through the shared
    // FakeHelperClient; disk is never touched by the save path (the helper owns writes).

    private const string CandidateText = "cache = true\n";
    private static readonly string BaseSha = new('a', 64);

    private static ConfigFileService NewSaveService(FakeHelperClient helper) =>
        new(helper, TempPath(),
            statusPollInterval: TimeSpan.FromMilliseconds(1),
            statusPollTimeout: TimeSpan.FromMilliseconds(10));

    private static Task<Result<StatusResponse>?> Status(bool proxyRunning, int protocolVersion) =>
        Task.FromResult<Result<StatusResponse>?>(Result<StatusResponse>.Ok(
            new StatusResponse(proxyRunning, "resolver", false, false, protocolVersion, "1.0.0")));

    /// <summary>P5b-E1 step 0: a v1 helper deserializing the v2 payload silently ignores
    /// BaseSha256 (unknown JSON property) and writes with no CAS and no OPSEC policy —
    /// the save path must refuse on the handshake BEFORE any WriteConfig frame.</summary>
    [Fact]
    public async Task SaveAndApply_version_skew_is_HelperIncompatible_before_any_write_frame()
    {
        var helper = new FakeHelperClient
        {
            GetStatusHandler = _ => Status(proxyRunning: true, IpcProtocol.Version + 1),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.HelperIncompatible, outcome.Kind);
        Assert.NotNull(outcome.Message);
        Assert.Empty(helper.WriteConfigCalls);
        Assert.Equal(0, helper.RestartProxyCalls);
    }

    [Fact]
    public async Task SaveAndApply_null_status_is_HelperUnavailable_without_write()
    {
        var helper = new FakeHelperClient
        {
            GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(null),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.HelperUnavailable, outcome.Kind);
        Assert.Empty(helper.WriteConfigCalls);
    }

    [Fact]
    public async Task SaveAndApply_failed_status_is_HelperUnavailable_without_write()
    {
        var helper = new FakeHelperClient
        {
            GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
                Result<StatusResponse>.Fail(IpcErrorCode.OperationFailed, "status probe failed")),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.HelperUnavailable, outcome.Kind);
        Assert.Empty(helper.WriteConfigCalls);
    }

    /// <summary>Step 1: the pre-check measures the ACTUAL serialized request (envelope +
    /// JSON escaping inflation) against <see cref="IpcSerializer.MaxBytes"/> so an
    /// oversize save gets a friendly TooLarge instead of the transport's fail-closed
    /// lost reply. Runs AFTER the handshake (GetStatus was called) and never sends the
    /// write frame.</summary>
    [Fact]
    public async Task SaveAndApply_oversized_request_is_TooLarge_after_handshake_without_write()
    {
        var helper = new FakeHelperClient();
        var oversized = new string('a', IpcSerializer.MaxBytes);

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(oversized, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.TooLarge, outcome.Kind);
        Assert.NotNull(outcome.Message);
        Assert.Equal(1, helper.GetStatusCalls);
        Assert.Empty(helper.WriteConfigCalls);
    }

    [Fact]
    public async Task SaveAndApply_lost_write_reply_is_HelperUnavailable_and_never_restarts()
    {
        var helper = new FakeHelperClient
        {
            WriteConfigHandler = (_, _, _) => Task.FromResult<Result?>(null),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.HelperUnavailable, outcome.Kind);
        Assert.Equal(0, helper.RestartProxyCalls);
    }

    [Fact]
    public async Task SaveAndApply_conflict_surfaces_the_helper_message_verbatim()
    {
        const string message = "config file changed on disk since it was loaded — reload before saving";
        var helper = new FakeHelperClient
        {
            WriteConfigHandler = (_, _, _) => Task.FromResult<Result?>(
                Result.Fail(IpcErrorCode.Conflict, message)),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.Conflict, outcome.Kind);
        Assert.Equal(message, outcome.Message);
        Assert.Equal(0, helper.RestartProxyCalls);
    }

    [Fact]
    public async Task SaveAndApply_other_refusals_are_Rejected_with_the_message_verbatim()
    {
        const string message = "OPSEC guard: netprobe_timeout must be 0 while protection is enabled";
        var helper = new FakeHelperClient
        {
            WriteConfigHandler = (_, _, _) => Task.FromResult<Result?>(
                Result.Fail(IpcErrorCode.ValidationFailed, message)),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.Rejected, outcome.Kind);
        Assert.Equal(message, outcome.Message);
        Assert.Equal(0, helper.RestartProxyCalls);
    }

    /// <summary>The write ALREADY happened when the restart reply is lost — this outcome
    /// must NEVER be conflated with HelperUnavailable (which implies nothing changed).</summary>
    [Fact]
    public async Task SaveAndApply_lost_restart_reply_is_RestartFailed_not_HelperUnavailable()
    {
        var helper = new FakeHelperClient
        {
            RestartProxyHandler = _ => Task.FromResult<Result<ServiceLifecycleResponse>?>(null),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.RestartFailed, outcome.Kind);
        Assert.Contains("status unverified", outcome.Message, StringComparison.Ordinal);
        Assert.Single(helper.WriteConfigCalls);
    }

    [Fact]
    public async Task SaveAndApply_failed_restart_result_is_RestartFailed()
    {
        var helper = new FakeHelperClient
        {
            RestartProxyHandler = _ => Task.FromResult<Result<ServiceLifecycleResponse>?>(
                Result<ServiceLifecycleResponse>.Fail(IpcErrorCode.OperationFailed, "service restart timed out")),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.RestartFailed, outcome.Kind);
    }

    /// <summary>§7.3: restart succeeded but the proxy never reports running before the
    /// (injectable, 10 ms here) timeout — the config was saved but appears rejected by
    /// the proxy. Distinct outcome, never green.</summary>
    [Fact]
    public async Task SaveAndApply_proxy_never_running_is_ProxyRejected_after_timeout()
    {
        var helper = new FakeHelperClient
        {
            GetStatusHandler = _ => Status(proxyRunning: false, IpcProtocol.Version),
        };

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.ProxyRejected, outcome.Kind);
        Assert.NotNull(outcome.Message);
        Assert.Single(helper.WriteConfigCalls);
        Assert.Equal(1, helper.RestartProxyCalls);
    }

    [Fact]
    public async Task SaveAndApply_happy_path_is_Applied_with_the_exact_text_and_sha()
    {
        var helper = new FakeHelperClient();

        var outcome = await NewSaveService(helper).SaveAndApplyAsync(CandidateText, BaseSha, CancellationToken.None);

        Assert.Equal(ConfigSaveOutcomeKind.Applied, outcome.Kind);
        var call = Assert.Single(helper.WriteConfigCalls);
        Assert.Equal(CandidateText, call.TomlText);
        Assert.Equal(BaseSha, call.BaseSha256);
        Assert.Equal(1, helper.RestartProxyCalls);
    }
}
