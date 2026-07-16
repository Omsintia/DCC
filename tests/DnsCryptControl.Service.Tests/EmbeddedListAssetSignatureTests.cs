using System.IO;
using System.Text;
using DnsCryptControl.Service.Supplychain;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>
/// Every bundled source-list asset (the ODoH caches and the default public-resolvers cache) must
/// carry a VALID detached minisign signature from the DNSCrypt resolver-list key — the same key
/// dnscrypt-proxy pins in the shipped config, so the proxy re-verifies these exact bytes on load
/// (a drift-lock test asserts the toml's minisign_key equals the pinned constant). This guards two
/// failure modes at once: a supply-chain slip when refreshing a committed asset, and any byte
/// mangling on the way to the placed cache (git line-ending rewrite, embed re-encode) that would
/// make the seeded cache FATAL to the proxy at start. Verification goes through the SAME
/// <see cref="ResolverListSignature"/> the store's seed-health check uses, so the test and the
/// product can never diverge on what "valid" means.
/// </summary>
public class EmbeddedListAssetSignatureTests
{
    [Theory]
    [InlineData("public-resolvers.md")]
    [InlineData("relays.md")]
    [InlineData("odoh-servers.md")]
    [InlineData("odoh-relays.md")]
    public void embedded_list_asset_verifies_against_the_pinned_resolver_list_key(string assetName)
    {
        var asm = typeof(FileSystemConfigStore).Assembly;
        var fileBytes = ReadResource(asm, assetName);
        var minisigText = Encoding.UTF8.GetString(ReadResource(asm, assetName + ".minisig"));

        Assert.True(
            ResolverListSignature.VerifiesWithPinnedKey(fileBytes, minisigText, assetName),
            $"minisign verification failed for the embedded asset {assetName}");
    }

    [Fact]
    public void verifier_rejects_a_tampered_list_and_a_renamed_asset()
    {
        var asm = typeof(FileSystemConfigStore).Assembly;
        var fileBytes = ReadResource(asm, "public-resolvers.md");
        var minisigText = Encoding.UTF8.GetString(ReadResource(asm, "public-resolvers.md.minisig"));

        var tampered = (byte[])fileBytes.Clone();
        tampered[0] ^= 0x01;
        Assert.False(ResolverListSignature.VerifiesWithPinnedKey(tampered, minisigText, "public-resolvers.md"));

        // The trusted-comment file: assertion refuses a signature transplanted onto another name.
        Assert.False(ResolverListSignature.VerifiesWithPinnedKey(fileBytes, minisigText, "relays.md"));

        // Malformed signature text is a clean false, never a throw.
        Assert.False(ResolverListSignature.VerifiesWithPinnedKey(fileBytes, "not a minisig", "public-resolvers.md"));
        Assert.False(ResolverListSignature.VerifiesWithPinnedKey(System.Array.Empty<byte>(), minisigText, "public-resolvers.md"));
    }

    private static byte[] ReadResource(System.Reflection.Assembly asm, string logicalName)
    {
        using var stream = asm.GetManifestResourceStream(logicalName);
        Assert.NotNull(stream);
        using var ms = new MemoryStream();
        stream!.CopyTo(ms);
        var bytes = ms.ToArray();
        Assert.NotEmpty(bytes);
        return bytes;
    }
}
