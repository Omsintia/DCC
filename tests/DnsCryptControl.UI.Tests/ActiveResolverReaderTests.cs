using System.IO;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// C1: best-effort reader of the first configured <c>server_names</c> entry from
/// <c>dnscrypt-proxy.toml</c>, via Core's <c>TomlConfigDocument</c>. Purely
/// informational — never a source of protection truth — so every failure mode fails
/// closed to <c>null</c> rather than throwing.
/// </summary>
public class ActiveResolverReaderTests
{
    [Fact]
    public void Reads_first_server_names_entry_from_a_temp_toml()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".toml");
        try
        {
            File.WriteAllText(path,
                """
                server_names = ['cloudflare', 'quad9-doh-ip4-filter-pri']
                listen_addresses = ['127.0.0.1:53']
                """);

            var reader = new ActiveResolverReader(path);

            var name = reader.ReadPrimaryName();

            Assert.Equal("cloudflare", name);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Missing_file_returns_null()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".toml");
        Assert.False(File.Exists(path));

        var reader = new ActiveResolverReader(path);

        Assert.Null(reader.ReadPrimaryName());
    }

    [Fact]
    public void Empty_server_names_array_returns_null()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".toml");
        try
        {
            File.WriteAllText(path, "server_names = []\n");

            var reader = new ActiveResolverReader(path);

            Assert.Null(reader.ReadPrimaryName());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Malformed_toml_returns_null()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".toml");
        try
        {
            File.WriteAllText(path, "server_names = [[[not valid");

            var reader = new ActiveResolverReader(path);

            Assert.Null(reader.ReadPrimaryName());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Missing_server_names_key_returns_null()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".toml");
        try
        {
            File.WriteAllText(path, "listen_addresses = ['127.0.0.1:53']\n");

            var reader = new ActiveResolverReader(path);

            Assert.Null(reader.ReadPrimaryName());
        }
        finally
        {
            File.Delete(path);
        }
    }
}
