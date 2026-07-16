using System.Security.Cryptography;
using System.Text;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>Computes the lowercase-hex SHA-256 of a config text the way the wire
/// contract's <c>WriteConfigPayload.BaseSha256</c> expects (IC-2/IC-9), so tests carry
/// realistic base hashes instead of placeholder strings.</summary>
internal static class TestSha
{
    public static string Of(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
}
