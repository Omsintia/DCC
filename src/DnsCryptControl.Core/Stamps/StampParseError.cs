namespace DnsCryptControl.Core.Stamps;

/// <summary>Why an <c>sdns://</c> string failed to parse (fail-closed — a UI surfaces the reason).</summary>
public enum StampParseErrorKind
{
    /// <summary>No error (the parse succeeded).</summary>
    None = 0,

    /// <summary>Missing the <c>sdns:</c> prefix, or null/empty input.</summary>
    NotAStamp,

    /// <summary>Input exceeds the hardening length cap.</summary>
    TooLarge,

    /// <summary>The base64url envelope is malformed (bad alphabet, padding, whitespace, or non-canonical).</summary>
    InvalidBase64,

    /// <summary>Decoded to zero bytes — no protocol id.</summary>
    Empty,

    /// <summary>The protocol id is not one this parser recognizes.</summary>
    UnknownProtocol,

    /// <summary>A length-prefixed field runs past the end of the buffer (truncated), or is too short for its type.</summary>
    Truncated,

    /// <summary>Extra bytes after the last field (the reference rejects this).</summary>
    TrailingGarbage,

    /// <summary>A DNSCrypt public key is not exactly 32 bytes (a hostile length would crash the proxy at load).</summary>
    InvalidPublicKeyLength,

    /// <summary>A certificate hash is neither empty nor exactly 32 bytes.</summary>
    InvalidHashLength,

    /// <summary>An address field is not a valid IP literal (for a type that requires one).</summary>
    InvalidAddress,

    /// <summary>A port is out of range 1..65535 or malformed.</summary>
    InvalidPort,

    /// <summary>A string field (hostname/path/provider) carries a NUL, control char, or invalid UTF-8 — a config/UI injection surface.</summary>
    InvalidString,

    /// <summary>The composite <c>sdns://relay/server</c> form is malformed.</summary>
    InvalidComposite,
}

/// <summary>A typed parse failure with a human-actionable detail (IC-10).</summary>
public readonly record struct StampParseError(StampParseErrorKind Kind, string Detail)
{
    /// <summary>The success sentinel.</summary>
    public static readonly StampParseError None = new(StampParseErrorKind.None, "");

    /// <summary>True when this represents a failed parse.</summary>
    public bool IsError => Kind != StampParseErrorKind.None;

    public override string ToString() => IsError ? $"{Kind}: {Detail}" : "None";
}
