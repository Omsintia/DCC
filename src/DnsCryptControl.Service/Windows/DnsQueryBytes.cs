using System;
using System.Collections.Generic;
using System.Text;

namespace DnsCryptControl.Service.Windows;

/// <summary>Builds a minimal, standards-correct DNS query for a single A record (QTYPE=1, QCLASS=IN).
/// Used only to ping the loopback proxy on 127.0.0.1:53 / [::1]:53 and confirm it answers — the bytes
/// never traverse the Windows resolver. Pure function: no I/O, no state.</summary>
internal static class DnsQueryBytes
{
    /// <summary>Builds the wire bytes of an A-record query for <paramref name="name"/> with transaction
    /// id <paramref name="id"/>. Header: ID, flags RD=1 (0x0100), QDCOUNT=1, AN/NS/AR=0. Then the QNAME
    /// (length-prefixed labels + zero root), QTYPE=0x0001, QCLASS=0x0001.</summary>
    /// <exception cref="ArgumentException">name is empty, or a label is empty/over 63 bytes.</exception>
    internal static byte[] BuildAQuery(string name, ushort id)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        // Reject names with empty labels: consecutive dots, or a leading dot (e.g. ".foo", "a..b").
        // A single trailing dot (root notation "foo.test.") is stripped before splitting; anything
        // else that produces an empty label is malformed.
        var normalised = name.EndsWith('.') ? name[..^1] : name;
        if (normalised.StartsWith('.') || normalised.Contains(".."))
            throw new ArgumentException(
                "DNS name contains an empty label (consecutive dots or leading dot).", nameof(name));

        var buf = new List<byte>(32)
        {
            (byte)(id >> 8), (byte)(id & 0xFF), // ID
            0x01, 0x00,                          // flags: RD=1
            0x00, 0x01,                          // QDCOUNT=1
            0x00, 0x00,                          // ANCOUNT=0
            0x00, 0x00,                          // NSCOUNT=0
            0x00, 0x00,                          // ARCOUNT=0
        };

        foreach (var label in normalised.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            if (labelBytes.Length is 0 or > 63)
                throw new ArgumentException($"DNS label '{label}' must be 1..63 bytes.", nameof(name));
            buf.Add((byte)labelBytes.Length);
            buf.AddRange(labelBytes);
        }

        if (buf.Count <= 12)
            throw new ArgumentException("DNS name produced no labels.", nameof(name));

        buf.Add(0x00);              // root label terminator
        buf.Add(0x00); buf.Add(0x01); // QTYPE = A
        buf.Add(0x00); buf.Add(0x01); // QCLASS = IN
        return buf.ToArray();
    }
}
