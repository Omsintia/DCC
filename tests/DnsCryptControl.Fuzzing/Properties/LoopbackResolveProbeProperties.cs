using System;
using CsCheck;
using DnsCryptControl.Service.Windows;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for <see cref="LoopbackResolveProbe.IsValidProxyResponse"/> after the F4
/// hardening (2026-07-09): the loopback liveness probe now requires the response to echo the exact question
/// it sent (QDCOUNT=1 + a byte-exact QNAME/QTYPE/QCLASS at offset 12), not just a well-formed header with an
/// accepted RCODE. Oracles: the validator is TOTAL (never throws) + deterministic over arbitrary bytes; a
/// correctly-echoed NOERROR/NXDOMAIN response (with or without a trailing answer) is accepted; ANY tamper of
/// a single echoed-question byte is rejected; a bare 12-byte header (no question) is always rejected; and a
/// wrong RCODE is rejected even with a perfect echo. The question is never compression-compressed, so a
/// byte-exact compare is the correct oracle. See the fuzzing design notes.
/// </summary>
public class LoopbackResolveProbeProperties
{
    private static readonly Gen<ushort> IdGen = Gen.Int[0, 65535].Select(i => (ushort)i);
    private static readonly Gen<int> AcceptedRcode = Gen.Int[0, 1].Select(i => i == 0 ? 0 : 3); // NOERROR | NXDOMAIN
    private static readonly Gen<byte[]> QuestionGen = Gen.Byte.Array[1, 40]; // echo compare never parses it

    // A response frame: header (id, QR=1, QDCOUNT=1, rcode) + the echoed question + an optional trailing answer.
    private static byte[] BuildResponse(ushort id, int rcode, byte[] question, byte[] answer)
    {
        var buf = new byte[12 + question.Length + answer.Length];
        buf[0] = (byte)(id >> 8); buf[1] = (byte)(id & 0xFF);
        buf[2] = 0x80;                 // QR=1
        buf[3] = (byte)rcode;
        buf[4] = 0x00; buf[5] = 0x01;  // QDCOUNT=1
        Array.Copy(question, 0, buf, 12, question.Length);
        Array.Copy(answer, 0, buf, 12 + question.Length, answer.Length);
        return buf;
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Total_and_deterministic_over_arbitrary_bytes() =>
        Gen.Select(Gen.Byte.Array[0, 64], Gen.Int[0, 65535], Gen.Byte.Array[0, 20],
            (buf, id, question) => (buf, id, question)).Sample(t =>
        {
            // A throw would fail the property; the result is deterministic for the same inputs.
            var a = LoopbackResolveProbe.IsValidProxyResponse(t.buf, (ushort)t.id, t.question);
            var b = LoopbackResolveProbe.IsValidProxyResponse(t.buf, (ushort)t.id, t.question);
            return a == b;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Accepts_a_correctly_echoed_response() =>
        Gen.Select(IdGen, QuestionGen, AcceptedRcode, Gen.Byte.Array[0, 30],
            (id, question, rcode, answer) => (id, question, rcode, answer)).Sample(t =>
        {
            var buf = BuildResponse(t.id, t.rcode, t.question, t.answer);
            return LoopbackResolveProbe.IsValidProxyResponse(buf, t.id, t.question);
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Rejects_any_single_byte_tamper_of_the_question_echo() =>
        Gen.Select(IdGen, QuestionGen, AcceptedRcode, Gen.Int[0, 1000], Gen.Int[1, 255],
            (id, question, rcode, idx, xor) => (id, question, rcode, idx, xor)).Sample(t =>
        {
            var buf = BuildResponse(t.id, t.rcode, t.question, Array.Empty<byte>());
            // Flip at least one bit of a byte inside the echoed-question region -> the exact compare must fail.
            var target = 12 + (t.idx % t.question.Length);
            buf[target] ^= (byte)t.xor;
            return !LoopbackResolveProbe.IsValidProxyResponse(buf, t.id, t.question);
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Rejects_a_bare_header_with_no_question_echo() =>
        Gen.Select(IdGen, QuestionGen, AcceptedRcode, (id, question, rcode) => (id, question, rcode)).Sample(t =>
        {
            // A 12-byte header: matching id, QR=1, an accepted RCODE, QDCOUNT=0, no question bytes.
            var buf = new byte[12];
            buf[0] = (byte)(t.id >> 8); buf[1] = (byte)(t.id & 0xFF);
            buf[2] = 0x80;
            buf[3] = (byte)t.rcode;
            return !LoopbackResolveProbe.IsValidProxyResponse(buf, t.id, t.question);
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Rejects_a_wrong_rcode_even_with_a_perfect_echo() =>
        Gen.Select(IdGen, QuestionGen, Gen.Int[0, 15], Gen.Byte.Array[0, 20],
            (id, question, rcode, answer) => (id, question, rcode, answer)).Sample(t =>
        {
            var buf = BuildResponse(t.id, t.rcode, t.question, t.answer);
            var accepted = t.rcode is 0 or 3;
            return LoopbackResolveProbe.IsValidProxyResponse(buf, t.id, t.question) == accepted;
        }, iter: Fuzz.Iter);
}
