using System.Linq;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>The bounded in-memory attribution ring (v1.3.0): the seq-cursor contract the
/// GetDnsAttributions poll depends on — monotonic sequence numbers, GetSince filtering + ordering,
/// cap eviction, and a LastSeq that advances past evicted records so a slow poller skips ahead
/// instead of replaying forever.</summary>
public class DnsAttributionRingTests
{
    [Fact]
    public void EmptyRing_reportsLastSeqZero_andNoRecords()
    {
        var ring = new DnsAttributionRing(capacity: 4);

        var snapshot = ring.GetSince(0);

        Assert.Equal(0, snapshot.LastSeq);
        Assert.Empty(snapshot.Records);
    }

    [Fact]
    public void Add_assignsMonotonicallyIncreasingSeq_startingAtOne()
    {
        var ring = new DnsAttributionRing(capacity: 4);

        Assert.Equal(1, ring.Add(1000, 10, "a.example", "chrome"));
        Assert.Equal(2, ring.Add(1001, 11, "b.example", "firefox"));
        Assert.Equal(3, ring.Add(1002, 12, "c.example", null));
    }

    [Fact]
    public void GetSince_filtersBySeq_andReturnsOldestToNewest()
    {
        var ring = new DnsAttributionRing(capacity: 8);
        ring.Add(1000, 10, "a.example", "chrome");
        ring.Add(1001, 11, "b.example", "firefox");
        ring.Add(1002, 12, "c.example", null);

        var snapshot = ring.GetSince(1);

        Assert.Equal(3, snapshot.LastSeq);
        Assert.Equal(new long[] { 2, 3 }, snapshot.Records.Select(r => r.Seq).ToArray());
        Assert.Equal("b.example", snapshot.Records[0].QueryName);
        Assert.Equal("c.example", snapshot.Records[1].QueryName);
        Assert.Equal(11, snapshot.Records[0].ProcessId);
        Assert.Null(snapshot.Records[1].ProcessName);
    }

    [Fact]
    public void GetSince_atOrPastTheNewestSeq_returnsNoRecords_butStillTheLastSeq()
    {
        var ring = new DnsAttributionRing(capacity: 8);
        ring.Add(1000, 10, "a.example", "chrome");
        ring.Add(1001, 11, "b.example", "firefox");

        Assert.Empty(ring.GetSince(2).Records);
        Assert.Equal(2, ring.GetSince(2).LastSeq);
        Assert.Empty(ring.GetSince(99).Records);
        Assert.Equal(2, ring.GetSince(99).LastSeq);
    }

    [Fact]
    public void PastTheCap_theOldestRecordIsEvicted_andSeqKeepsAdvancing()
    {
        var ring = new DnsAttributionRing(capacity: 3);
        for (var i = 1; i <= 5; i++)
        {
            ring.Add(1000 + i, i, "q" + i + ".example", "app" + i);
        }

        var snapshot = ring.GetSince(0);

        // Only the newest 3 survive (seq 3..5); LastSeq reflects everything ever added.
        Assert.Equal(5, snapshot.LastSeq);
        Assert.Equal(new long[] { 3, 4, 5 }, snapshot.Records.Select(r => r.Seq).ToArray());
        Assert.DoesNotContain(snapshot.Records, r => r.QueryName == "q1.example");
    }

    [Fact]
    public void SlowPollerCursor_skipsAheadViaLastSeq_evenWhenItsRecordsWereEvicted()
    {
        // The cursor contract: a poller that last saw seq 1 but slept through an eviction wave
        // gets whatever survives plus the CURRENT LastSeq, so its next poll starts fresh instead
        // of replaying a cursor the ring can no longer honour.
        var ring = new DnsAttributionRing(capacity: 2);
        ring.Add(1000, 1, "a.example", null);
        ring.Add(1001, 2, "b.example", null);
        ring.Add(1002, 3, "c.example", null); // evicts seq 1

        var snapshot = ring.GetSince(1);

        Assert.Equal(3, snapshot.LastSeq);
        Assert.Equal(new long[] { 2, 3 }, snapshot.Records.Select(r => r.Seq).ToArray());
    }

    [Fact]
    public void Clear_dropsRecords_preservesTheSeqCounter_andSeqContinuesMonotonically()
    {
        // The retention half of the privacy contract: the watcher clears the ring on session
        // teardown, and the wipe must NOT rewind the seq counter — a cursor issued before the
        // clear stays valid, and post-clear records never reuse an already-consumed seq.
        var ring = new DnsAttributionRing(capacity: 4);
        ring.Add(1000, 10, "a.example", "chrome");
        ring.Add(1001, 11, "b.example", "firefox");

        ring.Clear();

        var snapshot = ring.GetSince(0);
        Assert.Empty(snapshot.Records);
        Assert.Equal(2, snapshot.LastSeq);

        Assert.Equal(3, ring.Add(1002, 12, "c.example", null));
        Assert.Equal(new long[] { 3 }, ring.GetSince(0).Records.Select(r => r.Seq).ToArray());
    }

    [Fact]
    public void RecordFields_areStoredVerbatim()
    {
        var ring = new DnsAttributionRing(capacity: 4);
        ring.Add(1_752_800_000_123, 4242, "Sub.Example.COM.", "msedge");

        var record = Assert.Single(ring.GetSince(0).Records);

        // The ring is a dumb bounded buffer: qname casing/dots are preserved verbatim —
        // normalization is the UI-side correlator's job, not the helper's.
        Assert.Equal(1_752_800_000_123, record.UnixTimeMs);
        Assert.Equal(4242, record.ProcessId);
        Assert.Equal("Sub.Example.COM.", record.QueryName);
        Assert.Equal("msedge", record.ProcessName);
    }
}
