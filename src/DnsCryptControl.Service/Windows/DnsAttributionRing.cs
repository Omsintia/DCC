using System;
using System.Collections.Generic;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// The bounded IN-MEMORY ring behind per-app DNS attribution (v1.3.0): every captured
/// Microsoft-Windows-DNS-Client "query called" event lands here, capped so the helper's memory
/// stays bounded no matter the query volume, and NEVER touches disk — the attribution stream is
/// browsing history, and this app's posture is that browsing history at rest is a bug. Capture
/// AND retention end with the session: the watcher <see cref="Clear"/>s the ring on every session
/// teardown, so records can never outlive the polling session that consented to them (or be
/// replayed to the NEXT session's <c>GetSince(0)</c> — possibly another user's). Sequence
/// numbers are assigned monotonically under the lock so <see cref="GetSince"/> can serve as an
/// exactly-once poll cursor even across eviction (an evicted record's seq is simply skipped;
/// <c>LastSeq</c> still advances) and across <see cref="Clear"/> (the counter is preserved so
/// cursors stay valid). Pure and OS-free by construction so the cursor/eviction contract is
/// unit-testable without ETW; thread-safe because the writer is the ETW callback thread while
/// the reader is the pipe-dispatch thread.
/// </summary>
internal sealed class DnsAttributionRing
{
    private readonly int _capacity;
    private readonly Queue<DnsAttributionRecord> _records;
    private readonly object _gate = new();
    private long _lastSeq;

    /// <summary>Creates a ring holding at most <paramref name="capacity"/> records; the oldest
    /// record is evicted past that so memory stays bounded regardless of query volume.</summary>
    internal DnsAttributionRing(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
        _records = new Queue<DnsAttributionRecord>(capacity);
    }

    /// <summary>Appends one captured event, assigning the next monotonically increasing sequence
    /// number under the lock (the ETW callback thread races the pipe reader), and evicts the
    /// oldest record past the cap. Returns the assigned sequence number.</summary>
    internal long Add(long unixTimeMs, int processId, string queryName, string? processName)
    {
        ArgumentNullException.ThrowIfNull(queryName);
        lock (_gate)
        {
            var seq = ++_lastSeq;
            _records.Enqueue(new DnsAttributionRecord(seq, unixTimeMs, processId, queryName, processName));
            if (_records.Count > _capacity)
            {
                _records.Dequeue();
            }

            return seq;
        }
    }

    /// <summary>Drops every retained record — the retention half of the privacy contract: called by
    /// the watcher on session teardown so the captured browsing history dies with the session that
    /// consented to it. PRESERVES the monotonic sequence counter (a post-clear <see cref="Add"/>
    /// continues from it, and <see cref="GetSince"/> still reports it as <c>LastSeq</c>), so an
    /// in-flight poller's cursor stays valid instead of silently rewinding.</summary>
    internal void Clear()
    {
        lock (_gate)
        {
            _records.Clear();
        }
    }

    /// <summary>Returns the records with <c>Seq &gt; afterSeq</c>, oldest → newest, plus the
    /// ring's current <c>LastSeq</c> — reported even when every newer record was already evicted,
    /// so a slow poller's cursor skips ahead instead of replaying the whole ring forever.</summary>
    internal DnsAttributionSnapshot GetSince(long afterSeq)
    {
        lock (_gate)
        {
            List<DnsAttributionRecord>? matched = null;
            foreach (var record in _records)
            {
                if (record.Seq > afterSeq)
                {
                    (matched ??= new List<DnsAttributionRecord>()).Add(record);
                }
            }

            return new DnsAttributionSnapshot(
                _lastSeq, (IReadOnlyList<DnsAttributionRecord>?)matched ?? Array.Empty<DnsAttributionRecord>());
        }
    }
}
