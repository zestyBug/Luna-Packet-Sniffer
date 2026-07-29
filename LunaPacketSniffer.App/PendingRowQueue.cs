using System.Collections.Concurrent;
using System.Collections.ObjectModel;

namespace LunaPacketSniffer.App;

/// <summary>
/// Moves rows produced on the capture thread into the bound collections on the UI thread. Draining is
/// capped per tick so a burst of traffic cannot stall the dispatcher.
/// </summary>
internal static class PendingRowQueue
{
    /// <summary>
    /// Queues a UI update while retaining only the newest entries when the dispatcher cannot keep up.
    /// Capture output is written before these events are raised, so trimming affects the live view only.
    /// </summary>
    public static void Enqueue<TRow>(ConcurrentQueue<TRow> pending, TRow row, int maxPendingRows)
        where TRow : class
    {
        pending.Enqueue(row);
        while (pending.Count > maxPendingRows && pending.TryDequeue(out _))
        {
        }
    }

    /// <summary>Appends queued rows, trimming the oldest ones past <paramref name="maxRows"/>.</summary>
    /// <returns>The last row added, or <see langword="null"/> when nothing was queued.</returns>
    public static TRow? Drain<TRow>(
        ConcurrentQueue<TRow> pending,
        ObservableCollection<TRow> rows,
        int maxPerDrain,
        int maxRows)
        where TRow : class
    {
        TRow? lastAdded = null;
        for (var added = 0; added < maxPerDrain && pending.TryDequeue(out var row); added++)
        {
            if (rows.Count >= maxRows)
            {
                rows.RemoveAt(0);
            }

            rows.Add(row);
            lastAdded = row;
        }

        return lastAdded;
    }

    /// <summary>
    /// Applies queued updates to existing rows, creating a row the first time a key is seen. Used by the
    /// flow and KCP grids, where each row aggregates many updates instead of growing the list.
    /// </summary>
    /// <returns>The last row touched, or <see langword="null"/> when nothing was queued.</returns>
    public static TRow? DrainKeyed<TUpdate, TRow>(
        ConcurrentQueue<TUpdate> pending,
        ObservableCollection<TRow> rows,
        Dictionary<string, TRow> rowsByKey,
        int maxPerDrain,
        Func<TUpdate, string> selectKey,
        Func<TUpdate, TRow> createRow,
        Action<TRow, TUpdate> applyUpdate)
        where TRow : class
    {
        TRow? lastUpdated = null;
        for (var updated = 0; updated < maxPerDrain && pending.TryDequeue(out var update); updated++)
        {
            var key = selectKey(update);
            if (!rowsByKey.TryGetValue(key, out var row))
            {
                row = createRow(update);
                rowsByKey.Add(key, row);
                rows.Add(row);
            }

            applyUpdate(row, update);
            lastUpdated = row;
        }

        return lastUpdated;
    }
}
