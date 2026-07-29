namespace LunaPacketSniffer.Protocols;

/// <summary>
/// Reassembles one direction of a TCP stream from possibly out-of-order segments, tracking
/// retransmissions and gaps. Reassembly is dropped once the stream exceeds
/// <see cref="MaxContiguousBytes"/> so a long-lived connection cannot grow without bound.
/// </summary>
public sealed class TcpStreamAssembler
{
    private const int MaxContiguousBytes = 1_048_576;
    private const int MinimumCapacity = 4_096;

    private readonly SortedDictionary<uint, byte[]> _segments = [];
    private byte[] _contiguous = [];
    private int _contiguousLength;
    private uint? _nextSequence;

    /// <summary>
    /// The bytes reassembled so far. This is a view over an internal buffer that a later
    /// <see cref="Append"/> may overwrite, so read it before appending again.
    /// </summary>
    public ReadOnlyMemory<byte> Contiguous => _contiguous.AsMemory(0, _contiguousLength);

    public long RetransmissionCount { get; private set; }
    public long OutOfOrderCount { get; private set; }
    public long MissingByteCount { get; private set; }

    public ReadOnlyMemory<byte> Append(uint sequence, ReadOnlySpan<byte> payload)
    {
        _nextSequence ??= sequence;

        if (IsBefore(sequence, _nextSequence.Value) || _segments.ContainsKey(sequence))
        {
            RetransmissionCount++;
            return Contiguous;
        }

        if (sequence != _nextSequence.Value)
        {
            OutOfOrderCount++;
        }

        _segments.Add(sequence, payload.ToArray());
        while (_nextSequence is { } expected && _segments.Remove(expected, out var segment))
        {
            AppendContiguous(segment);
            _nextSequence = unchecked(expected + (uint)segment.Length);
        }

        UpdateMissingByteCount();

        if (_contiguousLength > MaxContiguousBytes)
        {
            Reset();
        }

        return Contiguous;
    }

    private void AppendContiguous(ReadOnlySpan<byte> segment)
    {
        var required = _contiguousLength + segment.Length;
        if (required > _contiguous.Length)
        {
            Array.Resize(ref _contiguous, Math.Max(required, Math.Max(MinimumCapacity, _contiguous.Length * 2)));
        }

        segment.CopyTo(_contiguous.AsSpan(_contiguousLength));
        _contiguousLength = required;
    }

    private void Reset()
    {
        _contiguous = [];
        _contiguousLength = 0;
        _segments.Clear();
        _nextSequence = null;
        MissingByteCount = 0;
    }

    /// <summary>The distance from the next expected sequence number to the nearest buffered segment.</summary>
    private void UpdateMissingByteCount()
    {
        if (_nextSequence is null || _segments.Count == 0)
        {
            MissingByteCount = 0;
            return;
        }

        uint? nearestSequence = null;
        var nearestDistance = uint.MaxValue;
        foreach (var sequence in _segments.Keys)
        {
            var distance = unchecked(sequence - _nextSequence.Value);
            if (distance < nearestDistance)
            {
                nearestSequence = sequence;
                nearestDistance = distance;
            }
        }

        MissingByteCount = nearestSequence is null || IsBefore(nearestSequence.Value, _nextSequence.Value) ? 0 : nearestDistance;
    }

    /// <summary>Sequence-number comparison that tolerates 32-bit wraparound.</summary>
    private static bool IsBefore(uint first, uint second) => unchecked((int)(first - second)) < 0;
}
