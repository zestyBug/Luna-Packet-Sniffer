using System.Globalization;
using System.Text;

namespace LunaPacketSniffer.Persistence.Http;

/// <summary>
/// Accumulates one direction of an HTTP/1.x byte stream and pops complete messages out of it.
///
/// Bytes live in a single growable buffer with a consumed-prefix offset instead of being copied out
/// of the front, and both the header scan and the chunked-body scan remember how far they already
/// read. A body arriving in many pieces therefore costs time proportional to its size rather than to
/// its size squared.
/// </summary>
internal sealed class HttpMessageBuffer
{
    private const int InitialCapacity = 8 * 1_024;

    private static ReadOnlySpan<byte> HeaderTerminator => "\r\n\r\n"u8;
    private static ReadOnlySpan<byte> LineTerminator => "\r\n"u8;

    private readonly List<byte> _chunkBody = [];
    private byte[] _buffer = [];
    private int _start;
    private int _end;

    /// <summary>How far the header scan already looked without finding a terminator.</summary>
    private int _headerScanned;

    /// <summary>Where the next chunk header starts, or -1 when no chunked body is in progress.</summary>
    private int _chunkPosition = -1;

    public void Append(ReadOnlySpan<byte> data)
    {
        EnsureCapacity(data.Length);
        data.CopyTo(_buffer.AsSpan(_end));
        _end += data.Length;
    }

    /// <summary>
    /// Pops the next complete message. Returns <see langword="false"/> when more bytes are needed;
    /// the buffered data is left untouched so the next call can retry.
    /// </summary>
    public bool TryRead(out HttpMessage message)
    {
        message = default!;
        var headerEnd = FindHeaderEnd();
        if (headerEnd < 0)
        {
            return false;
        }

        var headerText = Encoding.ASCII.GetString(_buffer.AsSpan(_start, headerEnd - _start));
        var headers = HttpHeader.Parse(headerText);
        var bodyStart = headerEnd + HeaderTerminator.Length;
        byte[] body;
        int messageEnd;
        if (IsChunked(headers))
        {
            if (!TryReadChunkedBody(bodyStart, out body, out messageEnd))
            {
                return false;
            }
        }
        else
        {
            var bodyLength = GetBodyLength(headers, TryGetResponseStatus(headerText));
            if (_end - bodyStart < bodyLength)
            {
                return false;
            }

            body = _buffer.AsSpan(bodyStart, bodyLength).ToArray();
            messageEnd = bodyStart + bodyLength;
        }

        _start = messageEnd;
        _headerScanned = _start;
        message = HttpMessage.Parse(headerText, headers, body);
        return message.IsRequest || message.Status > 0;
    }

    /// <summary>Takes everything still buffered, used when a connection switches to WebSocket framing.</summary>
    public byte[] Drain()
    {
        var data = _buffer.AsSpan(_start, _end - _start).ToArray();
        _start = 0;
        _end = 0;
        _headerScanned = 0;
        ResetChunkState();
        return data;
    }

    private int FindHeaderEnd()
    {
        // Resume where the last unsuccessful scan stopped, overlapping by the terminator length so a
        // terminator split across two appends is still found.
        var from = Math.Max(_start, _headerScanned - (HeaderTerminator.Length - 1));
        var index = IndexOf(from, HeaderTerminator);
        if (index < 0)
        {
            _headerScanned = _end;
        }

        return index;
    }

    private bool TryReadChunkedBody(int bodyStart, out byte[] body, out int messageEnd)
    {
        body = [];
        messageEnd = 0;
        if (_chunkPosition < bodyStart)
        {
            _chunkPosition = bodyStart;
            _chunkBody.Clear();
        }

        while (true)
        {
            var chunkHeaderStart = _chunkPosition;
            var lineEnd = IndexOf(chunkHeaderStart, LineTerminator);
            if (lineEnd < 0 || !TryParseChunkLength(_buffer.AsSpan(chunkHeaderStart, lineEnd - chunkHeaderStart), out var length))
            {
                _chunkPosition = chunkHeaderStart;
                return false;
            }

            var chunkDataStart = lineEnd + LineTerminator.Length;
            if (length == 0)
            {
                return TryFinishChunkedBody(chunkHeaderStart, chunkDataStart, out body, out messageEnd);
            }

            var chunkEnd = (long)chunkDataStart + length + LineTerminator.Length;
            if (_end < chunkEnd ||
                _buffer[chunkDataStart + length] != (byte)'\r' ||
                _buffer[chunkDataStart + length + 1] != (byte)'\n')
            {
                _chunkPosition = chunkHeaderStart;
                return false;
            }

            _chunkBody.AddRange(_buffer.AsSpan(chunkDataStart, length));
            _chunkPosition = (int)chunkEnd;
        }
    }

    /// <summary>Consumes the terminating zero-length chunk and any trailer headers that follow it.</summary>
    private bool TryFinishChunkedBody(int chunkHeaderStart, int trailerStart, out byte[] body, out int messageEnd)
    {
        body = [];
        messageEnd = 0;
        if (_end < trailerStart + LineTerminator.Length)
        {
            _chunkPosition = chunkHeaderStart;
            return false;
        }

        if (_buffer[trailerStart] == (byte)'\r' && _buffer[trailerStart + 1] == (byte)'\n')
        {
            messageEnd = trailerStart + LineTerminator.Length;
        }
        else
        {
            var trailerEnd = IndexOf(trailerStart, HeaderTerminator);
            if (trailerEnd < 0)
            {
                _chunkPosition = chunkHeaderStart;
                return false;
            }

            messageEnd = trailerEnd + HeaderTerminator.Length;
        }

        body = _chunkBody.ToArray();
        ResetChunkState();
        return true;
    }

    private void ResetChunkState()
    {
        _chunkPosition = -1;
        _chunkBody.Clear();
    }

    private int IndexOf(int from, ReadOnlySpan<byte> value)
    {
        if (from < 0 || from > _end)
        {
            return -1;
        }

        var index = _buffer.AsSpan(from, _end - from).IndexOf(value);
        return index < 0 ? -1 : from + index;
    }

    /// <summary>Grows the buffer, compacting the consumed prefix away first when that is enough.</summary>
    private void EnsureCapacity(int additional)
    {
        if (_end + additional <= _buffer.Length)
        {
            return;
        }

        var length = _end - _start;
        if (_start > 0 && length + additional <= _buffer.Length)
        {
            _buffer.AsSpan(_start, length).CopyTo(_buffer);
            ShiftOffsets(_start);
            return;
        }

        var grown = new byte[Math.Max(Math.Max(InitialCapacity, _buffer.Length * 2), length + additional)];
        _buffer.AsSpan(_start, length).CopyTo(grown);
        _buffer = grown;
        ShiftOffsets(_start);
    }

    private void ShiftOffsets(int consumed)
    {
        _end -= consumed;
        _start = 0;
        _headerScanned = Math.Max(0, _headerScanned - consumed);
        if (_chunkPosition >= 0)
        {
            _chunkPosition = Math.Max(0, _chunkPosition - consumed);
        }
    }

    private static bool TryParseChunkLength(ReadOnlySpan<byte> line, out int length)
    {
        var text = Encoding.ASCII.GetString(line);
        var separator = text.IndexOf(';');
        return int.TryParse(
            separator < 0 ? text : text[..separator],
            NumberStyles.HexNumber,
            CultureInfo.InvariantCulture,
            out length) && length >= 0;
    }

    private static int GetBodyLength(List<HttpHeader> headers, int? responseStatus)
    {
        // Informational, no-content, and not-modified responses never carry a body.
        if (responseStatus is 100 or 101 or 102 or 103 or 204 or 304)
        {
            return 0;
        }

        return int.TryParse(HttpHeader.GetValue(headers, "Content-Length"), out var length) && length >= 0 ? length : 0;
    }

    private static bool IsChunked(List<HttpHeader> headers) =>
        HttpHeader.GetValue(headers, "Transfer-Encoding")?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true;

    private static int? TryGetResponseStatus(string headerText)
    {
        var firstLine = headerText.Split("\r\n", 2, StringSplitOptions.None)[0];
        var parts = firstLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && parts[0].StartsWith("HTTP/", StringComparison.Ordinal) && int.TryParse(parts[1], out var status)
            ? status
            : null;
    }
}
