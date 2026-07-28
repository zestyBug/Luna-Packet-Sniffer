namespace LunaPacketSniffer.Persistence;

internal sealed class WebSocketMessageReader
{
    private readonly List<byte> _data = [];
    private readonly List<byte> _fragments = [];
    private byte? _fragmentOpcode;

    public void Append(ReadOnlySpan<byte> data, bool isRequest, DateTimeOffset timestamp, Action<WebSocketMessage> messageObserved)
    {
        foreach (var value in data)
        {
            _data.Add(value);
        }

        while (TryReadFrame(out var frame))
        {
            if (frame.Opcode == 0)
            {
                if (_fragmentOpcode is null)
                {
                    continue;
                }

                _fragments.AddRange(frame.Payload);
                if (frame.Final)
                {
                    messageObserved(new WebSocketMessage(timestamp, isRequest, GetOpcodeName(_fragmentOpcode.Value), _fragments.ToArray()));
                    _fragments.Clear();
                    _fragmentOpcode = null;
                }

                continue;
            }

            if (frame.Opcode is 1 or 2)
            {
                if (frame.Final)
                {
                    messageObserved(new WebSocketMessage(timestamp, isRequest, GetOpcodeName(frame.Opcode), frame.Payload));
                }
                else
                {
                    _fragmentOpcode = frame.Opcode;
                    _fragments.Clear();
                    _fragments.AddRange(frame.Payload);
                }

                continue;
            }

            messageObserved(new WebSocketMessage(timestamp, isRequest, GetOpcodeName(frame.Opcode), frame.Payload));
        }
    }

    private bool TryReadFrame(out WebSocketFrame frame)
    {
        frame = default;
        if (_data.Count < 2)
        {
            return false;
        }

        var first = _data[0];
        var second = _data[1];
        var final = (first & 0x80) != 0;
        var opcode = (byte)(first & 0x0F);
        var masked = (second & 0x80) != 0;
        var payloadLength = (ulong)(second & 0x7F);
        var offset = 2;
        if (payloadLength == 126)
        {
            if (_data.Count < offset + 2)
            {
                return false;
            }

            payloadLength = (uint)(_data[offset] << 8 | _data[offset + 1]);
            offset += 2;
        }
        else if (payloadLength == 127)
        {
            if (_data.Count < offset + 8)
            {
                return false;
            }

            payloadLength = 0;
            for (var index = 0; index < 8; index++)
            {
                payloadLength = (payloadLength << 8) | _data[offset + index];
            }

            offset += 8;
        }

        var maskLength = masked ? 4 : 0;
        if (payloadLength > int.MaxValue)
        {
            throw new InvalidDataException("WebSocket frame is too large.");
        }

        var length = (int)payloadLength;
        if (_data.Count < offset + maskLength + length)
        {
            return false;
        }

        var maskOffset = offset;
        offset += maskLength;
        var payload = _data.GetRange(offset, length).ToArray();
        if (masked)
        {
            for (var index = 0; index < payload.Length; index++)
            {
                payload[index] ^= _data[maskOffset + index % 4];
            }
        }

        _data.RemoveRange(0, offset + length);
        frame = new WebSocketFrame(final, opcode, payload);
        return true;
    }

    private static string GetOpcodeName(byte opcode) => opcode switch
    {
        0 => "Continuation",
        1 => "Text",
        2 => "Binary",
        8 => "Close",
        9 => "Ping",
        10 => "Pong",
        _ => $"Opcode {opcode}",
    };

    private readonly record struct WebSocketFrame(bool Final, byte Opcode, byte[] Payload);
}

public sealed record WebSocketMessage(DateTimeOffset Timestamp, bool IsRequest, string Opcode, byte[] Data, string? FilePath = null);
