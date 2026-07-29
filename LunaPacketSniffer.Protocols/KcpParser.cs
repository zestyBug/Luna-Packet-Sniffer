using System.Buffers.Binary;

namespace LunaPacketSniffer.Protocols;

public readonly record struct KcpSegment(
    uint ConversationId,
    string Command,
    byte FragmentCount,
    uint SequenceNumber,
    uint Unacknowledged,
    ReadOnlyMemory<byte> Payload);

/// <summary>
/// Heuristic KCP segment reader. KCP has no port or magic number of its own, so a payload is only
/// accepted when the command byte is known and the declared length matches exactly.
/// </summary>
public static class KcpParser
{
    private const int HeaderLength = 24;

    public static bool TryParse(ReadOnlySpan<byte> payload, out KcpSegment segment)
    {
        segment = default;
        if (payload.Length < HeaderLength)
        {
            return false;
        }

        var command = payload[4] switch
        {
            81 => "PUSH",
            82 => "ACK",
            83 => "WASK",
            84 => "WINS",
            _ => null,
        };
        if (command is null)
        {
            return false;
        }

        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(payload[20..]);
        if (payloadLength != payload.Length - HeaderLength)
        {
            return false;
        }

        segment = new KcpSegment(
            BinaryPrimitives.ReadUInt32LittleEndian(payload),
            command,
            payload[5],
            BinaryPrimitives.ReadUInt32LittleEndian(payload[12..]),
            BinaryPrimitives.ReadUInt32LittleEndian(payload[16..]),
            payload[HeaderLength..].ToArray());
        return true;
    }
}
