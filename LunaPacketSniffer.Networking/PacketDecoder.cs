using System.Net;

namespace LunaPacketSniffer.Networking;

public sealed record DecodedPacket(
    byte Protocol,
    IPEndPoint Source,
    IPEndPoint Destination,
    ReadOnlyMemory<byte> Payload,
    uint? TcpSequenceNumber);

public static class PacketDecoder
{
    public static bool TryDecode(byte[] packet, out DecodedPacket? decodedPacket)
    {
        decodedPacket = null;
        if (packet.Length < 20)
        {
            return false;
        }

        var version = packet[0] >> 4;
        if (version == 4)
        {
            return TryDecodeIpv4(packet, out decodedPacket);
        }

        return version == 6 && TryDecodeIpv6(packet, out decodedPacket);
    }

    private static bool TryDecodeIpv4(byte[] packet, out DecodedPacket? decodedPacket)
    {
        decodedPacket = null;
        var headerLength = (packet[0] & 0x0F) * 4;
        if (headerLength < 20 || packet.Length < headerLength)
        {
            return false;
        }

        return TryDecodeTransport(
            packet[9],
            new IPAddress(packet.AsSpan(12, 4)),
            new IPAddress(packet.AsSpan(16, 4)),
            packet.AsMemory(headerLength),
            out decodedPacket);
    }

    private static bool TryDecodeIpv6(byte[] packet, out DecodedPacket? decodedPacket)
    {
        decodedPacket = null;
        if (packet.Length < 40)
        {
            return false;
        }

        return TryDecodeTransport(
            packet[6],
            new IPAddress(packet.AsSpan(8, 16)),
            new IPAddress(packet.AsSpan(24, 16)),
            packet.AsMemory(40),
            out decodedPacket);
    }

    private static bool TryDecodeTransport(
        byte protocol,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ReadOnlyMemory<byte> transport,
        out DecodedPacket? decodedPacket)
    {
        decodedPacket = null;
        if (protocol is not 6 and not 17 || transport.Length < 4)
        {
            return false;
        }

        var span = transport.Span;
        var sourcePort = ReadPort(span, 0);
        var destinationPort = ReadPort(span, 2);
        var payloadOffset = protocol == 6
            ? transport.Length >= 20 ? ((span[12] >> 4) * 4) : 0
            : 8;
        if (payloadOffset == 0 || transport.Length < payloadOffset)
        {
            return false;
        }

        uint? sequenceNumber = protocol == 6 ? ReadUInt32(span, 4) : null;
        decodedPacket = new DecodedPacket(
            protocol,
            new IPEndPoint(sourceAddress, sourcePort),
            new IPEndPoint(destinationAddress, destinationPort),
            transport[payloadOffset..],
            sequenceNumber);
        return true;
    }

    private static ushort ReadPort(ReadOnlySpan<byte> bytes, int offset) =>
        (ushort)((bytes[offset] << 8) | bytes[offset + 1]);

    private static uint ReadUInt32(ReadOnlySpan<byte> bytes, int offset) =>
        ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3];
}
