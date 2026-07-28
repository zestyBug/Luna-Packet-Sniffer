using LunaPacketSniffer.Networking;
using LunaPacketSniffer.Protocols;
using Xunit;

namespace LunaPacketSniffer.Protocols.Tests;

public sealed class PacketParserTests
{
    [Fact]
    public void AnalyzesIpv4Icmp()
    {
        var packet = new byte[28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[12] = 192;
        packet[13] = 0;
        packet[14] = 2;
        packet[15] = 1;
        packet[16] = 198;
        packet[17] = 51;
        packet[18] = 100;
        packet[19] = 1;
        packet[20] = 8;

        var analysis = PacketAnalyzer.Analyze(packet);

        Assert.Equal("ICMP", analysis.Protocol);
        Assert.Equal("Type 8, Code 0", analysis.Summary);
        Assert.Equal("192.0.2.1", analysis.Source);
        Assert.Equal("198.51.100.1", analysis.Destination);
    }

    [Fact]
    public void ReassemblesOutOfOrderTcpSegmentsAndReportsGapsAndRetransmissions()
    {
        var stream = new TcpStreamAssembler();

        stream.Append(100, "ab"u8);
        stream.Append(104, "ef"u8);
        Assert.Equal(1, stream.OutOfOrderCount);
        Assert.Equal(2, stream.MissingByteCount);

        stream.Append(102, "cd"u8);
        stream.Append(100, "ab"u8);

        Assert.Equal("abcdef", System.Text.Encoding.ASCII.GetString(stream.Contiguous.Span));
        Assert.Equal(0, stream.MissingByteCount);
        Assert.Equal(1, stream.RetransmissionCount);
    }

    [Fact]
    public void DecodesIpv4UdpPayload()
    {
        var packet = new byte[]
        {
            0x45, 0, 0, 31, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            0x04, 0xD2, 0x16, 0x2E, 0, 11, 0, 0, (byte)'A', (byte)'B', (byte)'C',
        };

        Assert.True(PacketDecoder.TryDecode(packet, out var value));
        var decoded = Assert.IsType<DecodedPacket>(value);

        Assert.Equal((byte)17, decoded.Protocol);
        Assert.Equal("1.2.3.4:1234", decoded.Source.ToString());
        Assert.Equal("5.6.7.8:5678", decoded.Destination.ToString());
        Assert.Equal("ABC", System.Text.Encoding.ASCII.GetString(decoded.Payload.Span));
    }

    [Fact]
    public void ParsesKcpPushSegment()
    {
        var payload = new byte[]
        {
            0x12, 0x34, 0x56, 0x78, 81, 0, 0x80, 0,
            0, 0, 0, 0, 7, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0,
            (byte)'K', (byte)'C', (byte)'P',
        };

        Assert.True(KcpParser.TryParse(payload, out var segment));

        Assert.Equal(0x78563412u, segment.ConversationId);
        Assert.Equal("PUSH", segment.Command);
        Assert.Equal((byte)0, segment.FragmentCount);
        Assert.Equal(7u, segment.SequenceNumber);
        Assert.Equal(3u, segment.Unacknowledged);
        Assert.Equal("KCP", System.Text.Encoding.ASCII.GetString(segment.Payload.Span));
    }

    [Fact]
    public void RejectsKcpSegmentWithMismatchedLength()
    {
        var payload = new byte[24];
        payload[4] = 81;
        payload[20] = 1;

        Assert.False(KcpParser.TryParse(payload, out _));
    }
}
