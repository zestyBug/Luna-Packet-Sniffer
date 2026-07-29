using System.Net;
using System.Text;
using LunaPacketSniffer.Networking;

namespace LunaPacketSniffer.Protocols;

/// <summary>
/// Classifies a single packet in isolation. Protocols that need connection state (reassembled HTTP,
/// KCP conversations) are handled by <see cref="ProtocolAnalyzerSession"/> instead.
/// </summary>
public static class PacketAnalyzer
{
    private const int DnsPort = 53;
    private const int HttpPort = 80;
    private const int MaxStartLineScan = 512;
    private const int MaxHeaderScan = 8_192;

    public static PacketAnalysis Analyze(byte[] packet) =>
        Analyze(packet, PacketDecoder.TryDecode(packet, out var decoded) ? decoded : null);

    /// <summary>
    /// Classifies a packet whose IP/transport headers have already been decoded, so callers that
    /// need the decoded form anyway do not pay for a second decode.
    /// </summary>
    public static PacketAnalysis Analyze(byte[] packet, DecodedPacket? decoded)
    {
        if (decoded is null)
        {
            return TryAnalyzeIcmp(packet, out var icmp)
                ? icmp
                : new PacketAnalysis("Raw", string.Empty, "Unknown", "Unknown");
        }

        var (protocol, summary) = Classify(decoded);
        return new PacketAnalysis(protocol, summary, decoded.Source.ToString(), decoded.Destination.ToString());
    }

    private static (string Protocol, string Summary) Classify(DecodedPacket decoded)
    {
        var payload = decoded.Payload.Span;
        if (decoded.Source.Port == DnsPort || decoded.Destination.Port == DnsPort)
        {
            return ("DNS", DnsParser.TryGetQuestion(payload, out var question) ? question : "DNS");
        }

        if (decoded.Protocol == IpProtocol.Udp && KcpParser.TryParse(payload, out var kcp))
        {
            return ("KCP", $"conv={kcp.ConversationId} {kcp.Command} sn={kcp.SequenceNumber} una={kcp.Unacknowledged}");
        }

        if (decoded.Protocol == IpProtocol.Tcp && TlsParser.TryGetServerName(payload, out var serverName))
        {
            return ("TLS", $"SNI: {serverName}");
        }

        if (decoded.Protocol == IpProtocol.Tcp && (decoded.Source.Port == HttpPort || decoded.Destination.Port == HttpPort) &&
            TryGetHttpSummary(payload) is { } httpSummary)
        {
            return ("HTTP", httpSummary);
        }

        return (IpProtocol.GetName(decoded.Protocol), string.Empty);
    }

    /// <summary>ICMP is not decoded by <see cref="PacketDecoder"/>, so it is recognised from the raw IP header here.</summary>
    private static bool TryAnalyzeIcmp(ReadOnlySpan<byte> packet, out PacketAnalysis analysis)
    {
        analysis = default!;
        if (packet.Length < 8)
        {
            return false;
        }

        var version = packet[0] >> 4;
        var (isIcmp, headerLength, source, destination, protocol) = version switch
        {
            4 when packet.Length >= 28 => (
                packet[9] == IpProtocol.Icmp,
                (packet[0] & 0x0F) * 4,
                new IPAddress(packet.Slice(12, 4)).ToString(),
                new IPAddress(packet.Slice(16, 4)).ToString(),
                "ICMP"),
            6 when packet.Length >= 48 => (
                packet[6] == IpProtocol.IcmpV6,
                40,
                new IPAddress(packet.Slice(8, 16)).ToString(),
                new IPAddress(packet.Slice(24, 16)).ToString(),
                "ICMPv6"),
            _ => (false, 0, string.Empty, string.Empty, string.Empty),
        };
        if (!isIcmp || packet.Length < headerLength + 2)
        {
            return false;
        }

        analysis = new PacketAnalysis(protocol, $"Type {packet[headerLength]}, Code {packet[headerLength + 1]}", source, destination);
        return true;
    }

    internal static string? TryGetHttpStartLine(ReadOnlySpan<byte> payload)
    {
        var length = Math.Min(payload.Length, MaxStartLineScan);
        if (length == 0)
        {
            return null;
        }

        var text = Encoding.ASCII.GetString(payload[..length]);
        var lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
        if (lineEnd <= 0)
        {
            return null;
        }

        var line = text[..lineEnd];
        return line.StartsWith("HTTP/", StringComparison.Ordinal) || IsRequestLine(line) ? line : null;
    }

    /// <summary>Returns the request URL, or the status line for a response.</summary>
    internal static string? TryGetHttpSummary(ReadOnlySpan<byte> payload)
    {
        var line = TryGetHttpStartLine(payload);
        if (line is null || line.StartsWith("HTTP/", StringComparison.Ordinal))
        {
            return line;
        }

        var firstSpace = line.IndexOf(' ');
        var lastSpace = line.LastIndexOf(' ');
        if (firstSpace <= 0 || firstSpace == lastSpace)
        {
            return line;
        }

        var target = line[(firstSpace + 1)..lastSpace];
        if (Uri.TryCreate(target, UriKind.Absolute, out var absoluteUri))
        {
            return absoluteUri.ToString();
        }

        // An origin-form target only becomes a URL once the Host header is known.
        var headers = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, MaxHeaderScan)]);
        foreach (var header in headers.Split("\r\n", StringSplitOptions.None))
        {
            if (!header.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var host = header[5..].Trim();
            return host.Length == 0 ? target : $"http://{host}{target}";
        }

        return target;
    }

    private static bool IsRequestLine(string line) =>
        line.StartsWith("GET ", StringComparison.Ordinal) ||
        line.StartsWith("POST ", StringComparison.Ordinal) ||
        line.StartsWith("PUT ", StringComparison.Ordinal) ||
        line.StartsWith("DELETE ", StringComparison.Ordinal) ||
        line.StartsWith("HEAD ", StringComparison.Ordinal);
}
