using LunaPacketSniffer.Networking;

namespace LunaPacketSniffer.Protocols;

/// <summary>
/// Stateful analysis across a whole capture. Adds what a single packet cannot show: HTTP summaries
/// recovered from reassembled streams, response rows labelled with their request URL, and KCP
/// conversation tracking.
/// </summary>
public sealed class ProtocolAnalyzerSession
{
    private const int HttpPort = 80;

    private readonly Dictionary<string, TcpStreamAssembler> _streams = [];
    private readonly Dictionary<string, string> _requestUrls = [];
    private readonly KcpConversationTracker _kcpConversations = new();

    public event Action<KcpConversationUpdate>? KcpConversationObserved;

    public PacketAnalysis Analyze(byte[] packet) =>
        Analyze(packet, PacketDecoder.TryDecode(packet, out var decoded) ? decoded : null);

    /// <summary>
    /// Analyses a packet whose IP/transport headers have already been decoded. The capture pipeline
    /// decodes each packet once and passes the result here and to the flow table.
    /// </summary>
    public PacketAnalysis Analyze(byte[] packet, DecodedPacket? decoded)
    {
        var analysis = PacketAnalyzer.Analyze(packet, decoded);
        if (decoded is null)
        {
            return analysis;
        }

        if (_kcpConversations.Observe(decoded) is { } kcpConversation)
        {
            KcpConversationObserved?.Invoke(kcpConversation);
        }

        if (decoded.Protocol != IpProtocol.Tcp ||
            (decoded.Source.Port != HttpPort && decoded.Destination.Port != HttpPort) ||
            decoded.TcpSequenceNumber is not { } sequenceNumber ||
            decoded.Payload.IsEmpty)
        {
            return analysis;
        }

        return TryGetReassembledSummary(decoded, sequenceNumber) is { } summary
            ? analysis with { Protocol = "HTTP", Summary = summary }
            : analysis;
    }

    private string? TryGetReassembledSummary(DecodedPacket decoded, uint sequenceNumber)
    {
        var directionKey = $"{decoded.Source}>{decoded.Destination}";
        if (!_streams.TryGetValue(directionKey, out var stream))
        {
            stream = new TcpStreamAssembler();
            _streams.Add(directionKey, stream);
        }

        var contiguous = stream.Append(sequenceNumber, decoded.Payload.Span);
        var summary = PacketAnalyzer.TryGetHttpSummary(contiguous.Span);
        if (summary is null)
        {
            return null;
        }

        // A response row is more useful showing the URL it answers than its own status line.
        var connectionKey = GetConnectionKey(decoded.Source.ToString(), decoded.Destination.ToString());
        if (summary.StartsWith("HTTP/", StringComparison.Ordinal))
        {
            return _requestUrls.TryGetValue(connectionKey, out var requestUrl) ? requestUrl : summary;
        }

        _requestUrls[connectionKey] = summary;
        return summary;
    }

    /// <summary>An endpoint-order-independent key, so both directions of a connection map to one entry.</summary>
    private static string GetConnectionKey(string firstEndpoint, string secondEndpoint) =>
        string.CompareOrdinal(firstEndpoint, secondEndpoint) < 0
            ? $"{firstEndpoint}|{secondEndpoint}"
            : $"{secondEndpoint}|{firstEndpoint}";
}
