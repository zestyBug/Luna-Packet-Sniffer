using System.Text;
using LunaPacketSniffer.Networking;

namespace LunaPacketSniffer.Protocols;

public sealed record PacketAnalysis(string Protocol, string Summary, string Source, string Destination);

public static class PacketAnalyzer
{
    public static PacketAnalysis Analyze(byte[] packet)
    {
        if (!PacketDecoder.TryDecode(packet, out var decoded))
        {
            return TryAnalyzeIcmp(packet, out var icmp)
                ? icmp
                : new PacketAnalysis("Raw", string.Empty, "Unknown", "Unknown");
        }

        var decodedPacket = decoded!;
        var protocol = decodedPacket.Protocol == 6 ? "TCP" : "UDP";
        var summary = string.Empty;
        if (decodedPacket.Source.Port == 53 || decodedPacket.Destination.Port == 53)
        {
            protocol = "DNS";
            summary = DnsParser.TryGetQuestion(decodedPacket.Payload.Span, out var question) ? question : "DNS";
        }
        else if (decodedPacket.Protocol == 17 && KcpParser.TryParse(decodedPacket.Payload.Span, out var kcp))
        {
            protocol = "KCP";
            summary = $"conv={kcp.ConversationId} {kcp.Command} sn={kcp.SequenceNumber} una={kcp.Unacknowledged}";
        }
        else if (decodedPacket.Protocol == 6 && TlsParser.TryGetServerName(decodedPacket.Payload.Span, out var serverName))
        {
            protocol = "TLS";
            summary = $"SNI: {serverName}";
        }
        else if (decodedPacket.Protocol == 6 && (decodedPacket.Source.Port == 80 || decodedPacket.Destination.Port == 80))
        {
            var httpSummary = TryGetHttpSummary(decodedPacket.Payload.Span);
            if (httpSummary is not null)
            {
                protocol = "HTTP";
                summary = httpSummary;
            }
        }

        return new PacketAnalysis(protocol, summary, decodedPacket.Source.ToString(), decodedPacket.Destination.ToString());
    }

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
            4 when packet.Length >= 28 => (packet[9] == 1, (packet[0] & 0x0F) * 4, new System.Net.IPAddress(packet.Slice(12, 4)).ToString(), new System.Net.IPAddress(packet.Slice(16, 4)).ToString(), "ICMP"),
            6 when packet.Length >= 48 => (packet[6] == 58, 40, new System.Net.IPAddress(packet.Slice(8, 16)).ToString(), new System.Net.IPAddress(packet.Slice(24, 16)).ToString(), "ICMPv6"),
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
        var length = Math.Min(payload.Length, 512);
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
        return line.StartsWith("HTTP/", StringComparison.Ordinal) ||
               line.StartsWith("GET ", StringComparison.Ordinal) ||
               line.StartsWith("POST ", StringComparison.Ordinal) ||
               line.StartsWith("PUT ", StringComparison.Ordinal) ||
               line.StartsWith("DELETE ", StringComparison.Ordinal) ||
               line.StartsWith("HEAD ", StringComparison.Ordinal)
            ? line
            : null;
    }

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

        var length = Math.Min(payload.Length, 8_192);
        var headers = Encoding.ASCII.GetString(payload[..length]);
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
}

public readonly record struct KcpSegment(uint ConversationId, string Command, byte FragmentCount, uint SequenceNumber, uint Unacknowledged, ReadOnlyMemory<byte> Payload);

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

        var payloadLength = ReadUInt32LittleEndian(payload, 20);
        if (payloadLength != payload.Length - HeaderLength)
        {
            return false;
        }

        segment = new KcpSegment(
            ReadUInt32LittleEndian(payload, 0),
            command,
            payload[5],
            ReadUInt32LittleEndian(payload, 12),
            ReadUInt32LittleEndian(payload, 16),
            payload[HeaderLength..].ToArray());
        return true;
    }

    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> bytes, int offset) =>
        (uint)bytes[offset] |
        ((uint)bytes[offset + 1] << 8) |
        ((uint)bytes[offset + 2] << 16) |
        ((uint)bytes[offset + 3] << 24);
}

internal static class TlsParser
{
    public static bool TryGetServerName(ReadOnlySpan<byte> payload, out string serverName)
    {
        serverName = string.Empty;
        if (payload.Length < 9 || payload[0] != 22 || payload[5] != 1)
        {
            return false;
        }

        var recordLength = ReadUInt16BigEndian(payload, 3);
        var handshakeLength = ReadUInt24BigEndian(payload, 6);
        if (payload.Length < 5 + recordLength || handshakeLength + 4 > recordLength)
        {
            return false;
        }

        var offset = 9 + 2 + 32;
        if (offset >= payload.Length)
        {
            return false;
        }

        var sessionIdLength = payload[offset++];
        offset += sessionIdLength;
        if (!TryReadLengthPrefixedSection(payload, ref offset, 2, out _) ||
            !TryReadLengthPrefixedSection(payload, ref offset, 1, out _) ||
            !TryReadLengthPrefixedSection(payload, ref offset, 2, out var extensions))
        {
            return false;
        }

        var extensionOffset = 0;
        while (extensionOffset + 4 <= extensions.Length)
        {
            var extensionType = ReadUInt16BigEndian(extensions, extensionOffset);
            var extensionLength = ReadUInt16BigEndian(extensions, extensionOffset + 2);
            extensionOffset += 4;
            if (extensionOffset + extensionLength > extensions.Length)
            {
                return false;
            }

            if (extensionType == 0 && TryGetServerNameExtension(extensions.Slice(extensionOffset, extensionLength), out serverName))
            {
                return true;
            }

            extensionOffset += extensionLength;
        }

        return false;
    }

    private static bool TryGetServerNameExtension(ReadOnlySpan<byte> extension, out string serverName)
    {
        serverName = string.Empty;
        if (extension.Length < 5)
        {
            return false;
        }

        var listLength = ReadUInt16BigEndian(extension, 0);
        if (listLength + 2 > extension.Length || extension[2] != 0)
        {
            return false;
        }

        var nameLength = ReadUInt16BigEndian(extension, 3);
        if (nameLength == 0 || nameLength + 5 > extension.Length)
        {
            return false;
        }

        serverName = Encoding.ASCII.GetString(extension.Slice(5, nameLength));
        return true;
    }

    private static bool TryReadLengthPrefixedSection(ReadOnlySpan<byte> source, ref int offset, int lengthSize, out ReadOnlySpan<byte> section)
    {
        section = default;
        if (offset + lengthSize > source.Length)
        {
            return false;
        }

        var length = lengthSize == 1 ? source[offset] : ReadUInt16BigEndian(source, offset);
        offset += lengthSize;
        if (offset + length > source.Length)
        {
            return false;
        }

        section = source.Slice(offset, length);
        offset += length;
        return true;
    }

    private static int ReadUInt16BigEndian(ReadOnlySpan<byte> source, int offset) => (source[offset] << 8) | source[offset + 1];

    private static int ReadUInt24BigEndian(ReadOnlySpan<byte> source, int offset) =>
        (source[offset] << 16) | (source[offset + 1] << 8) | source[offset + 2];
}

public sealed class ProtocolAnalyzerSession
{
    private readonly Dictionary<string, TcpStreamAssembler> _streams = [];
    private readonly Dictionary<string, string> _requestUrls = [];
    private readonly KcpConversationTracker _kcpConversations = new();

    public event Action<KcpConversationUpdate>? KcpConversationObserved;

    public PacketAnalysis Analyze(byte[] packet)
    {
        var analysis = PacketAnalyzer.Analyze(packet);
        if (PacketDecoder.TryDecode(packet, out var decodedKcp) && decodedKcp is not null && _kcpConversations.Observe(decodedKcp) is { } kcpConversation)
        {
            KcpConversationObserved?.Invoke(kcpConversation);
        }
        if (!PacketDecoder.TryDecode(packet, out var decoded) || decoded is null ||
            decoded.Protocol != 6 || (decoded.Source.Port != 80 && decoded.Destination.Port != 80) ||
            decoded.TcpSequenceNumber is null || decoded.Payload.IsEmpty)
        {
            return analysis;
        }

        var directionKey = $"{decoded.Source}>{decoded.Destination}";
        if (!_streams.TryGetValue(directionKey, out var stream))
        {
            stream = new TcpStreamAssembler();
            _streams.Add(directionKey, stream);
        }

        var contiguous = stream.Append(decoded.TcpSequenceNumber.Value, decoded.Payload.Span);
        var summary = PacketAnalyzer.TryGetHttpSummary(contiguous.Span);
        if (summary is null)
        {
            return analysis;
        }

        var connectionKey = GetConnectionKey(decoded.Source.ToString(), decoded.Destination.ToString());
        if (summary.StartsWith("HTTP/", StringComparison.Ordinal))
        {
            return _requestUrls.TryGetValue(connectionKey, out var requestUrl)
                ? analysis with { Protocol = "HTTP", Summary = requestUrl }
                : analysis with { Protocol = "HTTP", Summary = summary };
        }

        _requestUrls[connectionKey] = summary;
        return analysis with { Protocol = "HTTP", Summary = summary };
    }

    private static string GetConnectionKey(string firstEndpoint, string secondEndpoint) =>
        string.CompareOrdinal(firstEndpoint, secondEndpoint) < 0
            ? $"{firstEndpoint}|{secondEndpoint}"
            : $"{secondEndpoint}|{firstEndpoint}";
}

public sealed class TcpStreamAssembler
{
    private readonly SortedDictionary<uint, byte[]> _segments = [];
    private uint? _nextSequence;
    private readonly List<byte> _contiguous = [];

    public ReadOnlyMemory<byte> Contiguous => _contiguous.ToArray();
    public long RetransmissionCount { get; private set; }
    public long OutOfOrderCount { get; private set; }
    public long MissingByteCount { get; private set; }

    public ReadOnlyMemory<byte> Append(uint sequence, ReadOnlySpan<byte> payload)
    {
        if (_nextSequence is null)
        {
            _nextSequence = sequence;
        }

        if (IsBefore(sequence, _nextSequence.Value) || _segments.ContainsKey(sequence))
        {
            RetransmissionCount++;
            return _contiguous.ToArray();
        }

        if (sequence != _nextSequence.Value)
        {
            OutOfOrderCount++;
        }

        _segments.Add(sequence, payload.ToArray());
        while (_nextSequence is { } expected && _segments.Remove(expected, out var segment))
        {
            _contiguous.AddRange(segment);
            _nextSequence = unchecked(expected + (uint)segment.Length);
        }

        UpdateMissingByteCount();

        if (_contiguous.Count > 1_048_576)
        {
            _contiguous.Clear();
            _segments.Clear();
            _nextSequence = null;
            MissingByteCount = 0;
        }

        return _contiguous.ToArray();
    }

    private void UpdateMissingByteCount()
    {
        if (_nextSequence is null || _segments.Count == 0)
        {
            MissingByteCount = 0;
            return;
        }

        uint? nearestSequence = null;
        uint nearestDistance = uint.MaxValue;
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

    private static bool IsBefore(uint first, uint second) => unchecked((int)(first - second)) < 0;
}

internal static class DnsParser
{
    public static bool TryGetQuestion(ReadOnlySpan<byte> payload, out string question)
    {
        question = string.Empty;
        if (payload.Length < 12 || ((payload[4] << 8) | payload[5]) == 0)
        {
            return false;
        }

        var offset = 12;
        var labels = new List<string>();
        while (offset < payload.Length)
        {
            var length = payload[offset++];
            if (length == 0)
            {
                break;
            }

            if ((length & 0xC0) != 0 || offset + length > payload.Length)
            {
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(payload.Slice(offset, length)));
            offset += length;
        }

        if (labels.Count == 0 || offset + 4 > payload.Length)
        {
            return false;
        }

        question = string.Join('.', labels);
        return true;
    }
}
