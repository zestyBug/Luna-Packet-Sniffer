using System.ComponentModel;
using System.Text;
using LunaPacketSniffer.App.Formatting;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Protocols;

namespace LunaPacketSniffer.App.ViewModels;

/// <summary>
/// A row in the TCP / UDP Flows grid. Live rows accumulate their own reassembled streams;
/// rows restored from a saved capture reassemble on demand through <c>storedStreamDetailLoader</c>.
/// </summary>
public sealed class FlowSessionListItem : INotifyPropertyChanged
{
    private const int TextPreviewMaxBytes = 16_384;

    private readonly TcpStreamAssembler _inboundStream = new();
    private readonly TcpStreamAssembler _outboundStream = new();
    private readonly Func<string>? _storedStreamDetailLoader;
    private long _packetCount;
    private long _byteCount;

    public FlowSessionListItem(FlowRecord flow)
    {
        ProcessId = flow.Process.ProcessId.ToString();
        ProcessName = flow.Process.ProcessName;
        Protocol = flow.Key.Protocol == 6 ? "TCP" : "UDP";
        LocalEndpoint = $"{flow.Key.LocalAddress}:{flow.Key.LocalPort}";
        RemoteEndpoint = $"{flow.Key.RemoteAddress}:{flow.Key.RemotePort}";
        Detail = CreateDetail(includeCounts: false);
    }

    public FlowSessionListItem(
        string processId,
        string processName,
        string protocol,
        string localEndpoint,
        string remoteEndpoint,
        long packetCount,
        long byteCount,
        Func<string>? storedStreamDetailLoader)
    {
        ProcessId = processId;
        ProcessName = processName;
        Protocol = protocol;
        LocalEndpoint = localEndpoint;
        RemoteEndpoint = remoteEndpoint;
        _packetCount = packetCount;
        _byteCount = byteCount;
        _storedStreamDetailLoader = storedStreamDetailLoader;
        Detail = CreateDetail(includeCounts: true);
    }

    public string ProcessId { get; }
    public string ProcessName { get; }
    public string Protocol { get; }
    public string LocalEndpoint { get; }
    public string RemoteEndpoint { get; }
    public long PacketCount => _packetCount;
    public long ByteCount => _byteCount;
    public string Detail { get; private set; }
    public event PropertyChangedEventHandler? PropertyChanged;

    public string GetDetail() =>
        _storedStreamDetailLoader is null
            ? Detail
            : $"{Detail}{Environment.NewLine}{Environment.NewLine}{_storedStreamDetailLoader()}";

    public void AddPacket(FlowUpdate update)
    {
        _packetCount++;
        _byteCount += update.Length;
        if (Protocol == "TCP" && update.TcpSequenceNumber is { } sequence && update.Payload.Length > 0)
        {
            var stream = update.Direction == PacketDirection.Outbound ? _outboundStream : _inboundStream;
            stream.Append(sequence, update.Payload);
        }

        Detail = CreateDetail(includeCounts: true, CreateTcpStreamDetail());
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(PacketCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ByteCount)));
    }

    private string CreateDetail(bool includeCounts, string suffix = "")
    {
        var newLine = Environment.NewLine;
        var detail = new StringBuilder()
            .Append($"Process: {ProcessName} ({ProcessId})")
            .Append($"{newLine}Protocol: {Protocol}")
            .Append($"{newLine}Local: {LocalEndpoint}")
            .Append($"{newLine}Remote: {RemoteEndpoint}");
        if (includeCounts)
        {
            detail.Append($"{newLine}Packets: {_packetCount:N0}")
                  .Append($"{newLine}Bytes: {_byteCount:N0}");
        }

        return detail.Append(suffix).ToString();
    }

    private string CreateTcpStreamDetail() =>
        Protocol == "TCP" ? FormatStreamPair(_outboundStream, _inboundStream, leadingBlankLines: true) : string.Empty;

    /// <summary>Renders the outbound/inbound stream previews shown under a TCP flow.</summary>
    internal static string FormatStreamPair(TcpStreamAssembler outbound, TcpStreamAssembler inbound, bool leadingBlankLines = false)
    {
        var newLine = Environment.NewLine;
        var prefix = leadingBlankLines ? $"{newLine}{newLine}" : string.Empty;
        return $"{prefix}Outbound stream preview:{newLine}{FormatStream(outbound)}{newLine}{newLine}Inbound stream preview:{newLine}{FormatStream(inbound)}";
    }

    private static string FormatStream(TcpStreamAssembler stream)
    {
        var data = stream.Contiguous;
        var preview = data.Span[..Math.Min(data.Length, TextPreviewMaxBytes)];
        var text = new StringBuilder(preview.Length + 4_096);
        text.AppendLine($"Retransmissions: {stream.RetransmissionCount:N0}");
        text.AppendLine($"Out of order: {stream.OutOfOrderCount:N0}");
        text.AppendLine($"Missing bytes: {stream.MissingByteCount:N0}");
        text.AppendLine();
        text.AppendLine("Text preview:");
        foreach (var value in preview)
        {
            // Unlike the hex dump's ASCII column, the text preview keeps line breaks and tabs.
            text.Append(value is >= 32 and <= 126 or 10 or 13 or 9 ? (char)value : '.');
        }

        if (data.Length > preview.Length)
        {
            text.AppendLine();
            text.Append($"... {data.Length - preview.Length:N0} bytes omitted");
        }

        text.AppendLine();
        text.AppendLine();
        text.AppendLine("Hex:");
        HexDump.Append(text, data.Span, omittedNote: "from the hex view");
        return text.ToString();
    }
}
