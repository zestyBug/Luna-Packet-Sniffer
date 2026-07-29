using System.IO;
using System.Text;
using LunaPacketSniffer.App.Formatting;
using LunaPacketSniffer.App.Recording;
using LunaPacketSniffer.App.ViewModels;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Networking;
using LunaPacketSniffer.Protocols;

namespace LunaPacketSniffer.App.Loading;

/// <summary>
/// Builds the detail-pane text for rows restored from a saved capture. Everything here reads from
/// disk, so it runs lazily when a row is selected rather than while the capture is being loaded.
/// </summary>
internal static class LoadedCaptureDetails
{
    public static string CreatePacketDetail(string detail, string pcapPath, long pcapOffset, int capturedLength)
    {
        var newLine = Environment.NewLine;
        try
        {
            var data = PcapPacketReader.ReadPacket(pcapPath, pcapOffset, capturedLength);
            return $"{detail}{newLine}{newLine}Raw bytes:{newLine}{HexDump.Format(data)}";
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or OverflowException)
        {
            return $"{detail}{newLine}{newLine}Raw bytes could not be read: {exception.Message}";
        }
    }

    public static string CreateHttpDetail(
        string detail,
        long requestBodyLength,
        string requestContentType,
        string? requestBodyPath,
        long responseBodyLength,
        string responseContentType,
        string? responseBodyPath)
    {
        var text = new StringBuilder(detail);
        AppendBody(text, "Request body", requestBodyLength, requestContentType, requestBodyPath);
        AppendBody(text, "Response body", responseBodyLength, responseContentType, responseBodyPath);
        return text.ToString();
    }

    /// <summary>Reassembles both directions of a stored TCP flow by re-reading its packets from the PCAPNG.</summary>
    public static string CreateTcpFlowDetail(string captureDirectory, long flowId)
    {
        var pcapPath = Path.Combine(captureDirectory, CaptureOutput.PcapFileName);
        var outbound = new TcpStreamAssembler();
        var inbound = new TcpStreamAssembler();
        using var connection = CaptureLoader.OpenReadOnly(Path.Combine(captureDirectory, CaptureOutput.IndexFileName));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT direction, captured_length, pcap_offset FROM packets WHERE flow_id = $flowId ORDER BY timestamp_unix_microseconds;";
        command.Parameters.AddWithValue("$flowId", flowId);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var packet = PcapPacketReader.ReadPacket(pcapPath, reader.GetInt64(2), checked((int)reader.GetInt64(1)));
            if (!PacketDecoder.TryDecode(packet, out var decoded) || decoded?.TcpSequenceNumber is not { } sequence || decoded.Payload.IsEmpty)
            {
                continue;
            }

            var stream = reader.GetInt64(0) == (long)PacketDirection.Outbound ? outbound : inbound;
            stream.Append(sequence, decoded.Payload.Span);
        }

        return FlowSessionListItem.FormatStreamPair(outbound, inbound);
    }

    private static void AppendBody(StringBuilder detail, string title, long length, string contentType, string? bodyPath)
    {
        detail.AppendLine();
        detail.AppendLine();
        HttpBodyFormatter.AppendHeading(detail, title, length, contentType);
        if (length == 0)
        {
            return;
        }

        if (bodyPath is null || !File.Exists(bodyPath))
        {
            detail.AppendLine("Body file was not found.");
            return;
        }

        detail.AppendLine($"Saved: {bodyPath}");
        var data = File.ReadAllBytes(bodyPath);

        // Bodies saved as .bin are binary or still compressed, so they are only shown as hex.
        if (Path.GetExtension(bodyPath).Equals(".bin", StringComparison.OrdinalIgnoreCase))
        {
            detail.AppendLine(HexDump.Format(data));
            return;
        }

        detail.AppendLine(HttpBodyFormatter.ToText(data, contentType));
    }
}
