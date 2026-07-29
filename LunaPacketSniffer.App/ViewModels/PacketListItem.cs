using System.Text;
using LunaPacketSniffer.App.Formatting;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Protocols;

namespace LunaPacketSniffer.App.ViewModels;

/// <summary>
/// A row in the Packets grid. <paramref name="DetailLoader"/> is set for rows restored from a saved
/// capture, where the raw bytes are read from disk only when the row is selected.
/// </summary>
public sealed record PacketListItem(
    string Timestamp,
    string Direction,
    string ProcessId,
    string ProcessName,
    string Protocol,
    string Source,
    string Destination,
    int Length,
    string Summary,
    string Detail,
    Func<string>? DetailLoader = null)
{
    public string GetDetail() => DetailLoader?.Invoke() ?? Detail;

    public static PacketListItem Create(CapturedPacket packet, PacketAnalysis analysis)
    {
        var flow = packet.Flow;
        return new PacketListItem(
            packet.Timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
            packet.Direction == PacketDirection.Outbound ? "→" : "←",
            flow?.Process.ProcessId.ToString() ?? "Unknown",
            flow?.Process.ProcessName ?? "Unknown",
            analysis.Protocol,
            analysis.Source,
            analysis.Destination,
            packet.Data.Length,
            analysis.Summary,
            CreateDetail(packet, analysis));
    }

    private static string CreateDetail(CapturedPacket packet, PacketAnalysis analysis)
    {
        var detail = new StringBuilder();
        detail.AppendLine($"Timestamp: {packet.Timestamp:O}");
        detail.AppendLine($"Direction: {packet.Direction}");
        detail.AppendLine($"Interface: {packet.InterfaceIndex}");
        detail.AppendLine($"Process: {packet.Flow?.Process.ProcessName ?? "Unknown"} ({packet.Flow?.Process.ProcessId.ToString() ?? "Unknown"})");
        if (!string.IsNullOrEmpty(packet.Flow?.Process.ImagePath))
        {
            detail.AppendLine($"Image: {packet.Flow.Process.ImagePath}");
        }
        detail.AppendLine($"Protocol: {analysis.Protocol}");
        detail.AppendLine($"Source: {analysis.Source}");
        detail.AppendLine($"Destination: {analysis.Destination}");
        detail.AppendLine($"Length: {packet.Data.Length} bytes");
        if (!string.IsNullOrEmpty(analysis.Summary))
        {
            detail.AppendLine($"Summary: {analysis.Summary}");
        }

        detail.AppendLine();
        detail.AppendLine("Raw bytes:");
        HexDump.Append(detail, packet.Data);
        return detail.ToString();
    }
}
