using System.Text;
using LunaPacketSniffer.App.Formatting;
using LunaPacketSniffer.Persistence;

namespace LunaPacketSniffer.App.ViewModels;

public sealed record WebSocketListItem(
    string Timestamp,
    string Direction,
    string Type,
    int Length,
    string Summary,
    string Detail)
{
    private const int MaxSummaryLength = 1_024;

    public static string FormatDirection(bool isRequest) => isRequest ? "Client → Server" : "Server → Client";

    public static WebSocketListItem Create(WebSocketMessage message)
    {
        var isText = message.Opcode == "Text";
        var summary = isText ? Encoding.UTF8.GetString(message.Data) : message.Opcode;
        if (summary.Length > MaxSummaryLength)
        {
            summary = summary[..MaxSummaryLength] + "...";
        }

        var detail = new StringBuilder();
        detail.AppendLine($"Timestamp: {message.Timestamp:O}");
        detail.AppendLine($"Direction: {FormatDirection(message.IsRequest)}");
        detail.AppendLine($"Type: {message.Opcode}");
        detail.AppendLine($"Length: {message.Data.Length:N0} bytes");
        if (message.FilePath is not null)
        {
            detail.AppendLine($"Saved: {message.FilePath}");
        }
        detail.AppendLine();
        if (isText)
        {
            detail.AppendLine(Encoding.UTF8.GetString(message.Data));
        }
        else
        {
            HexDump.Append(detail, message.Data, includeText: false);
        }

        return new WebSocketListItem(
            message.Timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
            FormatDirection(message.IsRequest),
            message.Opcode,
            message.Data.Length,
            summary,
            detail.ToString());
    }
}
