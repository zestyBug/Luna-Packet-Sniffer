using System.Text;
using LunaPacketSniffer.App.Formatting;
using LunaPacketSniffer.Persistence;

namespace LunaPacketSniffer.App.ViewModels;

/// <summary>
/// A row in the HTTP(S) grid. <paramref name="DetailLoader"/> is set for rows restored from a saved
/// capture, where the bodies are read from disk only when the row is selected.
/// </summary>
public sealed record HttpSessionListItem(
    string Timestamp,
    string Method,
    string Status,
    string Url,
    string Duration,
    string Detail,
    Func<string>? DetailLoader = null)
{
    public string GetDetail() => DetailLoader?.Invoke() ?? Detail;

    public static HttpSessionListItem Create(HttpTransaction transaction)
    {
        var detail = new StringBuilder();
        detail.AppendLine($"Started: {transaction.StartedAt:O}");
        detail.AppendLine($"Completed: {transaction.CompletedAt:O}");
        detail.AppendLine($"Request: {transaction.Method} {transaction.Url} {transaction.HttpVersion}");
        detail.AppendLine($"Response: {transaction.Status} {transaction.StatusText}");
        detail.AppendLine();
        detail.AppendLine("Request headers:");
        detail.AppendLine(transaction.RequestHeaders);
        detail.AppendLine();
        detail.AppendLine("Response headers:");
        detail.AppendLine(transaction.ResponseHeaders);
        AppendBody(detail, "Request body", transaction.RequestBody);
        AppendBody(detail, "Response body", transaction.ResponseBody);
        return new HttpSessionListItem(
            transaction.StartedAt.LocalDateTime.ToString("HH:mm:ss.fff"),
            transaction.Method,
            $"{transaction.Status} {transaction.StatusText}",
            transaction.Url,
            FormatDuration(transaction.StartedAt, transaction.CompletedAt),
            detail.ToString());
    }

    public static string FormatDuration(DateTimeOffset startedAt, DateTimeOffset completedAt) =>
        $"{Math.Max(0, (completedAt - startedAt).TotalMilliseconds):F0} ms";

    private static void AppendBody(StringBuilder detail, string title, HttpBody body)
    {
        detail.AppendLine();
        HttpBodyFormatter.AppendHeading(detail, title, body.Data.Length, body.ContentType);
        if (body.FilePath is not null)
        {
            detail.AppendLine($"Saved: {body.FilePath}");
        }
        if (body.Data.Length == 0)
        {
            return;
        }

        var data = HttpBodyFormatter.Decompress(body.Data, body.ContentEncoding, out var decodingError);
        if (decodingError is not null)
        {
            detail.AppendLine(decodingError);
            return;
        }

        if (HttpBodyFormatter.IsTextContent(body.ContentType))
        {
            detail.AppendLine(HttpBodyFormatter.ToText(data, body.ContentType));
            return;
        }

        HexDump.Append(detail, data, includeText: false);
    }
}
