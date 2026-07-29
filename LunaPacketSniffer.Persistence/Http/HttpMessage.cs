namespace LunaPacketSniffer.Persistence.Http;

/// <summary>A parsed HTTP/1.x request or response, headers and body together.</summary>
internal sealed record HttpMessage(
    bool IsRequest,
    string Method,
    string Url,
    int Status,
    string StatusText,
    string Version,
    List<HttpHeader> Headers,
    byte[] Body)
{
    private static readonly string[] Methods =
        ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

    public string ContentType => HttpHeader.GetValue(Headers, "Content-Type") ?? string.Empty;
    public string ContentEncoding => HttpHeader.GetValue(Headers, "Content-Encoding") ?? string.Empty;

    public static HttpMessage Parse(string headerText, List<HttpHeader> headers, byte[] body)
    {
        var firstLine = headerText.Split("\r\n", 2, StringSplitOptions.None)[0];
        var parts = firstLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 3 && parts[2].StartsWith("HTTP/", StringComparison.Ordinal) && IsMethod(parts[0]))
        {
            return new HttpMessage(true, parts[0], ResolveUrl(parts[1], headers), 0, string.Empty, parts[2], headers, body);
        }

        var status = parts.Length >= 2 && parts[0].StartsWith("HTTP/", StringComparison.Ordinal) && int.TryParse(parts[1], out var value) ? value : 0;
        return new HttpMessage(
            false,
            string.Empty,
            string.Empty,
            status,
            parts.Length == 3 ? parts[2] : string.Empty,
            parts.Length > 0 ? parts[0] : string.Empty,
            headers,
            body);
    }

    /// <summary>An origin-form target only becomes an absolute URL once the Host header is known.</summary>
    private static string ResolveUrl(string target, List<HttpHeader> headers)
    {
        if (Uri.TryCreate(target, UriKind.Absolute, out var absoluteUri))
        {
            return absoluteUri.ToString();
        }

        return HttpHeader.GetValue(headers, "Host") is { Length: > 0 } host ? $"http://{host}{target}" : target;
    }

    private static bool IsMethod(string method) => Array.IndexOf(Methods, method) >= 0;
}
