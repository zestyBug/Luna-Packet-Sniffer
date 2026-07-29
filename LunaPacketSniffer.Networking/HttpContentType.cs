namespace LunaPacketSniffer.Networking;

/// <summary>
/// Content-Type classification shared by the HAR writer and the UI detail pane, so both agree on
/// which bodies are shown as text and which are shown as hex.
/// </summary>
public static class HttpContentType
{
    public static bool IsText(string contentType) =>
        contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase);

    public static bool IsJson(string contentType) =>
        contentType.Contains("json", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the body is stored as received rather than decoded (no or identity encoding).</summary>
    public static bool IsIdentityEncoding(string contentEncoding) =>
        string.IsNullOrWhiteSpace(contentEncoding) ||
        string.Equals(contentEncoding, "identity", StringComparison.OrdinalIgnoreCase);
}
