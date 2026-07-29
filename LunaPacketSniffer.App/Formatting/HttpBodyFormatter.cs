using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace LunaPacketSniffer.App.Formatting;

/// <summary>
/// Decodes and pretty-prints HTTP bodies for the detail pane.
/// </summary>
internal static class HttpBodyFormatter
{
    private static readonly JsonSerializerOptions IndentedJson = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static bool IsTextContent(string contentType) =>
        contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase);

    /// <summary>Decodes the body as UTF-8, indenting it when the content type declares JSON.</summary>
    public static string ToText(ReadOnlySpan<byte> data, string contentType)
    {
        var text = Encoding.UTF8.GetString(data);
        return contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ? IndentJson(text) : text;
    }

    public static string IndentJson(string text)
    {
        try
        {
            return JsonSerializer.Serialize(JsonDocument.Parse(text), IndentedJson);
        }
        catch (JsonException)
        {
            return text;
        }
    }

    /// <summary>
    /// Reverses the Content-Encoding of a body. Returns an empty array and sets
    /// <paramref name="error"/> when the encoding is unsupported or the data is corrupt.
    /// </summary>
    public static byte[] Decompress(byte[] data, string contentEncoding, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(contentEncoding) || string.Equals(contentEncoding, "identity", StringComparison.OrdinalIgnoreCase))
        {
            return data;
        }

        try
        {
            using var input = new MemoryStream(data, writable: false);
            using Stream decoder = contentEncoding.ToLowerInvariant() switch
            {
                "gzip" => new GZipStream(input, CompressionMode.Decompress),
                "deflate" => new DeflateStream(input, CompressionMode.Decompress),
                "br" => new BrotliStream(input, CompressionMode.Decompress),
                _ => throw new NotSupportedException($"Unsupported Content-Encoding: {contentEncoding}"),
            };
            using var output = new MemoryStream();
            decoder.CopyTo(output);
            return output.ToArray();
        }
        catch (Exception exception) when (exception is InvalidDataException or NotSupportedException)
        {
            error = $"Body decode failed: {exception.Message}";
            return [];
        }
    }

    /// <summary>Writes the "&lt;title&gt;: N bytes (content type)" line shared by every body view.</summary>
    public static void AppendHeading(StringBuilder detail, string title, long length, string contentType)
    {
        var suffix = string.IsNullOrWhiteSpace(contentType) ? string.Empty : $" ({contentType})";
        detail.AppendLine($"{title}: {length:N0} bytes{suffix}");
    }
}
