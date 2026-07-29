using System.Text.Json.Serialization;
using LunaPacketSniffer.Persistence.Http;

namespace LunaPacketSniffer.Persistence.Har;

// The HAR 1.2 document shape. Property names are serialized with a camelCase policy; the fields the
// spec requires but this tool does not measure are emitted as constants (-1 / empty).

internal sealed record HarDocument(HarLog Log);

internal sealed record HarLog(string Version, HarCreator Creator, List<HarEntry> Entries);

internal sealed record HarCreator(string Name, string Version);

internal sealed record HarEntry(
    [property: JsonIgnore] DateTimeOffset StartedAt,
    HarRequest Request,
    HarResponse Response,
    [property: JsonIgnore] DateTimeOffset CompletedAt)
{
    public DateTimeOffset StartedDateTime => StartedAt;
    public double Time => Math.Max(0, (CompletedAt - StartedAt).TotalMilliseconds);
    public object Cache { get; } = new();
    public HarTimings Timings { get; } = new(-1, -1, -1, -1, -1);
}

internal sealed record HarRequest(
    string Method,
    string Url,
    string HttpVersion,
    List<HttpHeader> Headers,
    int BodySize,
    HarPostData? PostData)
{
    public List<HarQueryString> QueryString { get; } = [];
    public int HeadersSize => -1;
}

internal sealed record HarResponse(
    int Status,
    string StatusText,
    string HttpVersion,
    List<HttpHeader> Headers,
    int BodySize,
    HarContent Content)
{
    [JsonPropertyName("redirectURL")]
    public string RedirectUrl => string.Empty;
    public int HeadersSize => -1;
}

internal sealed record HarQueryString(string Name, string Value);

internal sealed record HarPostData(string MimeType, string? Text, string? Encoding);

internal sealed record HarContent(int Size, string MimeType, string? Text, string? Encoding);

internal sealed record HarTimings(int Blocked, int Dns, int Connect, int Send, int Wait);

/// <summary>A body rendered into the HAR document itself, or <see langword="null"/> when it is binary.</summary>
internal sealed record HarText(string Text, string? Encoding);
