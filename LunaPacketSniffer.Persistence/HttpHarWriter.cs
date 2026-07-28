using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Networking;

namespace LunaPacketSniffer.Persistence;

public sealed class HttpHarWriter : IAsyncDisposable
{
    private readonly string _path;
    private readonly string _bodyDirectory;
    private readonly Lock _syncRoot = new();
    private readonly Dictionary<string, HttpConnection> _connections = [];
    private readonly List<HarEntry> _entries = [];
    private long _nextBodyId;
    private bool _disposed;

    public event Action<HttpTransaction>? TransactionObserved;
    public event Action<WebSocketMessage>? WebSocketMessageObserved;

    public HttpHarWriter(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        _bodyDirectory = Path.Combine(Path.GetDirectoryName(path)!, "bodies");
        Directory.CreateDirectory(_bodyDirectory);
    }

    public void Observe(CapturedPacket packet)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!PacketDecoder.TryDecode(packet.Data, out var decoded) || decoded is null || decoded.Protocol != 6 || decoded.Payload.IsEmpty || (decoded.Source.Port != 80 && decoded.Destination.Port != 80))
        {
            return;
        }

        Observe(GetConnectionKey(decoded.Source.ToString(), decoded.Destination.ToString()), packet.Direction == PacketDirection.Outbound, decoded.Payload.Span, packet.Timestamp);
    }

    public void ObserveDecrypted(string connectionKey, bool isRequest, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Observe(connectionKey, isRequest, data, DateTimeOffset.UtcNow);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        var document = new HarDocument(new HarLog("1.2", new HarCreator("LunaPacketSniffer", "1.0"), _entries));
        await using var stream = new FileStream(_path, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
        await JsonSerializer.SerializeAsync(stream, document, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = true,
        });
        _disposed = true;
    }

    private void Observe(string connectionKey, bool isRequest, ReadOnlySpan<byte> data, DateTimeOffset timestamp)
    {
        lock (_syncRoot)
        {
            if (!_connections.TryGetValue(connectionKey, out var connection))
            {
                connection = new HttpConnection();
                _connections.Add(connectionKey, connection);
            }

            if (connection.WebSocketReader is { } webSocketReader)
            {
                webSocketReader.Append(data, isRequest, timestamp, ObserveWebSocketMessage);
                return;
            }

            var buffer = isRequest ? connection.RequestBuffer : connection.ResponseBuffer;
            buffer.Append(data);
            while (buffer.TryRead(out var message))
            {
                if (isRequest && message.IsRequest)
                {
                    connection.Requests.Enqueue(new HttpRequest(timestamp, message));
                }
                else if (!isRequest && !message.IsRequest && connection.Requests.TryDequeue(out var request))
                {
                    AddTransaction(request, message, timestamp);
                    if (IsWebSocketUpgrade(request.Message, message))
                    {
                        connection.WebSocketReader = new WebSocketMessageReader();
                        var remaining = buffer.Drain();
                        if (remaining.Length > 0)
                        {
                            connection.WebSocketReader.Append(remaining, false, timestamp, ObserveWebSocketMessage);
                        }

                        return;
                    }
                }
            }
        }
    }

    private void AddTransaction(HttpRequest request, HttpMessage response, DateTimeOffset completedAt)
    {
        var requestBody = CreateBody(request.Message, "request");
        var responseBody = CreateBody(response, "response");
        _entries.Add(new HarEntry(request.StartedAt, CreateHarRequest(request), CreateHarResponse(response), completedAt));
        TransactionObserved?.Invoke(new HttpTransaction(
            request.StartedAt,
            completedAt,
            request.Message.Method,
            request.Message.Url,
            response.Status,
            response.StatusText,
            request.Message.Version,
            FormatHeaders(request.Message.Headers),
            FormatHeaders(response.Headers),
            requestBody,
            responseBody));
    }

    private static HarRequest CreateHarRequest(HttpRequest request)
    {
        var message = request.Message;
        var text = ToHarText(message.Body, message.ContentType, message.ContentEncoding);
        return new HarRequest(
            message.Method,
            message.Url,
            message.Version,
            message.Headers,
            message.Body.Length,
            message.Body.Length == 0 ? null : new HarPostData(message.ContentType, text?.Text, text?.Encoding));
    }

    private static HarResponse CreateHarResponse(HttpMessage response)
    {
        var contentType = response.ContentType;
        var text = ToHarText(response.Body, contentType, response.ContentEncoding);
        return new HarResponse(
            response.Status,
            response.StatusText,
            response.Version,
            response.Headers,
            response.Body.Length,
            new HarContent(response.Body.Length, contentType, text?.Text, text?.Encoding));
    }

    private HttpBody CreateBody(HttpMessage message, string direction)
    {
        if (message.Body.Length == 0)
        {
            return new HttpBody(message.ContentType, message.ContentEncoding, message.Body);
        }

        var name = $"{Interlocked.Increment(ref _nextBodyId):D8}-{direction}{GetBodyExtension(message.ContentType, message.ContentEncoding)}";
        File.WriteAllBytes(Path.Combine(_bodyDirectory, name), message.Body);
        return new HttpBody(message.ContentType, message.ContentEncoding, message.Body, Path.Combine("bodies", name));
    }

    private void ObserveWebSocketMessage(WebSocketMessage message)
    {
        var extension = message.Opcode == "Text" ? ".txt" : ".bin";
        var direction = message.IsRequest ? "request" : "response";
        var name = $"{Interlocked.Increment(ref _nextBodyId):D8}-websocket-{direction}{extension}";
        File.WriteAllBytes(Path.Combine(_bodyDirectory, name), message.Data);
        WebSocketMessageObserved?.Invoke(message with { FilePath = Path.Combine("bodies", name) });
    }

    private static string GetBodyExtension(string contentType, string contentEncoding)
    {
        if (!string.IsNullOrWhiteSpace(contentEncoding) && !string.Equals(contentEncoding, "identity", StringComparison.OrdinalIgnoreCase))
        {
            return ".bin";
        }

        var mediaType = contentType.Split(';', 2)[0].Trim().ToLowerInvariant();
        return mediaType switch
        {
            "application/json" or "text/json" => ".json",
            "text/html" => ".html",
            "application/xml" or "text/xml" => ".xml",
            "application/javascript" or "text/javascript" => ".js",
            "text/plain" => ".txt",
            _ => ".bin",
        };
    }

    private static string GetConnectionKey(string firstEndpoint, string secondEndpoint) =>
        string.CompareOrdinal(firstEndpoint, secondEndpoint) < 0
            ? $"{firstEndpoint}|{secondEndpoint}"
            : $"{secondEndpoint}|{firstEndpoint}";

    private static HttpMessage ParseMessage(string headerText, byte[] body)
    {
        var lines = headerText.Split("\r\n", StringSplitOptions.None);
        var headers = ParseHeaders(lines);
        var firstLine = lines[0];
        var parts = firstLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        var isRequest = parts.Length == 3 && parts[2].StartsWith("HTTP/", StringComparison.Ordinal) && IsMethod(parts[0]);
        if (isRequest)
        {
            var target = parts[1];
            var url = Uri.TryCreate(target, UriKind.Absolute, out var absoluteUri)
                ? absoluteUri.ToString()
                : GetHeaderValue(headers, "Host") is { Length: > 0 } host ? $"http://{host}{target}" : target;
            return new HttpMessage(true, parts[0], url, 0, string.Empty, parts[2], headers, body);
        }

        var status = parts.Length >= 2 && parts[0].StartsWith("HTTP/", StringComparison.Ordinal) && int.TryParse(parts[1], out var value) ? value : 0;
        return new HttpMessage(false, string.Empty, string.Empty, status, parts.Length == 3 ? parts[2] : string.Empty, parts.Length > 0 ? parts[0] : string.Empty, headers, body);
    }

    private static List<HarHeader> ParseHeaders(string[] lines)
    {
        var headers = new List<HarHeader>();
        foreach (var line in lines.Skip(1))
        {
            var separator = line.IndexOf(':');
            if (separator > 0)
            {
                headers.Add(new HarHeader(line[..separator], line[(separator + 1)..].Trim()));
            }
        }

        return headers;
    }

    private static string? GetHeaderValue(IEnumerable<HarHeader> headers, string name) =>
        headers.FirstOrDefault(header => string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;

    private static string FormatHeaders(IEnumerable<HarHeader> headers) =>
        string.Join(Environment.NewLine, headers.Select(header => $"{header.Name}: {header.Value}"));

    private static bool IsMethod(string method) => method is "GET" or "POST" or "PUT" or "DELETE" or "HEAD" or "OPTIONS" or "PATCH" or "CONNECT" or "TRACE";

    private static bool IsWebSocketUpgrade(HttpMessage request, HttpMessage response) =>
        response.Status == 101 &&
        string.Equals(GetHeaderValue(request.Headers, "Upgrade"), "websocket", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(GetHeaderValue(response.Headers, "Upgrade"), "websocket", StringComparison.OrdinalIgnoreCase);

    private sealed class HttpConnection
    {
        public HttpMessageBuffer RequestBuffer { get; } = new();
        public HttpMessageBuffer ResponseBuffer { get; } = new();
        public Queue<HttpRequest> Requests { get; } = [];
        public WebSocketMessageReader? WebSocketReader { get; set; }
    }

    private sealed class HttpMessageBuffer
    {
        private readonly List<byte> _data = [];

        public void Append(ReadOnlySpan<byte> data)
        {
            foreach (var value in data)
            {
                _data.Add(value);
            }
        }

        public bool TryRead(out HttpMessage message)
        {
            message = default!;
            var headerEnd = Find(_data, "\r\n\r\n"u8);
            if (headerEnd < 0)
            {
                return false;
            }

            var headerLength = headerEnd + 4;
            var headerText = Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(_data)[..headerEnd]);
            var headers = ParseHeaders(headerText.Split("\r\n", StringSplitOptions.None));
            var firstLine = headerText.Split("\r\n", 2, StringSplitOptions.None)[0];
            var responseStatus = TryGetResponseStatus(firstLine);
            var bodyLength = GetBodyLength(headers, responseStatus);
            byte[] body;
            int consumed;
            if (IsChunked(headers))
            {
                if (!TryReadChunkedBody(_data, headerLength, out body, out consumed))
                {
                    return false;
                }
            }
            else
            {
                if (_data.Count < headerLength + bodyLength)
                {
                    return false;
                }

                body = _data.GetRange(headerLength, bodyLength).ToArray();
                consumed = headerLength + bodyLength;
            }

            _data.RemoveRange(0, consumed);
            message = ParseMessage(headerText, body);
            return message.IsRequest || message.Status > 0;
        }

        public byte[] Drain()
        {
            var data = _data.ToArray();
            _data.Clear();
            return data;
        }

        private static int GetBodyLength(IEnumerable<HarHeader> headers, int? responseStatus)
        {
            if (responseStatus is 100 or 101 or 102 or 103 or 204 or 304)
            {
                return 0;
            }

            return int.TryParse(GetHeaderValue(headers, "Content-Length"), out var length) && length >= 0 ? length : 0;
        }

        private static bool IsChunked(IEnumerable<HarHeader> headers) =>
            GetHeaderValue(headers, "Transfer-Encoding")?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true;

        private static int? TryGetResponseStatus(string firstLine)
        {
            var parts = firstLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length >= 2 && parts[0].StartsWith("HTTP/", StringComparison.Ordinal) && int.TryParse(parts[1], out var status) ? status : null;
        }

        private static bool TryReadChunkedBody(List<byte> data, int offset, out byte[] body, out int consumed)
        {
            body = [];
            consumed = 0;
            var chunks = new List<byte>();
            var position = offset;
            while (true)
            {
                var lineEnd = Find(data, "\r\n"u8, position);
                if (lineEnd < 0 || !int.TryParse(Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(data)[position..lineEnd]).Split(';')[0], System.Globalization.NumberStyles.HexNumber, null, out var length))
                {
                    return false;
                }

                position = lineEnd + 2;
                if (length == 0)
                {
                    if (data.Count < position + 2)
                    {
                        return false;
                    }

                    if (data[position] == '\r' && data[position + 1] == '\n')
                    {
                        body = chunks.ToArray();
                        consumed = position + 2;
                        return true;
                    }

                    var trailerEnd = Find(data, "\r\n\r\n"u8, position);
                    if (trailerEnd < 0)
                    {
                        return false;
                    }

                    body = chunks.ToArray();
                    consumed = trailerEnd + 4;
                    return true;
                }

                if (data.Count < position + length + 2 || data[position + length] != '\r' || data[position + length + 1] != '\n')
                {
                    return false;
                }

                chunks.AddRange(data.GetRange(position, length));
                position += length + 2;
            }
        }

        private static int Find(List<byte> data, ReadOnlySpan<byte> value, int start = 0)
        {
            for (var index = start; index <= data.Count - value.Length; index++)
            {
                if (CollectionsMarshal.AsSpan(data).Slice(index, value.Length).SequenceEqual(value))
                {
                    return index;
                }
            }

            return -1;
        }
    }

    private sealed record HttpRequest(DateTimeOffset StartedAt, HttpMessage Message);

    private sealed record HarRequest(
        string Method,
        string Url,
        string HttpVersion,
        List<HarHeader> Headers,
        int BodySize,
        HarPostData? PostData)
    {
        public List<HarQueryString> QueryString { get; } = [];
        public int HeadersSize => -1;
    }

    private sealed record HttpMessage(bool IsRequest, string Method, string Url, int Status, string StatusText, string Version, List<HarHeader> Headers, byte[] Body)
    {
        public string ContentType => GetHeaderValue(Headers, "Content-Type") ?? string.Empty;
        public string ContentEncoding => GetHeaderValue(Headers, "Content-Encoding") ?? string.Empty;
    }

    private sealed record HarEntry(
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

    private sealed record HarResponse(int Status, string StatusText, string HttpVersion, List<HarHeader> Headers, int BodySize, HarContent Content)
    {
        [JsonPropertyName("redirectURL")]
        public string RedirectUrl => string.Empty;
        public int HeadersSize => -1;
    }

    private static HarText? ToHarText(byte[] body, string contentType, string contentEncoding) =>
        IsTextContent(contentType) && (string.IsNullOrWhiteSpace(contentEncoding) || string.Equals(contentEncoding, "identity", StringComparison.OrdinalIgnoreCase))
            ? new(Encoding.UTF8.GetString(body), null)
            : null;
    private static bool IsTextContent(string contentType) => contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) || contentType.Contains("json", StringComparison.OrdinalIgnoreCase) || contentType.Contains("xml", StringComparison.OrdinalIgnoreCase) || contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase);

    private sealed record HarDocument(HarLog Log);
    private sealed record HarLog(string Version, HarCreator Creator, List<HarEntry> Entries);
    private sealed record HarCreator(string Name, string Version);
    private sealed record HarHeader(string Name, string Value);
    private sealed record HarQueryString(string Name, string Value);
    private sealed record HarPostData(string MimeType, string? Text, string? Encoding);
    private sealed record HarContent(int Size, string MimeType, string? Text, string? Encoding);
    private sealed record HarText(string Text, string? Encoding);
    private sealed record HarTimings(int Blocked, int Dns, int Connect, int Send, int Wait);
}

public sealed record HttpBody(string ContentType, string ContentEncoding, byte[] Data, string? FilePath = null);

public sealed record HttpTransaction(
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    string Method,
    string Url,
    int Status,
    string StatusText,
    string HttpVersion,
    string RequestHeaders,
    string ResponseHeaders,
    HttpBody RequestBody,
    HttpBody ResponseBody);
