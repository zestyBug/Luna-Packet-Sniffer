using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Networking;
using LunaPacketSniffer.Persistence.Har;
using LunaPacketSniffer.Persistence.Http;

namespace LunaPacketSniffer.Persistence;

/// <summary>
/// Reassembles HTTP traffic — cleartext port 80 packets and decrypted HTTPS from the MITM proxy —
/// into transactions, writes the bodies to <c>bodies\</c>, and emits a HAR document on disposal.
/// </summary>
public sealed class HttpHarWriter : IAsyncDisposable
{
    private const int HttpPort = 80;

    private static readonly JsonSerializerOptions HarJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };

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

    public void Observe(CapturedPacket packet) =>
        Observe(packet, PacketDecoder.TryDecode(packet.Data, out var decoded) ? decoded : null);

    /// <summary>Observes a packet the caller has already decoded, avoiding a second decode.</summary>
    public void Observe(CapturedPacket packet, DecodedPacket? decoded)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (decoded is null || decoded.Protocol != IpProtocol.Tcp || decoded.Payload.IsEmpty ||
            (decoded.Source.Port != HttpPort && decoded.Destination.Port != HttpPort))
        {
            return;
        }

        Observe(
            GetConnectionKey(decoded.Source.ToString(), decoded.Destination.ToString()),
            packet.Direction == PacketDirection.Outbound,
            decoded.Payload.Span,
            packet.Timestamp);
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
        await JsonSerializer.SerializeAsync(stream, document, HarJson);
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
                    connection.Requests.Enqueue(new PendingRequest(timestamp, message));
                }
                else if (!isRequest && !message.IsRequest && connection.Requests.TryDequeue(out var request))
                {
                    AddTransaction(request, message, timestamp);
                    if (IsWebSocketUpgrade(request.Message, message))
                    {
                        StartWebSocket(connection, buffer, timestamp);
                        return;
                    }
                }
            }
        }
    }

    /// <summary>After a 101 the connection stops being HTTP, so remaining bytes go to the frame reader.</summary>
    private void StartWebSocket(HttpConnection connection, HttpMessageBuffer buffer, DateTimeOffset timestamp)
    {
        connection.WebSocketReader = new WebSocketMessageReader();
        var remaining = buffer.Drain();
        if (remaining.Length > 0)
        {
            connection.WebSocketReader.Append(remaining, false, timestamp, ObserveWebSocketMessage);
        }
    }

    private void AddTransaction(PendingRequest request, HttpMessage response, DateTimeOffset completedAt)
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
            HttpHeader.Format(request.Message.Headers),
            HttpHeader.Format(response.Headers),
            requestBody,
            responseBody));
    }

    private static HarRequest CreateHarRequest(PendingRequest request)
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
        var text = ToHarText(response.Body, response.ContentType, response.ContentEncoding);
        return new HarResponse(
            response.Status,
            response.StatusText,
            response.Version,
            response.Headers,
            response.Body.Length,
            new HarContent(response.Body.Length, response.ContentType, text?.Text, text?.Encoding));
    }

    /// <summary>Binary and still-encoded bodies stay out of the HAR document and live only as files.</summary>
    private static HarText? ToHarText(byte[] body, string contentType, string contentEncoding) =>
        HttpContentType.IsText(contentType) && HttpContentType.IsIdentityEncoding(contentEncoding)
            ? new HarText(Encoding.UTF8.GetString(body), null)
            : null;

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
        if (!HttpContentType.IsIdentityEncoding(contentEncoding))
        {
            return ".bin";
        }

        return contentType.Split(';', 2)[0].Trim().ToLowerInvariant() switch
        {
            "application/json" or "text/json" => ".json",
            "text/html" => ".html",
            "application/xml" or "text/xml" => ".xml",
            "application/javascript" or "text/javascript" => ".js",
            "text/plain" => ".txt",
            _ => ".bin",
        };
    }

    /// <summary>An endpoint-order-independent key, so both directions of a connection share one entry.</summary>
    private static string GetConnectionKey(string firstEndpoint, string secondEndpoint) =>
        string.CompareOrdinal(firstEndpoint, secondEndpoint) < 0
            ? $"{firstEndpoint}|{secondEndpoint}"
            : $"{secondEndpoint}|{firstEndpoint}";

    private static bool IsWebSocketUpgrade(HttpMessage request, HttpMessage response) =>
        response.Status == 101 &&
        string.Equals(HttpHeader.GetValue(request.Headers, "Upgrade"), "websocket", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(HttpHeader.GetValue(response.Headers, "Upgrade"), "websocket", StringComparison.OrdinalIgnoreCase);

    private sealed record PendingRequest(DateTimeOffset StartedAt, HttpMessage Message);

    private sealed class HttpConnection
    {
        public HttpMessageBuffer RequestBuffer { get; } = new();
        public HttpMessageBuffer ResponseBuffer { get; } = new();
        public Queue<PendingRequest> Requests { get; } = [];
        public WebSocketMessageReader? WebSocketReader { get; set; }
    }
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
