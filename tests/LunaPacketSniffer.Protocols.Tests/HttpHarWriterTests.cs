using System.Text;
using LunaPacketSniffer.Persistence;
using Xunit;

namespace LunaPacketSniffer.Protocols.Tests;

public sealed class HttpHarWriterTests
{
    [Fact]
    public async Task StoresBinaryBodyOnlyInBodiesDirectory()
    {
        var directory = CreateDirectory();
        var path = Path.Combine(directory, "capture.http.har");
        try
        {
            await using var writer = new HttpHarWriter(path);
            writer.ObserveDecrypted("connection", true, "GET /video HTTP/1.1\r\nHost: example.test\r\n\r\n"u8);
            writer.ObserveDecrypted("connection", false, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: 4\r\n\r\n"u8);
            writer.ObserveDecrypted("connection", false, [1, 2, 3, 4]);
            await writer.DisposeAsync();

            var har = await File.ReadAllTextAsync(path);
            Assert.DoesNotContain("AQIDBA==", har);
            var body = Assert.Single(Directory.GetFiles(Path.Combine(directory, "bodies")));
            Assert.Equal([1, 2, 3, 4], await File.ReadAllBytesAsync(body));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ObserveDecryptedParsesMaskedWebSocketTextFrameAfterUpgrade()
    {
        var directory = CreateDirectory();
        var path = Path.Combine(directory, "capture.http.har");
        try
        {
            await using var writer = new HttpHarWriter(path);
            WebSocketMessage? message = null;
            writer.WebSocketMessageObserved += value => message = value;

            writer.ObserveDecrypted("connection", true, "GET /socket HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"u8);
            writer.ObserveDecrypted("connection", false, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"u8);
            writer.ObserveDecrypted("connection", true, [0x81, 0x82, 1, 2, 3, 4, (byte)('H' ^ 1), (byte)('i' ^ 2)]);

            Assert.NotNull(message);
            Assert.True(message.IsRequest);
            Assert.Equal("Text", message.Opcode);
            Assert.Equal("Hi", Encoding.UTF8.GetString(message.Data));
            Assert.NotNull(message.FilePath);
            Assert.True(File.Exists(Path.Combine(directory, message.FilePath)));
            await writer.DisposeAsync();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ObserveDecryptedPairsFragmentedRequestAndResponseBodies()
    {
        var directory = CreateDirectory();
        var path = Path.Combine(directory, "capture.http.har");
        try
        {
            await using var writer = new HttpHarWriter(path);
            HttpTransaction? transaction = null;
            writer.TransactionObserved += value => transaction = value;

            writer.ObserveDecrypted("connection", true, Encoding.ASCII.GetBytes("POST /api HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: 8\r\n\r\n{\"id"));
            writer.ObserveDecrypted("connection", true, Encoding.ASCII.GetBytes("\":1}"));
            writer.ObserveDecrypted("connection", false, Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}"));

            Assert.NotNull(transaction);
            Assert.Equal("POST", transaction.Method);
            Assert.Equal("http://example.test/api", transaction.Url);
            Assert.Equal("{\"id\":1}", Encoding.UTF8.GetString(transaction.RequestBody.Data));
            Assert.Equal("{\"ok\":true}", Encoding.UTF8.GetString(transaction.ResponseBody.Data));
            Assert.NotNull(transaction.RequestBody.FilePath);
            Assert.NotNull(transaction.ResponseBody.FilePath);
            Assert.True(File.Exists(Path.Combine(directory, transaction.RequestBody.FilePath)));
            Assert.True(File.Exists(Path.Combine(directory, transaction.ResponseBody.FilePath)));
            await writer.DisposeAsync();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string CreateDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "LunaPacketSniffer.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
