using System.Text;
using LunaPacketSniffer.Persistence;
using Xunit;

namespace LunaPacketSniffer.Protocols.Tests;

/// <summary>
/// Exercises the incremental HTTP/1.x framing inside <see cref="HttpHarWriter"/>: chunked bodies,
/// trailers, pipelined messages, and messages that arrive split across many reads.
/// </summary>
public sealed class HttpMessageBufferTests
{
    [Fact]
    public async Task ReassemblesChunkedResponseDeliveredInSeveralReads()
    {
        await using var harness = new WriterHarness();

        harness.Request("GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n");
        harness.Response("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello");
        Assert.Empty(harness.Transactions);

        harness.Response("\r\n6\r\n World\r\n");
        Assert.Empty(harness.Transactions);

        harness.Response("0\r\n\r\n");

        var transaction = Assert.Single(harness.Transactions);
        Assert.Equal("Hello World", Encoding.UTF8.GetString(transaction.ResponseBody.Data));
    }

    [Fact]
    public async Task ReadsChunkedResponseWithSizeExtensionAndTrailer()
    {
        await using var harness = new WriterHarness();

        harness.Request("GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n");
        harness.Response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "3;name=value\r\nabc\r\n0\r\nX-Checksum: 1234\r\n\r\n");

        var transaction = Assert.Single(harness.Transactions);
        Assert.Equal("abc", Encoding.UTF8.GetString(transaction.ResponseBody.Data));
    }

    [Fact]
    public async Task ReadsPipelinedTransactionsFromASingleRead()
    {
        await using var harness = new WriterHarness();

        harness.Request(
            "GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n" +
            "GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n");
        harness.Response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\none" +
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\ntwo");

        Assert.Equal(2, harness.Transactions.Count);
        Assert.Equal("http://example.test/first", harness.Transactions[0].Url);
        Assert.Equal("one", Encoding.UTF8.GetString(harness.Transactions[0].ResponseBody.Data));
        Assert.Equal("http://example.test/second", harness.Transactions[1].Url);
        Assert.Equal(404, harness.Transactions[1].Status);
        Assert.Equal("two", Encoding.UTF8.GetString(harness.Transactions[1].ResponseBody.Data));
    }

    [Fact]
    public async Task ReadsMessagesDeliveredOneByteAtATime()
    {
        await using var harness = new WriterHarness();

        foreach (var value in Encoding.ASCII.GetBytes("POST /api HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2\r\n\r\nhi"))
        {
            harness.Writer.ObserveDecrypted(WriterHarness.ConnectionKey, true, [value]);
        }

        foreach (var value in Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"))
        {
            harness.Writer.ObserveDecrypted(WriterHarness.ConnectionKey, false, [value]);
        }

        var transaction = Assert.Single(harness.Transactions);
        Assert.Equal("hi", Encoding.UTF8.GetString(transaction.RequestBody.Data));
        Assert.Equal("ok", Encoding.UTF8.GetString(transaction.ResponseBody.Data));
    }

    [Fact]
    public async Task ReadsBodyLargerThanTheInitialBufferCapacity()
    {
        await using var harness = new WriterHarness();
        var body = new string('a', 100_000);

        harness.Request("GET /big HTTP/1.1\r\nHost: example.test\r\n\r\n");
        harness.Response($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n");
        foreach (var piece in Enumerable.Range(0, 100).Select(index => body.Substring(index * 1_000, 1_000)))
        {
            harness.Response(piece);
        }

        var transaction = Assert.Single(harness.Transactions);
        Assert.Equal(body, Encoding.UTF8.GetString(transaction.ResponseBody.Data));
    }

    [Fact]
    public async Task TreatsNoContentResponseAsBodylessSoTheNextMessageIsStillRead()
    {
        await using var harness = new WriterHarness();

        harness.Request("GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n");
        harness.Response(
            "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n" +
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok");

        Assert.Equal(2, harness.Transactions.Count);
        Assert.Equal(204, harness.Transactions[0].Status);
        Assert.Empty(harness.Transactions[0].ResponseBody.Data);
        Assert.Equal("ok", Encoding.UTF8.GetString(harness.Transactions[1].ResponseBody.Data));
    }

    private sealed class WriterHarness : IAsyncDisposable
    {
        public const string ConnectionKey = "connection";

        private readonly string _directory;

        public WriterHarness()
        {
            _directory = Path.Combine(Path.GetTempPath(), "LunaPacketSniffer.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
            Writer = new HttpHarWriter(Path.Combine(_directory, "capture.http.har"));
            Writer.TransactionObserved += Transactions.Add;
        }

        public HttpHarWriter Writer { get; }

        public List<HttpTransaction> Transactions { get; } = [];

        public void Request(string text) =>
            Writer.ObserveDecrypted(ConnectionKey, true, Encoding.ASCII.GetBytes(text));

        public void Response(string text) =>
            Writer.ObserveDecrypted(ConnectionKey, false, Encoding.ASCII.GetBytes(text));

        public async ValueTask DisposeAsync()
        {
            await Writer.DisposeAsync();
            Directory.Delete(_directory, recursive: true);
        }
    }
}
