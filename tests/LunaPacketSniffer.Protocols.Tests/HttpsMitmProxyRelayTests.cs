using System.Diagnostics;
using System.Text;
using LunaPacketSniffer.Proxy;
using Xunit;

namespace LunaPacketSniffer.Protocols.Tests;

/// <summary>
/// Covers the tunnel relay: a direction that reaches EOF first must not tear down the direction that
/// is still delivering, and a peer that never closes must not hold the connection open forever.
/// </summary>
public sealed class HttpsMitmProxyRelayTests
{
    [Fact]
    public async Task DeliversTheResponseAfterTheClientStopsSending()
    {
        // The client half-closes immediately; the server keeps sending. Returning as soon as the
        // first direction finished used to truncate this response.
        var client = new ScriptedStream([], TimeSpan.Zero);
        var server = new ScriptedStream(
            [Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n"), Encoding.ASCII.GetBytes("body")],
            TimeSpan.FromMilliseconds(50));

        var proxy = new HttpsMitmProxy(new RootCertificateAuthority());
        var decrypted = new List<string>();
        proxy.DecryptedData += data => decrypted.Add(Encoding.ASCII.GetString(data.Data));

        await proxy.RelayUntilClosedAsync(client, server, "key", 1234, CancellationToken.None);

        Assert.Equal("HTTP/1.1 200 OK\r\n\r\nbody", Encoding.ASCII.GetString(client.Written.ToArray()));
        Assert.Equal(["HTTP/1.1 200 OK\r\n\r\n", "body"], decrypted);
    }

    [Fact]
    public async Task RelaysBothDirectionsBeforeReturning()
    {
        var client = new ScriptedStream([Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n")], TimeSpan.Zero);
        var server = new ScriptedStream([Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\n\r\n")], TimeSpan.FromMilliseconds(30));

        var proxy = new HttpsMitmProxy(new RootCertificateAuthority());

        await proxy.RelayUntilClosedAsync(client, server, "key", 1234, CancellationToken.None);

        Assert.Equal("GET / HTTP/1.1\r\n\r\n", Encoding.ASCII.GetString(server.Written.ToArray()));
        Assert.Equal("HTTP/1.1 204 No Content\r\n\r\n", Encoding.ASCII.GetString(client.Written.ToArray()));
    }

    [Fact]
    public async Task StopsWhenTheCallerCancelsEvenThoughAPeerNeverCloses()
    {
        var client = new ScriptedStream([], TimeSpan.Zero);
        var server = new NeverEndingStream();

        var proxy = new HttpsMitmProxy(new RootCertificateAuthority());
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        var watch = Stopwatch.StartNew();
        await proxy.RelayUntilClosedAsync(client, server, "key", 1234, cancellation.Token);
        watch.Stop();

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"Relay took {watch.Elapsed}.");
    }

    /// <summary>Yields the scripted reads in order and then reports EOF, recording everything written.</summary>
    private sealed class ScriptedStream(IEnumerable<byte[]> reads, TimeSpan readDelay) : Stream
    {
        private readonly Queue<byte[]> _reads = new(reads);

        public MemoryStream Written { get; } = new();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (readDelay > TimeSpan.Zero)
            {
                await Task.Delay(readDelay, cancellationToken);
            }

            if (_reads.Count == 0)
            {
                return 0;
            }

            var next = _reads.Dequeue();
            next.CopyTo(buffer.Span);
            return next.Length;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            Written.WriteAsync(buffer, cancellationToken);

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>A peer that keeps the connection open without ever sending or closing.</summary>
    private sealed class NeverEndingStream : Stream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
