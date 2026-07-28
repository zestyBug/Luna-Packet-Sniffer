using System.Net;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Persistence;
using Microsoft.Data.Sqlite;
using Xunit;

namespace LunaPacketSniffer.Protocols.Tests;

public sealed class CaptureOutputIntegrationTests
{
    [Fact]
    public async Task ProducesReadableCaptureOutputSet()
    {
        var directory = Path.Combine(Path.GetTempPath(), "LunaPacketSniffer.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(directory);
            var timestamp = DateTimeOffset.UtcNow;
            var process = new ProcessIdentity(1234, timestamp.AddMinutes(-1), "sample", @"C:\sample.exe");
            var flow = new FlowRecord(process, new FlowKey(6, IPAddress.Loopback, 50000, IPAddress.Parse("203.0.113.1"), 80), timestamp);
            var packet = new CapturedPacket(timestamp, PacketDirection.Outbound, 1, [0x45, 0, 0, 0], flow);

            await using (var pcapWriter = new PcapNgWriter(Path.Combine(directory, "capture.pcapng")))
            await using (var indexWriter = new CaptureIndexWriter(Path.Combine(directory, "capture.index.sqlite")))
            await using (var harWriter = new HttpHarWriter(Path.Combine(directory, "capture.http.har")))
            await using (var sessionWriter = new CaptureSessionJsonWriter(Path.Combine(directory, "sessions.json")))
            {
                harWriter.TransactionObserved += indexWriter.WriteHttpTransaction;
                var offset = await pcapWriter.WritePacketAsync(packet);
                await indexWriter.WritePacketAsync(packet, offset);
                sessionWriter.Observe(packet);
                harWriter.ObserveDecrypted("connection", true, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"u8);
                harWriter.ObserveDecrypted("connection", false, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"u8);
            }

            Assert.True(new FileInfo(Path.Combine(directory, "capture.pcapng")).Length > 48);
            Assert.Contains("example.test", await File.ReadAllTextAsync(Path.Combine(directory, "capture.http.har")));
            Assert.Contains("sample", await File.ReadAllTextAsync(Path.Combine(directory, "sessions.json")));
            Assert.Single(Directory.GetFiles(Path.Combine(directory, "bodies")));

            using (var connection = new SqliteConnection($"Data Source={Path.Combine(directory, "capture.index.sqlite")}"))
            {
                connection.Open();
                Assert.Equal(1L, CountRows(connection, "packets"));
                Assert.Equal(1L, CountRows(connection, "http_transactions"));
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private static long CountRows(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table};";
        return (long)command.ExecuteScalar()!;
    }
}
