using LunaPacketSniffer.Persistence;
using LunaPacketSniffer.Protocols;
using Microsoft.Data.Sqlite;
using Xunit;

namespace LunaPacketSniffer.Protocols.Tests;

public sealed class CaptureIndexWriterTests
{
    [Fact]
    public async Task StoresHttpAndKcpSessions()
    {
        var path = Path.GetTempFileName();
        try
        {
            await using (var writer = new CaptureIndexWriter(path))
            {
                var timestamp = DateTimeOffset.UtcNow;
                writer.WriteHttpTransaction(new HttpTransaction(
                    timestamp,
                    timestamp.AddMilliseconds(10),
                    "GET",
                    "https://example.test/",
                    200,
                    "OK",
                    "HTTP/1.1",
                    "Accept: application/json",
                    "Content-Type: application/json",
                    new HttpBody(string.Empty, string.Empty, []),
                    new HttpBody("application/json", string.Empty, "{}"u8.ToArray())));
                writer.WriteKcpConversation(new KcpConversationUpdate(12, "127.0.0.1:1000", "127.0.0.1:2000", "PUSH", 4, 7, 2, 128));
                writer.WriteWebSocketMessage(new WebSocketMessage(timestamp, true, "Text", "hello"u8.ToArray(), "bodies/00000001-websocket-request.txt"));
            }

            using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                connection.Open();
                Assert.Equal(1L, ExecuteCount(connection, "http_transactions"));
                Assert.Equal(1L, ExecuteCount(connection, "kcp_conversations"));
                Assert.Equal(1L, ExecuteCount(connection, "websocket_messages"));
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(path);
        }
    }

    private static long ExecuteCount(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table};";
        return (long)command.ExecuteScalar()!;
    }
}
