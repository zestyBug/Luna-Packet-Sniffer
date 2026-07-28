using Microsoft.Data.Sqlite;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Protocols;

namespace LunaPacketSniffer.Persistence;

public sealed class CaptureIndexWriter : IAsyncDisposable
{
    private const int CommitInterval = 1_000;
    private readonly Lock _syncRoot = new();
    private readonly SqliteConnection _connection;
    private SqliteTransaction _transaction;
    private readonly Dictionary<ProcessIdentity, long> _processIds = [];
    private readonly Dictionary<FlowRecord, long> _flowIds = [];
    private int _uncommittedWriteCount;
    private bool _disposed;

    public CaptureIndexWriter(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        _connection = new SqliteConnection($"Data Source={path};Cache=Shared");
        _connection.Open();

        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;";
            command.ExecuteNonQuery();
        }

        CreateSchema();
        _transaction = _connection.BeginTransaction();
    }

    public ValueTask WritePacketAsync(CapturedPacket packet, long pcapOffset)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            WritePacket(packet, pcapOffset);
        }

        return ValueTask.CompletedTask;
    }

    public void WriteHttpTransaction(HttpTransaction transaction)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = _transaction;
            command.CommandText = """
                INSERT INTO http_transactions(started_at_unix_microseconds, completed_at_unix_microseconds, method, url, status, status_text, http_version, request_headers, response_headers, request_content_type, response_content_type, request_body_length, response_body_length)
                VALUES($startedAt, $completedAt, $method, $url, $status, $statusText, $httpVersion, $requestHeaders, $responseHeaders, $requestContentType, $responseContentType, $requestBodyLength, $responseBodyLength);
                """;
            command.Parameters.AddWithValue("$startedAt", ToUnixMicroseconds(transaction.StartedAt));
            command.Parameters.AddWithValue("$completedAt", ToUnixMicroseconds(transaction.CompletedAt));
            command.Parameters.AddWithValue("$method", transaction.Method);
            command.Parameters.AddWithValue("$url", transaction.Url);
            command.Parameters.AddWithValue("$status", transaction.Status);
            command.Parameters.AddWithValue("$statusText", transaction.StatusText);
            command.Parameters.AddWithValue("$httpVersion", transaction.HttpVersion);
            command.Parameters.AddWithValue("$requestHeaders", transaction.RequestHeaders);
            command.Parameters.AddWithValue("$responseHeaders", transaction.ResponseHeaders);
            command.Parameters.AddWithValue("$requestContentType", transaction.RequestBody.ContentType);
            command.Parameters.AddWithValue("$responseContentType", transaction.ResponseBody.ContentType);
            command.Parameters.AddWithValue("$requestBodyLength", transaction.RequestBody.Data.Length);
            command.Parameters.AddWithValue("$responseBodyLength", transaction.ResponseBody.Data.Length);
            command.ExecuteNonQuery();
            RecordWrite();
        }
    }

    public void WriteKcpConversation(KcpConversationUpdate conversation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = _transaction;
            command.CommandText = """
                INSERT INTO kcp_conversations(conversation_id, endpoint_a, endpoint_b, last_command, last_sequence_number, segment_count, reassembled_message_count, reassembled_byte_count)
                VALUES($conversationId, $endpointA, $endpointB, $lastCommand, $lastSequenceNumber, $segmentCount, $messageCount, $byteCount)
                ON CONFLICT(conversation_id, endpoint_a, endpoint_b) DO UPDATE SET
                    last_command = excluded.last_command,
                    last_sequence_number = excluded.last_sequence_number,
                    segment_count = excluded.segment_count,
                    reassembled_message_count = excluded.reassembled_message_count,
                    reassembled_byte_count = excluded.reassembled_byte_count;
                """;
            command.Parameters.AddWithValue("$conversationId", conversation.ConversationId);
            command.Parameters.AddWithValue("$endpointA", conversation.EndpointA);
            command.Parameters.AddWithValue("$endpointB", conversation.EndpointB);
            command.Parameters.AddWithValue("$lastCommand", conversation.LastCommand);
            command.Parameters.AddWithValue("$lastSequenceNumber", conversation.LastSequenceNumber);
            command.Parameters.AddWithValue("$segmentCount", conversation.SegmentCount);
            command.Parameters.AddWithValue("$messageCount", conversation.ReassembledMessageCount);
            command.Parameters.AddWithValue("$byteCount", conversation.ReassembledByteCount);
            command.ExecuteNonQuery();
            RecordWrite();
        }
    }

    public void WriteWebSocketMessage(WebSocketMessage message)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = _transaction;
            command.CommandText = """
                INSERT INTO websocket_messages(timestamp_unix_microseconds, direction, opcode, payload_length, body_file_path)
                VALUES($timestamp, $direction, $opcode, $payloadLength, $bodyFilePath);
                """;
            command.Parameters.AddWithValue("$timestamp", ToUnixMicroseconds(message.Timestamp));
            command.Parameters.AddWithValue("$direction", message.IsRequest ? 0 : 1);
            command.Parameters.AddWithValue("$opcode", message.Opcode);
            command.Parameters.AddWithValue("$payloadLength", message.Data.Length);
            command.Parameters.AddWithValue("$bodyFilePath", message.FilePath ?? string.Empty);
            command.ExecuteNonQuery();
            RecordWrite();
        }
    }

    private void WritePacket(CapturedPacket packet, long pcapOffset)
    {

        long? flowId = packet.Flow is null ? null : GetFlowId(packet.Flow);
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = """
            INSERT INTO packets(flow_id, timestamp_unix_microseconds, direction, captured_length, original_length, pcap_offset)
            VALUES($flowId, $timestamp, $direction, $capturedLength, $originalLength, $pcapOffset);
            """;
        command.Parameters.AddWithValue("$flowId", (object?)flowId ?? DBNull.Value);
        command.Parameters.AddWithValue("$timestamp", (packet.Timestamp.UtcDateTime.Ticks - DateTime.UnixEpoch.Ticks) / 10);
        command.Parameters.AddWithValue("$direction", (int)packet.Direction);
        command.Parameters.AddWithValue("$capturedLength", packet.Data.Length);
        command.Parameters.AddWithValue("$originalLength", packet.Data.Length);
        command.Parameters.AddWithValue("$pcapOffset", pcapOffset);
        command.ExecuteNonQuery();
        RecordWrite();
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return ValueTask.CompletedTask;
        }

        lock (_syncRoot)
        {
            _transaction.Commit();
            _transaction.Dispose();
            _connection.Dispose();
            _disposed = true;
        }
        return ValueTask.CompletedTask;
    }

    private long GetFlowId(FlowRecord flow)
    {
        if (_flowIds.TryGetValue(flow, out var flowId))
        {
            return flowId;
        }

        var processId = GetProcessId(flow.Process);
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = """
            INSERT INTO flows(process_id, protocol, local_address, local_port, remote_address, remote_port, created_at_unix_microseconds)
            VALUES($processId, $protocol, $localAddress, $localPort, $remoteAddress, $remotePort, $createdAt);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$processId", processId);
        command.Parameters.AddWithValue("$protocol", flow.Key.Protocol);
        command.Parameters.AddWithValue("$localAddress", flow.Key.LocalAddress.ToString());
        command.Parameters.AddWithValue("$localPort", flow.Key.LocalPort);
        command.Parameters.AddWithValue("$remoteAddress", flow.Key.RemoteAddress.ToString());
        command.Parameters.AddWithValue("$remotePort", flow.Key.RemotePort);
        command.Parameters.AddWithValue("$createdAt", (flow.CreatedAt.UtcDateTime.Ticks - DateTime.UnixEpoch.Ticks) / 10);
        flowId = (long)command.ExecuteScalar()!;
        _flowIds.Add(flow, flowId);
        return flowId;
    }

    private void CommitBatch()
    {
        _transaction.Commit();
        _transaction.Dispose();
        _transaction = _connection.BeginTransaction();
        _uncommittedWriteCount = 0;
    }

    private void RecordWrite()
    {
        _uncommittedWriteCount++;
        if (_uncommittedWriteCount >= CommitInterval)
        {
            CommitBatch();
        }
    }

    private static long ToUnixMicroseconds(DateTimeOffset timestamp) =>
        (timestamp.UtcDateTime.Ticks - DateTime.UnixEpoch.Ticks) / 10;

    private long GetProcessId(ProcessIdentity process)
    {
        if (_processIds.TryGetValue(process, out var processId))
        {
            return processId;
        }

        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = """
            INSERT INTO processes(os_process_id, started_at_unix_microseconds, process_name, image_path)
            VALUES($osProcessId, $startedAt, $processName, $imagePath);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$osProcessId", process.ProcessId);
        command.Parameters.AddWithValue("$startedAt", (process.StartedAt.UtcDateTime.Ticks - DateTime.UnixEpoch.Ticks) / 10);
        command.Parameters.AddWithValue("$processName", process.ProcessName);
        command.Parameters.AddWithValue("$imagePath", process.ImagePath);
        processId = (long)command.ExecuteScalar()!;
        _processIds.Add(process, processId);
        return processId;
    }

    private void CreateSchema()
    {
        using var command = _connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE processes (
                id INTEGER PRIMARY KEY,
                os_process_id INTEGER NOT NULL,
                started_at_unix_microseconds INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                image_path TEXT NOT NULL
            );
            CREATE TABLE flows (
                id INTEGER PRIMARY KEY,
                process_id INTEGER NOT NULL REFERENCES processes(id),
                protocol INTEGER NOT NULL,
                local_address TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_address TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                created_at_unix_microseconds INTEGER NOT NULL
            );
            CREATE TABLE packets (
                id INTEGER PRIMARY KEY,
                flow_id INTEGER NULL REFERENCES flows(id),
                timestamp_unix_microseconds INTEGER NOT NULL,
                direction INTEGER NOT NULL,
                captured_length INTEGER NOT NULL,
                original_length INTEGER NOT NULL,
                pcap_offset INTEGER NOT NULL
            );
            CREATE INDEX packets_flow_id ON packets(flow_id);
            CREATE INDEX packets_timestamp ON packets(timestamp_unix_microseconds);
            CREATE TABLE http_transactions (
                id INTEGER PRIMARY KEY,
                started_at_unix_microseconds INTEGER NOT NULL,
                completed_at_unix_microseconds INTEGER NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                status INTEGER NOT NULL,
                status_text TEXT NOT NULL,
                http_version TEXT NOT NULL,
                request_headers TEXT NOT NULL,
                response_headers TEXT NOT NULL,
                request_content_type TEXT NOT NULL,
                response_content_type TEXT NOT NULL,
                request_body_length INTEGER NOT NULL,
                response_body_length INTEGER NOT NULL
            );
            CREATE INDEX http_transactions_started_at ON http_transactions(started_at_unix_microseconds);
            CREATE TABLE kcp_conversations (
                id INTEGER PRIMARY KEY,
                conversation_id INTEGER NOT NULL,
                endpoint_a TEXT NOT NULL,
                endpoint_b TEXT NOT NULL,
                last_command TEXT NOT NULL,
                last_sequence_number INTEGER NOT NULL,
                segment_count INTEGER NOT NULL,
                reassembled_message_count INTEGER NOT NULL,
                reassembled_byte_count INTEGER NOT NULL,
                UNIQUE(conversation_id, endpoint_a, endpoint_b)
            );
            CREATE TABLE websocket_messages (
                id INTEGER PRIMARY KEY,
                timestamp_unix_microseconds INTEGER NOT NULL,
                direction INTEGER NOT NULL,
                opcode TEXT NOT NULL,
                payload_length INTEGER NOT NULL,
                body_file_path TEXT NOT NULL
            );
            CREATE INDEX websocket_messages_timestamp ON websocket_messages(timestamp_unix_microseconds);
            """;
        command.ExecuteNonQuery();
    }
}
