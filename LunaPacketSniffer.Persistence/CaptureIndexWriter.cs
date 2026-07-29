using Microsoft.Data.Sqlite;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Protocols;

namespace LunaPacketSniffer.Persistence;

/// <summary>
/// Writes the SQLite index that lets a saved capture be browsed without replaying the PCAPNG.
///
/// Every statement is prepared once and reused, and writes are batched into transactions that commit
/// every <see cref="CommitInterval"/> rows, so an abnormal exit still leaves the committed rows readable.
/// </summary>
public sealed class CaptureIndexWriter : IAsyncDisposable
{
    private const int CommitInterval = 1_000;

    private readonly Lock _syncRoot = new();
    private readonly SqliteConnection _connection;
    private readonly SqliteCommand _insertPacket;
    private readonly SqliteCommand _insertProcess;
    private readonly SqliteCommand _insertFlow;
    private readonly SqliteCommand _insertHttpTransaction;
    private readonly SqliteCommand _insertWebSocketMessage;
    private readonly SqliteCommand _upsertKcpConversation;
    private readonly Dictionary<ProcessIdentity, long> _processIds = [];
    private readonly Dictionary<FlowRecord, long> _flowIds = [];
    private SqliteTransaction _transaction;
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

        using (var command = _connection.CreateCommand())
        {
            command.CommandText = CaptureIndexSchema.CreateTables;
            command.ExecuteNonQuery();
        }

        _insertPacket = CreateCommand(CaptureIndexSchema.InsertPacket,
            "$flowId", "$timestamp", "$direction", "$capturedLength", "$originalLength", "$pcapOffset");
        _insertProcess = CreateCommand(CaptureIndexSchema.InsertProcess,
            "$osProcessId", "$startedAt", "$processName", "$imagePath");
        _insertFlow = CreateCommand(CaptureIndexSchema.InsertFlow,
            "$processId", "$protocol", "$localAddress", "$localPort", "$remoteAddress", "$remotePort", "$createdAt");
        _insertHttpTransaction = CreateCommand(CaptureIndexSchema.InsertHttpTransaction,
            "$startedAt", "$completedAt", "$method", "$url", "$status", "$statusText", "$httpVersion",
            "$requestHeaders", "$responseHeaders", "$requestContentType", "$responseContentType",
            "$requestBodyLength", "$responseBodyLength");
        _insertWebSocketMessage = CreateCommand(CaptureIndexSchema.InsertWebSocketMessage,
            "$timestamp", "$direction", "$opcode", "$payloadLength", "$bodyFilePath");
        _upsertKcpConversation = CreateCommand(CaptureIndexSchema.UpsertKcpConversation,
            "$conversationId", "$endpointA", "$endpointB", "$lastCommand", "$lastSequenceNumber",
            "$segmentCount", "$messageCount", "$byteCount");

        _transaction = _connection.BeginTransaction();
    }

    public ValueTask WritePacketAsync(CapturedPacket packet, long pcapOffset)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            var flowId = packet.Flow is null ? null : (long?)GetFlowId(packet.Flow);
            Execute(_insertPacket,
                (object?)flowId ?? DBNull.Value,
                ToUnixMicroseconds(packet.Timestamp),
                (int)packet.Direction,
                packet.Data.Length,
                packet.Data.Length,
                pcapOffset);
        }

        return ValueTask.CompletedTask;
    }

    public void WriteHttpTransaction(HttpTransaction transaction)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            Execute(_insertHttpTransaction,
                ToUnixMicroseconds(transaction.StartedAt),
                ToUnixMicroseconds(transaction.CompletedAt),
                transaction.Method,
                transaction.Url,
                transaction.Status,
                transaction.StatusText,
                transaction.HttpVersion,
                transaction.RequestHeaders,
                transaction.ResponseHeaders,
                transaction.RequestBody.ContentType,
                transaction.ResponseBody.ContentType,
                transaction.RequestBody.Data.Length,
                transaction.ResponseBody.Data.Length);
        }
    }

    public void WriteKcpConversation(KcpConversationUpdate conversation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            Execute(_upsertKcpConversation,
                conversation.ConversationId,
                conversation.EndpointA,
                conversation.EndpointB,
                conversation.LastCommand,
                conversation.LastSequenceNumber,
                conversation.SegmentCount,
                conversation.ReassembledMessageCount,
                conversation.ReassembledByteCount);
        }
    }

    public void WriteWebSocketMessage(WebSocketMessage message)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_syncRoot)
        {
            Execute(_insertWebSocketMessage,
                ToUnixMicroseconds(message.Timestamp),
                message.IsRequest ? 0 : 1,
                message.Opcode,
                message.Data.Length,
                message.FilePath ?? string.Empty);
        }
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
            _insertPacket.Dispose();
            _insertProcess.Dispose();
            _insertFlow.Dispose();
            _insertHttpTransaction.Dispose();
            _insertWebSocketMessage.Dispose();
            _upsertKcpConversation.Dispose();
            _connection.Dispose();
            _disposed = true;
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>Processes and flows are written once and then looked up from memory by identity.</summary>
    private long GetFlowId(FlowRecord flow)
    {
        if (_flowIds.TryGetValue(flow, out var flowId))
        {
            return flowId;
        }

        flowId = ExecuteScalar(_insertFlow,
            GetProcessId(flow.Process),
            flow.Key.Protocol,
            flow.Key.LocalAddress.ToString(),
            flow.Key.LocalPort,
            flow.Key.RemoteAddress.ToString(),
            flow.Key.RemotePort,
            ToUnixMicroseconds(flow.CreatedAt));
        _flowIds.Add(flow, flowId);
        return flowId;
    }

    private long GetProcessId(ProcessIdentity process)
    {
        if (_processIds.TryGetValue(process, out var processId))
        {
            return processId;
        }

        processId = ExecuteScalar(_insertProcess,
            process.ProcessId,
            ToUnixMicroseconds(process.StartedAt),
            process.ProcessName,
            process.ImagePath);
        _processIds.Add(process, processId);
        return processId;
    }

    private SqliteCommand CreateCommand(string commandText, params string[] parameterNames)
    {
        var command = _connection.CreateCommand();
        command.CommandText = commandText;
        foreach (var name in parameterNames)
        {
            command.Parameters.Add(new SqliteParameter(name, DBNull.Value));
        }

        return command;
    }

    private void Execute(SqliteCommand command, params object[] values)
    {
        Bind(command, values);
        command.ExecuteNonQuery();
        RecordWrite();
    }

    private long ExecuteScalar(SqliteCommand command, params object[] values)
    {
        Bind(command, values);
        return (long)command.ExecuteScalar()!;
    }

    private void Bind(SqliteCommand command, object[] values)
    {
        // The transaction is replaced on every batch commit, so it is rebound before each execution.
        command.Transaction = _transaction;
        for (var index = 0; index < values.Length; index++)
        {
            command.Parameters[index].Value = values[index];
        }
    }

    private void RecordWrite()
    {
        _uncommittedWriteCount++;
        if (_uncommittedWriteCount < CommitInterval)
        {
            return;
        }

        _transaction.Commit();
        _transaction.Dispose();
        _transaction = _connection.BeginTransaction();
        _uncommittedWriteCount = 0;
    }

    private static long ToUnixMicroseconds(DateTimeOffset timestamp) =>
        (timestamp.UtcDateTime.Ticks - DateTime.UnixEpoch.Ticks) / 10;
}
