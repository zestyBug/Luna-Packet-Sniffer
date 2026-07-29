using System.IO;
using LunaPacketSniffer.App.Recording;
using LunaPacketSniffer.App.ViewModels;
using LunaPacketSniffer.Core;
using Microsoft.Data.Sqlite;

namespace LunaPacketSniffer.App.Loading;

/// <summary>The grid contents restored from a saved capture folder.</summary>
internal sealed record LoadedCapture(
    IReadOnlyList<PacketListItem> Packets,
    IReadOnlyList<HttpSessionListItem> HttpTransactions,
    IReadOnlyList<WebSocketListItem> WebSocketMessages,
    IReadOnlyList<FlowSessionListItem> Flows,
    IReadOnlyList<KcpConversationListItem> KcpConversations);

/// <summary>
/// Rebuilds the grid rows of a previously saved capture from its SQLite index. Raw bytes and HTTP
/// bodies are not read here; rows carry loaders that fetch them when the row is selected.
/// </summary>
internal static class CaptureLoader
{
    private const long TcpProtocol = 6;
    private const long UdpProtocol = 17;

    /// <exception cref="InvalidDataException">The folder is not a LunaPacketSniffer capture.</exception>
    public static LoadedCapture Load(string directory)
    {
        var indexPath = Path.Combine(directory, CaptureOutput.IndexFileName);
        if (!File.Exists(indexPath))
        {
            throw new InvalidDataException($"The selected folder does not contain {CaptureOutput.IndexFileName}.");
        }

        using var connection = OpenReadOnly(indexPath);
        return new LoadedCapture(
            LoadPackets(connection, directory),
            LoadHttpTransactions(connection, directory),
            LoadWebSocketMessages(connection, directory),
            LoadFlows(connection, directory),
            LoadKcpConversations(connection));
    }

    public static SqliteConnection OpenReadOnly(string indexPath)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = indexPath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static List<PacketListItem> LoadPackets(SqliteConnection connection, string directory)
    {
        var pcapPath = Path.Combine(directory, CaptureOutput.PcapFileName);
        var rows = new List<PacketListItem>();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT packets.timestamp_unix_microseconds, packets.direction, packets.captured_length, packets.pcap_offset,
                   COALESCE(processes.os_process_id, 0), COALESCE(processes.process_name, 'Unknown'),
                   COALESCE(flows.protocol, -1), COALESCE(flows.local_address, ''), COALESCE(flows.local_port, 0),
                   COALESCE(flows.remote_address, ''), COALESCE(flows.remote_port, 0)
            FROM packets
            LEFT JOIN flows ON flows.id = packets.flow_id
            LEFT JOIN processes ON processes.id = flows.process_id
            ORDER BY packets.timestamp_unix_microseconds;
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var newLine = Environment.NewLine;
            var timestamp = FromUnixMicroseconds(reader.GetInt64(0));
            var isOutbound = reader.GetInt64(1) == (long)PacketDirection.Outbound;
            var capturedLength = checked((int)reader.GetInt64(2));
            var pcapOffset = reader.GetInt64(3);
            var processId = reader.GetInt64(4);
            var processName = reader.GetString(5);
            var protocol = FormatProtocol(reader.GetInt64(6));
            var source = FormatEndpoint(reader.GetString(7), reader.GetInt64(8));
            var destination = FormatEndpoint(reader.GetString(9), reader.GetInt64(10));
            var detail =
                $"Timestamp: {timestamp:O}{newLine}Direction: {(isOutbound ? "Outbound" : "Inbound")}{newLine}" +
                $"Process: {processName} ({processId}){newLine}Protocol: {protocol}{newLine}" +
                $"Source: {source}{newLine}Destination: {destination}{newLine}Length: {capturedLength:N0} bytes";
            rows.Add(new PacketListItem(
                timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
                isOutbound ? "→" : "←",
                processId == 0 ? "Unknown" : processId.ToString(),
                processName,
                protocol,
                source,
                destination,
                capturedLength,
                "Loaded capture",
                detail,
                () => LoadedCaptureDetails.CreatePacketDetail(detail, pcapPath, pcapOffset, capturedLength)));
        }

        return rows;
    }

    private static List<HttpSessionListItem> LoadHttpTransactions(SqliteConnection connection, string directory)
    {
        // The index does not record which body file belongs to which transaction, so the files are
        // matched to transactions in the order they were written.
        var bodyDirectory = Path.Combine(directory, CaptureOutput.BodiesDirectoryName);
        var requestBodyFiles = GetHttpBodyFiles(bodyDirectory, "-request.");
        var responseBodyFiles = GetHttpBodyFiles(bodyDirectory, "-response.");
        var requestBodyIndex = 0;
        var responseBodyIndex = 0;
        var rows = new List<HttpSessionListItem>();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT started_at_unix_microseconds, completed_at_unix_microseconds, method, url, status, status_text,
                   http_version, request_headers, response_headers, request_content_type, response_content_type,
                   request_body_length, response_body_length
            FROM http_transactions
            ORDER BY started_at_unix_microseconds;
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var newLine = Environment.NewLine;
            var startedAt = FromUnixMicroseconds(reader.GetInt64(0));
            var completedAt = FromUnixMicroseconds(reader.GetInt64(1));
            var method = reader.GetString(2);
            var url = reader.GetString(3);
            var status = reader.GetInt64(4);
            var statusText = reader.GetString(5);
            var requestContentType = reader.GetString(9);
            var responseContentType = reader.GetString(10);
            var requestBodyLength = reader.GetInt64(11);
            var responseBodyLength = reader.GetInt64(12);
            var requestBodyPath = requestBodyLength > 0 && requestBodyIndex < requestBodyFiles.Count ? requestBodyFiles[requestBodyIndex++] : null;
            var responseBodyPath = responseBodyLength > 0 && responseBodyIndex < responseBodyFiles.Count ? responseBodyFiles[responseBodyIndex++] : null;
            var detail =
                $"Started: {startedAt:O}{newLine}Completed: {completedAt:O}{newLine}" +
                $"Request: {method} {url} {reader.GetString(6)}{newLine}Response: {status} {statusText}{newLine}{newLine}" +
                $"Request headers:{newLine}{reader.GetString(7)}{newLine}{newLine}" +
                $"Response headers:{newLine}{reader.GetString(8)}";
            rows.Add(new HttpSessionListItem(
                startedAt.LocalDateTime.ToString("HH:mm:ss.fff"),
                method,
                $"{status} {statusText}",
                url,
                HttpSessionListItem.FormatDuration(startedAt, completedAt),
                detail,
                () => LoadedCaptureDetails.CreateHttpDetail(
                    detail,
                    requestBodyLength,
                    requestContentType,
                    requestBodyPath,
                    responseBodyLength,
                    responseContentType,
                    responseBodyPath)));
        }

        return rows;
    }

    private static List<WebSocketListItem> LoadWebSocketMessages(SqliteConnection connection, string directory)
    {
        var rows = new List<WebSocketListItem>();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT timestamp_unix_microseconds, direction, opcode, payload_length, body_file_path FROM websocket_messages ORDER BY timestamp_unix_microseconds;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var newLine = Environment.NewLine;
            var timestamp = FromUnixMicroseconds(reader.GetInt64(0));
            var isRequest = reader.GetInt64(1) == 0;
            var opcode = reader.GetString(2);
            var payloadLength = reader.GetInt64(3);
            var bodyFilePath = reader.GetString(4);
            var resolvedBodyPath = Path.IsPathRooted(bodyFilePath) ? bodyFilePath : Path.Combine(directory, bodyFilePath);
            var detail =
                $"Timestamp: {timestamp:O}{newLine}Direction: {WebSocketListItem.FormatDirection(isRequest)}{newLine}" +
                $"Type: {opcode}{newLine}Length: {payloadLength:N0} bytes{newLine}Saved: {resolvedBodyPath}";
            rows.Add(new WebSocketListItem(
                timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
                WebSocketListItem.FormatDirection(isRequest),
                opcode,
                checked((int)payloadLength),
                opcode,
                detail));
        }

        return rows;
    }

    private static List<FlowSessionListItem> LoadFlows(SqliteConnection connection, string directory)
    {
        var rows = new List<FlowSessionListItem>();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT flows.id, processes.os_process_id, processes.process_name, flows.protocol, flows.local_address, flows.local_port, flows.remote_address, flows.remote_port,
                   COUNT(packets.id), COALESCE(SUM(packets.captured_length), 0)
            FROM flows
            JOIN processes ON processes.id = flows.process_id
            LEFT JOIN packets ON packets.flow_id = flows.id
            GROUP BY flows.id
            ORDER BY flows.created_at_unix_microseconds;
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var flowId = reader.GetInt64(0);
            var isTcp = reader.GetInt64(3) == TcpProtocol;
            rows.Add(new FlowSessionListItem(
                reader.GetInt64(1).ToString(),
                reader.GetString(2),
                isTcp ? "TCP" : "UDP",
                FormatEndpoint(reader.GetString(4), reader.GetInt64(5)),
                FormatEndpoint(reader.GetString(6), reader.GetInt64(7)),
                reader.GetInt64(8),
                reader.GetInt64(9),
                isTcp ? () => LoadedCaptureDetails.CreateTcpFlowDetail(directory, flowId) : null));
        }

        return rows;
    }

    private static List<KcpConversationListItem> LoadKcpConversations(SqliteConnection connection)
    {
        var rows = new List<KcpConversationListItem>();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT conversation_id, endpoint_a, endpoint_b, last_command, last_sequence_number, segment_count, reassembled_message_count, reassembled_byte_count FROM kcp_conversations ORDER BY id;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new KcpConversationListItem(
                reader.GetInt64(0).ToString(),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt64(4),
                reader.GetInt64(5),
                reader.GetInt64(6),
                reader.GetInt64(7)));
        }

        return rows;
    }

    private static DateTimeOffset FromUnixMicroseconds(long microseconds) =>
        DateTimeOffset.FromUnixTimeMilliseconds(microseconds / 1_000).AddTicks((microseconds % 1_000) * 10).ToLocalTime();

    private static string FormatEndpoint(string address, long port) =>
        string.IsNullOrEmpty(address) ? "Unknown" : $"{address}:{port}";

    private static string FormatProtocol(long protocolNumber) => protocolNumber switch
    {
        TcpProtocol => "TCP",
        UdpProtocol => "UDP",
        _ => "Unknown",
    };

    private static List<string> GetHttpBodyFiles(string bodyDirectory, string directionMarker) =>
        Directory.Exists(bodyDirectory)
            ? Directory.EnumerateFiles(bodyDirectory)
                .Where(path => Path.GetFileName(path).Contains(directionMarker, StringComparison.OrdinalIgnoreCase) && !Path.GetFileName(path).Contains("-websocket-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => Path.GetFileName(path), StringComparer.Ordinal)
                .ToList()
            : [];
}
