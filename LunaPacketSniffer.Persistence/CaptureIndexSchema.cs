namespace LunaPacketSniffer.Persistence;

/// <summary>The schema of <c>capture.index.sqlite</c>. Raw packet bytes stay in the PCAPNG; the
/// <c>packets.pcap_offset</c> column points back into it.</summary>
internal static class CaptureIndexSchema
{
    public const string CreateTables = """
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

    public const string InsertPacket = """
        INSERT INTO packets(flow_id, timestamp_unix_microseconds, direction, captured_length, original_length, pcap_offset)
        VALUES($flowId, $timestamp, $direction, $capturedLength, $originalLength, $pcapOffset);
        """;

    public const string InsertProcess = """
        INSERT INTO processes(os_process_id, started_at_unix_microseconds, process_name, image_path)
        VALUES($osProcessId, $startedAt, $processName, $imagePath);
        SELECT last_insert_rowid();
        """;

    public const string InsertFlow = """
        INSERT INTO flows(process_id, protocol, local_address, local_port, remote_address, remote_port, created_at_unix_microseconds)
        VALUES($processId, $protocol, $localAddress, $localPort, $remoteAddress, $remotePort, $createdAt);
        SELECT last_insert_rowid();
        """;

    public const string InsertHttpTransaction = """
        INSERT INTO http_transactions(started_at_unix_microseconds, completed_at_unix_microseconds, method, url, status, status_text, http_version, request_headers, response_headers, request_content_type, response_content_type, request_body_length, response_body_length)
        VALUES($startedAt, $completedAt, $method, $url, $status, $statusText, $httpVersion, $requestHeaders, $responseHeaders, $requestContentType, $responseContentType, $requestBodyLength, $responseBodyLength);
        """;

    public const string InsertWebSocketMessage = """
        INSERT INTO websocket_messages(timestamp_unix_microseconds, direction, opcode, payload_length, body_file_path)
        VALUES($timestamp, $direction, $opcode, $payloadLength, $bodyFilePath);
        """;

    /// <summary>KCP rows are cumulative per conversation, so repeated observations upsert one row.</summary>
    public const string UpsertKcpConversation = """
        INSERT INTO kcp_conversations(conversation_id, endpoint_a, endpoint_b, last_command, last_sequence_number, segment_count, reassembled_message_count, reassembled_byte_count)
        VALUES($conversationId, $endpointA, $endpointB, $lastCommand, $lastSequenceNumber, $segmentCount, $messageCount, $byteCount)
        ON CONFLICT(conversation_id, endpoint_a, endpoint_b) DO UPDATE SET
            last_command = excluded.last_command,
            last_sequence_number = excluded.last_sequence_number,
            segment_count = excluded.segment_count,
            reassembled_message_count = excluded.reassembled_message_count,
            reassembled_byte_count = excluded.reassembled_byte_count;
        """;
}
