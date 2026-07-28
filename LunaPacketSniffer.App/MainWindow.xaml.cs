using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using LunaPacketSniffer.Capture;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Networking;
using LunaPacketSniffer.Persistence;
using LunaPacketSniffer.Protocols;
using LunaPacketSniffer.Proxy;

namespace LunaPacketSniffer.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _statisticsTimer;
    private readonly RootCertificateAuthority _rootCertificateAuthority = new();
    private readonly ConcurrentQueue<PacketListItem> _pendingPacketRows = new();
    private readonly ConcurrentQueue<HttpSessionListItem> _pendingHttpRows = new();
    private readonly ConcurrentQueue<WebSocketListItem> _pendingWebSocketRows = new();
    private readonly ConcurrentQueue<FlowUpdate> _pendingFlowUpdates = new();
    private readonly ConcurrentQueue<KcpConversationUpdate> _pendingKcpUpdates = new();
    private readonly ObservableCollection<PacketListItem> _packetRows = [];
    private readonly ObservableCollection<HttpSessionListItem> _httpRows = [];
    private readonly ObservableCollection<WebSocketListItem> _webSocketRows = [];
    private readonly ObservableCollection<FlowSessionListItem> _flowRows = [];
    private readonly Dictionary<string, FlowSessionListItem> _flowRowsByKey = [];
    private readonly ObservableCollection<KcpConversationListItem> _kcpRows = [];
    private readonly Dictionary<string, KcpConversationListItem> _kcpRowsByKey = [];
    private readonly ObservableCollection<CaptureFilter> _filters = [];
    private readonly ObservableCollection<ProcessListItem> _processes = [];
    private CaptureSession? _captureSession;
    private PcapNgWriter? _writer;
    private CaptureIndexWriter? _indexWriter;
    private HttpHarWriter? _harWriter;
    private CaptureSessionJsonWriter? _sessionWriter;
    private HttpsMitmProxy? _httpsProxy;
    private WindowsProxySession? _windowsProxySession;
    private IReadOnlyList<CaptureFilter> _decryptedProcessFilters = [];
    private readonly ConcurrentDictionary<int, bool> _decryptedPortMatches = new();
    private ProtocolAnalyzerSession? _protocolAnalyzer;
    private Task? _writerTask;
    private string? _outputDirectory;
    private FilterWindow? _filterWindow;
    private CertificateWindow? _certificateWindow;
    private string? _loadedCaptureDirectory;

    public MainWindow()
    {
        InitializeComponent();
        PacketGrid.ItemsSource = _packetRows;
        HttpGrid.ItemsSource = _httpRows;
        WebSocketGrid.ItemsSource = _webSocketRows;
        FlowGrid.ItemsSource = _flowRows;
        KcpGrid.ItemsSource = _kcpRows;
        _statisticsTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _statisticsTimer.Tick += (_, _) => UpdateStatistics();
    }

    private async void StartButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ApplicationLog.Write("Capture start requested.");
            _outputDirectory = CreateOutputDirectory();
            _packetRows.Clear();
            _pendingPacketRows.Clear();
            _httpRows.Clear();
            _pendingHttpRows.Clear();
            _webSocketRows.Clear();
            _pendingWebSocketRows.Clear();
            _flowRows.Clear();
            _flowRowsByKey.Clear();
            _pendingFlowUpdates.Clear();
            _kcpRows.Clear();
            _kcpRowsByKey.Clear();
            _pendingKcpUpdates.Clear();
            StatusText.Text = "Creating capture files";
            _writer = new PcapNgWriter(Path.Combine(_outputDirectory, "capture.pcapng"));
            _indexWriter = new CaptureIndexWriter(Path.Combine(_outputDirectory, "capture.index.sqlite"));
            _harWriter = new HttpHarWriter(Path.Combine(_outputDirectory, "capture.http.har"));
            _sessionWriter = new CaptureSessionJsonWriter(Path.Combine(_outputDirectory, "sessions.json"));
            _harWriter.TransactionObserved += transaction =>
            {
                _pendingHttpRows.Enqueue(HttpSessionListItem.Create(transaction));
                _indexWriter.WriteHttpTransaction(transaction);
            };
            _harWriter.WebSocketMessageObserved += message =>
            {
                _pendingWebSocketRows.Enqueue(WebSocketListItem.Create(message));
                _indexWriter.WriteWebSocketMessage(message);
            };
            _protocolAnalyzer = new ProtocolAnalyzerSession();
            _protocolAnalyzer.KcpConversationObserved += update =>
            {
                _pendingKcpUpdates.Enqueue(update);
                _indexWriter.WriteKcpConversation(update);
            };
            _captureSession = new CaptureSession();
            foreach (var filter in _filters)
            {
                _captureSession.Filters.Add(filter);
            }
            StartHttpsMitm();
            StatusText.Text = "Opening WinDivert";
            ApplicationLog.Write("Opening WinDivert.");
            _captureSession.Start();
            _writerTask = WritePacketsAsync(_captureSession, _writer, _indexWriter, _harWriter, _sessionWriter, _protocolAnalyzer, _pendingPacketRows, _pendingFlowUpdates);

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            StatusText.Text = "Capturing";
            DetailTextBox.Text = $"Capture output: {_outputDirectory}";
            ApplicationLog.Write($"Capture started. Output: {_outputDirectory}");
            _statisticsTimer.Start();
        }
        catch (Exception exception)
        {
            ApplicationLog.Write(exception);
            await StopHttpsMitmAsync();
            if (_captureSession is not null)
            {
                await _captureSession.StopAsync();
            }

            if (_writerTask is not null)
            {
                await _writerTask;
            }

            if (_writer is not null)
            {
                await _writer.DisposeAsync();
            }

            if (_indexWriter is not null)
            {
                await _indexWriter.DisposeAsync();
            }

            if (_harWriter is not null)
            {
                await _harWriter.DisposeAsync();
            }

            if (_sessionWriter is not null)
            {
                await _sessionWriter.DisposeAsync();
            }

            _writer = null;
            _indexWriter = null;
            _harWriter = null;
            _sessionWriter = null;
            _protocolAnalyzer = null;
            _captureSession = null;
            _writerTask = null;
            StatusText.Text = $"{exception.GetType().Name}: {exception.Message}";
            DetailTextBox.Text = exception.ToString();
        }
    }

    private async void StopButton_Click(object sender, RoutedEventArgs e)
    {
        if (_captureSession is null || _writer is null || _writerTask is null)
        {
            return;
        }

        StopButton.IsEnabled = false;
        StatusText.Text = "Finalizing capture";
        ApplicationLog.Write("Capture stop requested.");
        _statisticsTimer.Stop();

        await StopHttpsMitmAsync();
        await _captureSession.StopAsync();
        await _writerTask;
        await _writer.DisposeAsync();
        await _indexWriter!.DisposeAsync();
        await _harWriter!.DisposeAsync();
        await _sessionWriter!.DisposeAsync();

        StatusText.Text = $"Saved {_captureSession.CapturedPacketCount:N0} packets";
        ApplicationLog.Write($"Capture stopped. Packets: {_captureSession.CapturedPacketCount}");
        _captureSession = null;
        _writer = null;
        _indexWriter = null;
        _harWriter = null;
        _sessionWriter = null;
        _protocolAnalyzer = null;
        _writerTask = null;
        StartButton.IsEnabled = true;
    }

    private void OpenFiltersMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_filterWindow is null)
        {
            _filterWindow = new FilterWindow(_filters, _processes) { Owner = this };
            _filterWindow.Closed += (_, _) => _filterWindow = null;
            _filterWindow.Show();
            return;
        }

        _filterWindow.Activate();
    }

    private void OpenCertificatesMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_certificateWindow is null)
        {
            _certificateWindow = new CertificateWindow(_rootCertificateAuthority) { Owner = this };
            _certificateWindow.Closed += (_, _) => _certificateWindow = null;
            _certificateWindow.Show();
            return;
        }

        _certificateWindow.Activate();
    }

    private void OpenCaptureMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_captureSession is not null)
        {
            StatusText.Text = "Stop the active capture before loading another capture.";
            return;
        }

        var dialog = new OpenFolderDialog
        {
            Title = "Select a LunaPacketSniffer capture folder",
            InitialDirectory = Path.Combine(AppContext.BaseDirectory, "out"),
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            LoadCapture(dialog.FolderName);
        }
        catch (Exception exception) when (exception is IOException or SqliteException or InvalidDataException)
        {
            ApplicationLog.Write(exception);
            StatusText.Text = $"Could not load capture: {exception.Message}";
            DetailTextBox.Text = exception.ToString();
        }
    }

    private void OpenOutputFolderMenuItem_Click(object sender, RoutedEventArgs e)
    {
        var directory = _loadedCaptureDirectory ?? Path.Combine(AppContext.BaseDirectory, "out");
        Directory.CreateDirectory(directory);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{directory}\"") { UseShellExecute = true });
    }

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void LoadCapture(string directory)
    {
        var indexPath = Path.Combine(directory, "capture.index.sqlite");
        if (!File.Exists(indexPath))
        {
            throw new InvalidDataException("The selected folder does not contain capture.index.sqlite.");
        }

        _packetRows.Clear();
        _httpRows.Clear();
        _webSocketRows.Clear();
        _flowRows.Clear();
        _flowRowsByKey.Clear();
        _kcpRows.Clear();
        _kcpRowsByKey.Clear();

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = indexPath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());
        connection.Open();

        LoadPackets(connection, directory);
        LoadHttpTransactions(connection, directory);
        LoadWebSocketMessages(connection, directory);
        LoadFlows(connection);
        LoadKcpConversations(connection);

        _loadedCaptureDirectory = directory;
        StatusText.Text = $"Loaded {Path.GetFileName(directory)}";
        DetailTextBox.Text = $"Loaded capture: {directory}";
    }

    private void LoadPackets(SqliteConnection connection, string directory)
    {
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
            var timestamp = FromUnixMicroseconds(reader.GetInt64(0));
            var isOutbound = reader.GetInt64(1) == (long)PacketDirection.Outbound;
            var capturedLength = checked((int)reader.GetInt64(2));
            var pcapOffset = reader.GetInt64(3);
            var protocolNumber = reader.GetInt64(6);
            var protocol = protocolNumber switch
            {
                6 => "TCP",
                17 => "UDP",
                _ => "Unknown",
            };
            var source = FormatEndpoint(reader.GetString(7), reader.GetInt64(8));
            var destination = FormatEndpoint(reader.GetString(9), reader.GetInt64(10));
            var processId = reader.GetInt64(4);
            var processName = reader.GetString(5);
            var detail = $"Timestamp: {timestamp:O}{Environment.NewLine}Direction: {(isOutbound ? "Outbound" : "Inbound")}{Environment.NewLine}Process: {processName} ({processId}){Environment.NewLine}Protocol: {protocol}{Environment.NewLine}Source: {source}{Environment.NewLine}Destination: {destination}{Environment.NewLine}Length: {reader.GetInt64(2):N0} bytes";
            _packetRows.Add(new PacketListItem(
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
                () => CreateLoadedPacketDetail(detail, Path.Combine(directory, "capture.pcapng"), pcapOffset, capturedLength)));
        }
    }

    private void LoadHttpTransactions(SqliteConnection connection, string directory)
    {
        var bodyDirectory = Path.Combine(directory, "bodies");
        var requestBodyFiles = GetHttpBodyFiles(bodyDirectory, "-request.");
        var responseBodyFiles = GetHttpBodyFiles(bodyDirectory, "-response.");
        var requestBodyIndex = 0;
        var responseBodyIndex = 0;
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT started_at_unix_microseconds, completed_at_unix_microseconds, method, url, status, status_text, http_version, request_headers, response_headers, request_content_type, response_content_type, request_body_length, response_body_length FROM http_transactions ORDER BY started_at_unix_microseconds;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var startedAt = FromUnixMicroseconds(reader.GetInt64(0));
            var completedAt = FromUnixMicroseconds(reader.GetInt64(1));
            var requestBodyLength = reader.GetInt64(11);
            var responseBodyLength = reader.GetInt64(12);
            var requestContentType = reader.GetString(9);
            var responseContentType = reader.GetString(10);
            var requestBodyPath = requestBodyLength > 0 && requestBodyIndex < requestBodyFiles.Count ? requestBodyFiles[requestBodyIndex++] : null;
            var responseBodyPath = responseBodyLength > 0 && responseBodyIndex < responseBodyFiles.Count ? responseBodyFiles[responseBodyIndex++] : null;
            var detail = $"Started: {startedAt:O}{Environment.NewLine}Completed: {completedAt:O}{Environment.NewLine}Request: {reader.GetString(2)} {reader.GetString(3)} {reader.GetString(6)}{Environment.NewLine}Response: {reader.GetInt64(4)} {reader.GetString(5)}{Environment.NewLine}{Environment.NewLine}Request headers:{Environment.NewLine}{reader.GetString(7)}{Environment.NewLine}{Environment.NewLine}Response headers:{Environment.NewLine}{reader.GetString(8)}";
            _httpRows.Add(new HttpSessionListItem(
                startedAt.LocalDateTime.ToString("HH:mm:ss.fff"),
                reader.GetString(2),
                $"{reader.GetInt64(4)} {reader.GetString(5)}",
                reader.GetString(3),
                $"{Math.Max(0, (completedAt - startedAt).TotalMilliseconds):F0} ms",
                detail,
                () => CreateLoadedHttpDetail(detail, requestBodyLength, requestContentType, requestBodyPath, responseBodyLength, responseContentType, responseBodyPath)));
        }
    }

    private void LoadWebSocketMessages(SqliteConnection connection, string directory)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT timestamp_unix_microseconds, direction, opcode, payload_length, body_file_path FROM websocket_messages ORDER BY timestamp_unix_microseconds;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var timestamp = FromUnixMicroseconds(reader.GetInt64(0));
            var isRequest = reader.GetInt64(1) == 0;
            var bodyFilePath = reader.GetString(4);
            var resolvedBodyPath = Path.IsPathRooted(bodyFilePath) ? bodyFilePath : Path.Combine(directory, bodyFilePath);
            var detail = $"Timestamp: {timestamp:O}{Environment.NewLine}Direction: {(isRequest ? "Client → Server" : "Server → Client")}{Environment.NewLine}Type: {reader.GetString(2)}{Environment.NewLine}Length: {reader.GetInt64(3):N0} bytes{Environment.NewLine}Saved: {resolvedBodyPath}";
            _webSocketRows.Add(new WebSocketListItem(
                timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
                isRequest ? "Client → Server" : "Server → Client",
                reader.GetString(2),
                checked((int)reader.GetInt64(3)),
                reader.GetString(2),
                detail));
        }
    }

    private void LoadFlows(SqliteConnection connection)
    {
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
            var protocol = reader.GetInt64(3) == 6 ? "TCP" : "UDP";
            _flowRows.Add(new FlowSessionListItem(
                reader.GetInt64(1).ToString(),
                reader.GetString(2),
                protocol,
                FormatEndpoint(reader.GetString(4), reader.GetInt64(5)),
                FormatEndpoint(reader.GetString(6), reader.GetInt64(7)),
                reader.GetInt64(8),
                reader.GetInt64(9),
                protocol == "TCP" ? () => CreateLoadedTcpFlowDetail(Path.Combine(_loadedCaptureDirectory!, "capture.index.sqlite"), Path.Combine(_loadedCaptureDirectory!, "capture.pcapng"), flowId) : null));
        }
    }

    private void LoadKcpConversations(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT conversation_id, endpoint_a, endpoint_b, last_command, last_sequence_number, segment_count, reassembled_message_count, reassembled_byte_count FROM kcp_conversations ORDER BY id;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            _kcpRows.Add(new KcpConversationListItem(
                reader.GetInt64(0).ToString(),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt64(4),
                reader.GetInt64(5),
                reader.GetInt64(6),
                reader.GetInt64(7)));
        }
    }

    private static DateTimeOffset FromUnixMicroseconds(long microseconds) =>
        DateTimeOffset.FromUnixTimeMilliseconds(microseconds / 1_000).AddTicks((microseconds % 1_000) * 10).ToLocalTime();

    private static string FormatEndpoint(string address, long port) =>
        string.IsNullOrEmpty(address) ? "Unknown" : $"{address}:{port}";

    private static List<string> GetHttpBodyFiles(string bodyDirectory, string directionMarker) =>
        Directory.Exists(bodyDirectory)
            ? Directory.EnumerateFiles(bodyDirectory)
                .Where(path => Path.GetFileName(path).Contains(directionMarker, StringComparison.OrdinalIgnoreCase) && !Path.GetFileName(path).Contains("-websocket-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => Path.GetFileName(path), StringComparer.Ordinal)
                .ToList()
            : [];

    private static string CreateLoadedHttpDetail(string detail, long requestBodyLength, string requestContentType, string? requestBodyPath, long responseBodyLength, string responseContentType, string? responseBodyPath)
    {
        var text = new StringBuilder(detail);
        AppendLoadedHttpBody(text, "Request body", requestBodyLength, requestContentType, requestBodyPath);
        AppendLoadedHttpBody(text, "Response body", responseBodyLength, responseContentType, responseBodyPath);
        return text.ToString();
    }

    private static void AppendLoadedHttpBody(StringBuilder detail, string title, long length, string contentType, string? bodyPath)
    {
        detail.AppendLine();
        detail.AppendLine();
        detail.AppendLine($"{title}: {length:N0} bytes{(string.IsNullOrWhiteSpace(contentType) ? string.Empty : $" ({contentType})")}");
        if (length == 0)
        {
            return;
        }

        if (bodyPath is null || !File.Exists(bodyPath))
        {
            detail.AppendLine("Body file was not found.");
            return;
        }

        detail.AppendLine($"Saved: {bodyPath}");
        var data = File.ReadAllBytes(bodyPath);
        if (Path.GetExtension(bodyPath).Equals(".bin", StringComparison.OrdinalIgnoreCase))
        {
            detail.AppendLine(FormatHexDump(data));
            return;
        }

        var content = Encoding.UTF8.GetString(data);
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                content = JsonSerializer.Serialize(JsonDocument.Parse(content), new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                });
            }
            catch (JsonException)
            {
            }
        }

        detail.AppendLine(content);
    }

    private static string CreateLoadedPacketDetail(string detail, string pcapPath, long pcapOffset, int capturedLength)
    {
        try
        {
            var data = ReadPcapPacket(pcapPath, pcapOffset, capturedLength);
            return $"{detail}{Environment.NewLine}{Environment.NewLine}Raw bytes:{Environment.NewLine}{FormatHexDump(data)}";
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or OverflowException)
        {
            return $"{detail}{Environment.NewLine}{Environment.NewLine}Raw bytes could not be read: {exception.Message}";
        }
    }

    private static string CreateLoadedTcpFlowDetail(string indexPath, string pcapPath, long flowId)
    {
        var outbound = new TcpStreamAssembler();
        var inbound = new TcpStreamAssembler();
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = indexPath, Mode = SqliteOpenMode.ReadOnly }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT direction, captured_length, pcap_offset FROM packets WHERE flow_id = $flowId ORDER BY timestamp_unix_microseconds;";
        command.Parameters.AddWithValue("$flowId", flowId);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var packet = ReadPcapPacket(pcapPath, reader.GetInt64(2), checked((int)reader.GetInt64(1)));
            if (!PacketDecoder.TryDecode(packet, out var decoded) || decoded?.TcpSequenceNumber is not { } sequence || decoded.Payload.IsEmpty)
            {
                continue;
            }

            (reader.GetInt64(0) == (long)PacketDirection.Outbound ? outbound : inbound).Append(sequence, decoded.Payload.Span);
        }

        return $"Outbound stream preview:{Environment.NewLine}{FlowSessionListItem.FormatStream(outbound)}{Environment.NewLine}{Environment.NewLine}Inbound stream preview:{Environment.NewLine}{FlowSessionListItem.FormatStream(inbound)}";
    }

    private static byte[] ReadPcapPacket(string pcapPath, long pcapOffset, int capturedLength)
    {
        using var stream = new FileStream(pcapPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        stream.Position = pcapOffset;
        Span<byte> header = stackalloc byte[28];
        stream.ReadExactly(header);
        if (BinaryPrimitives.ReadUInt32LittleEndian(header) != 0x00000006)
        {
            throw new InvalidDataException("The PCAPNG offset does not point to an enhanced packet block.");
        }

        var packetLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(header[20..]));
        if (packetLength != capturedLength)
        {
            throw new InvalidDataException("The indexed packet length does not match the PCAPNG packet length.");
        }

        var data = GC.AllocateUninitializedArray<byte>(packetLength);
        stream.ReadExactly(data);
        return data;
    }

    private static string FormatHexDump(ReadOnlySpan<byte> data)
    {
        var displayedLength = Math.Min(data.Length, 4_096);
        var text = new StringBuilder(displayedLength * 4);
        for (var offset = 0; offset < displayedLength; offset += 16)
        {
            text.Append($"{offset:X4}  ");
            var lineLength = Math.Min(16, displayedLength - offset);
            for (var index = 0; index < 16; index++)
            {
                text.Append(index < lineLength ? $"{data[offset + index]:X2} " : "   ");
            }

            text.Append(" ");
            for (var index = 0; index < lineLength; index++)
            {
                var value = data[offset + index];
                text.Append(value is >= 32 and <= 126 ? (char)value : '.');
            }

            text.AppendLine();
        }

        if (displayedLength < data.Length)
        {
            text.AppendLine($"... {data.Length - displayedLength:N0} bytes omitted from this view");
        }

        return text.ToString();
    }

    protected override async void OnClosed(EventArgs e)
    {
        await StopHttpsMitmAsync();
        if (_captureSession is not null)
        {
            await _captureSession.StopAsync();
        }

        if (_writerTask is not null)
        {
            await _writerTask;
        }

        if (_writer is not null)
        {
            await _writer.DisposeAsync();
        }

        if (_indexWriter is not null)
        {
            await _indexWriter.DisposeAsync();
        }

        if (_harWriter is not null)
        {
            await _harWriter.DisposeAsync();
        }

        if (_sessionWriter is not null)
        {
            await _sessionWriter.DisposeAsync();
        }

        base.OnClosed(e);
    }

    private static string CreateOutputDirectory()
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory,
            "out",
            DateTimeOffset.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private void StartHttpsMitm()
    {
        _rootCertificateAuthority.EnsureInstalled();
        _httpsProxy = new HttpsMitmProxy(_rootCertificateAuthority);
        _decryptedProcessFilters = _filters.Where(filter => filter.Type is CaptureFilterType.ProcessId or CaptureFilterType.ProcessName).ToArray();
        _decryptedPortMatches.Clear();
        _httpsProxy.DecryptedData += data =>
        {
            if (ShouldSaveDecryptedData(data.SourcePort))
            {
                _harWriter?.ObserveDecrypted(data.ConnectionKey, data.IsRequest, data.Data);
            }
        };
        _httpsProxy.Faulted += ApplicationLog.Write;
        _httpsProxy.Start();
        _windowsProxySession = WindowsProxySession.Start(_httpsProxy.Port);
        ApplicationLog.Write($"Windows proxy set to 127.0.0.1:{_httpsProxy.Port}.");
    }

    private async ValueTask StopHttpsMitmAsync()
    {
        if (_windowsProxySession is not null)
        {
            _windowsProxySession.Dispose();
            _windowsProxySession = null;
            ApplicationLog.Write("Windows proxy settings restored.");
        }
        if (_httpsProxy is not null)
        {
            await _httpsProxy.DisposeAsync();
            _httpsProxy = null;
        }

        _decryptedPortMatches.Clear();
        _decryptedProcessFilters = [];
    }

    private bool ShouldSaveDecryptedData(int sourcePort)
    {
        if (_decryptedProcessFilters.Count == 0)
        {
            return true;
        }

        if (_decryptedPortMatches.TryGetValue(sourcePort, out var matches))
        {
            return matches;
        }

        if (_httpsProxy is null || !TcpConnectionOwnerLookup.TryGetProcessId((ushort)sourcePort, (ushort)_httpsProxy.Port, out var processId))
        {
            return false;
        }

        matches = _decryptedProcessFilters.Any(filter =>
            filter.Type == CaptureFilterType.ProcessId && filter.Value == processId.ToString());
        if (!matches)
        {
            try
            {
                using var process = Process.GetProcessById(checked((int)processId));
                matches = _decryptedProcessFilters.Any(filter =>
                    filter.Type == CaptureFilterType.ProcessName && string.Equals(filter.Value, process.ProcessName, StringComparison.OrdinalIgnoreCase));
            }
            catch (ArgumentException)
            {
            }
        }

        _decryptedPortMatches.TryAdd(sourcePort, matches);
        return matches;
    }

    private static async Task WritePacketsAsync(
        CaptureSession captureSession,
        PcapNgWriter writer,
        CaptureIndexWriter indexWriter,
        HttpHarWriter harWriter,
        CaptureSessionJsonWriter sessionWriter,
        ProtocolAnalyzerSession protocolAnalyzer,
        ConcurrentQueue<PacketListItem> pendingPacketRows,
        ConcurrentQueue<FlowUpdate> pendingFlowUpdates)
    {
        await foreach (var packet in captureSession.Packets.ReadAllAsync())
        {
            var offset = await writer.WritePacketAsync(packet);
            await indexWriter.WritePacketAsync(packet, offset);
            harWriter.Observe(packet);
            sessionWriter.Observe(packet);
            pendingPacketRows.Enqueue(PacketListItem.Create(packet, protocolAnalyzer.Analyze(packet.Data)));
            if (packet.Flow is { } flow)
            {
                PacketDecoder.TryDecode(packet.Data, out var decoded);
                pendingFlowUpdates.Enqueue(new FlowUpdate(
                    FlowUpdate.GetKey(flow),
                    flow,
                    packet.Data.Length,
                    packet.Direction,
                    decoded?.TcpSequenceNumber,
                    decoded?.Payload.ToArray() ?? []));
            }
        }
    }

    private void UpdateStatistics()
    {
        var added = 0;
        PacketListItem? lastPacket = null;
        while (added < 500 && _pendingPacketRows.TryDequeue(out var packet))
        {
            if (_packetRows.Count == 10_000)
            {
                _packetRows.RemoveAt(0);
            }

            _packetRows.Add(packet);
            lastPacket = packet;
            added++;
        }

        ScrollToLatest(PacketGrid, lastPacket);

        added = 0;
        HttpSessionListItem? lastHttpSession = null;
        while (added < 500 && _pendingHttpRows.TryDequeue(out var session))
        {
            if (_httpRows.Count == 10_000)
            {
                _httpRows.RemoveAt(0);
            }

            _httpRows.Add(session);
            lastHttpSession = session;
            added++;
        }

        ScrollToLatest(HttpGrid, lastHttpSession);

        added = 0;
        WebSocketListItem? lastWebSocketMessage = null;
        while (added < 500 && _pendingWebSocketRows.TryDequeue(out var message))
        {
            if (_webSocketRows.Count == 10_000)
            {
                _webSocketRows.RemoveAt(0);
            }

            _webSocketRows.Add(message);
            lastWebSocketMessage = message;
            added++;
        }

        ScrollToLatest(WebSocketGrid, lastWebSocketMessage);

        added = 0;
        FlowSessionListItem? lastFlow = null;
        while (added < 1_000 && _pendingFlowUpdates.TryDequeue(out var update))
        {
            if (!_flowRowsByKey.TryGetValue(update.Key, out var flow))
            {
                flow = new FlowSessionListItem(update.Flow);
                _flowRowsByKey.Add(update.Key, flow);
                _flowRows.Add(flow);
            }

            flow.AddPacket(update);
            lastFlow = flow;
            added++;
        }

        ScrollToLatest(FlowGrid, lastFlow);

        added = 0;
        KcpConversationListItem? lastKcpConversation = null;
        while (added < 1_000 && _pendingKcpUpdates.TryDequeue(out var update))
        {
            var key = $"{update.ConversationId}:{update.EndpointA}:{update.EndpointB}";
            if (!_kcpRowsByKey.TryGetValue(key, out var conversation))
            {
                conversation = new KcpConversationListItem(update);
                _kcpRowsByKey.Add(key, conversation);
                _kcpRows.Add(conversation);
            }

            conversation.Update(update);
            lastKcpConversation = conversation;
            added++;
        }

        ScrollToLatest(KcpGrid, lastKcpConversation);

        if (_captureSession is not null)
        {
            StatusText.Text = $"Capturing {_captureSession.CapturedPacketCount:N0} packets";
        }
    }

    private void ScrollToLatest(DataGrid grid, object? item)
    {
        if (AutoScrollToggleButton.IsChecked == true && item is not null)
        {
            grid.ScrollIntoView(item);
        }
    }

    private void PacketGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (PacketGrid.SelectedItem is PacketListItem item)
        {
            DetailTextBox.Text = item.GetDetail();
        }
    }

    private void HttpGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (HttpGrid.SelectedItem is HttpSessionListItem item)
        {
            DetailTextBox.Text = item.GetDetail();
        }
    }

    private void WebSocketGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (WebSocketGrid.SelectedItem is WebSocketListItem item)
        {
            DetailTextBox.Text = item.Detail;
        }
    }

    private void FlowGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (FlowGrid.SelectedItem is FlowSessionListItem item)
        {
            DetailTextBox.Text = item.GetDetail();
        }
    }

    private void KcpGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (KcpGrid.SelectedItem is KcpConversationListItem item)
        {
            DetailTextBox.Text = item.Detail;
        }
    }
}

public sealed record PacketListItem(
    string Timestamp,
    string Direction,
    string ProcessId,
    string ProcessName,
    string Protocol,
    string Source,
    string Destination,
    int Length,
    string Summary,
    string Detail,
    Func<string>? DetailLoader = null)
{
    public string GetDetail() => DetailLoader?.Invoke() ?? Detail;

    public static PacketListItem Create(CapturedPacket packet, PacketAnalysis analysis)
    {
        var flow = packet.Flow;
        return new PacketListItem(
            packet.Timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
            packet.Direction == PacketDirection.Outbound ? "→" : "←",
            flow?.Process.ProcessId.ToString() ?? "Unknown",
            flow?.Process.ProcessName ?? "Unknown",
            analysis.Protocol,
            analysis.Source,
            analysis.Destination,
            packet.Data.Length,
            analysis.Summary,
            CreateDetail(packet, analysis));
    }

    private static string CreateDetail(CapturedPacket packet, PacketAnalysis analysis)
    {
        var detail = new StringBuilder();
        detail.AppendLine($"Timestamp: {packet.Timestamp:O}");
        detail.AppendLine($"Direction: {packet.Direction}");
        detail.AppendLine($"Interface: {packet.InterfaceIndex}");
        detail.AppendLine($"Process: {packet.Flow?.Process.ProcessName ?? "Unknown"} ({packet.Flow?.Process.ProcessId.ToString() ?? "Unknown"})");
        if (!string.IsNullOrEmpty(packet.Flow?.Process.ImagePath))
        {
            detail.AppendLine($"Image: {packet.Flow.Process.ImagePath}");
        }
        detail.AppendLine($"Protocol: {analysis.Protocol}");
        detail.AppendLine($"Source: {analysis.Source}");
        detail.AppendLine($"Destination: {analysis.Destination}");
        detail.AppendLine($"Length: {packet.Data.Length} bytes");
        if (!string.IsNullOrEmpty(analysis.Summary))
        {
            detail.AppendLine($"Summary: {analysis.Summary}");
        }

        detail.AppendLine();
        detail.AppendLine("Raw bytes:");
        var displayedLength = Math.Min(packet.Data.Length, 4_096);
        for (var offset = 0; offset < displayedLength; offset += 16)
        {
            detail.Append($"{offset:X4}  ");
            var lineLength = Math.Min(16, displayedLength - offset);
            for (var index = 0; index < 16; index++)
            {
                detail.Append(index < lineLength ? $"{packet.Data[offset + index]:X2} " : "   ");
            }

            detail.Append(" ");
            for (var index = 0; index < lineLength; index++)
            {
                var value = packet.Data[offset + index];
                detail.Append(value is >= 32 and <= 126 ? (char)value : '.');
            }

            detail.AppendLine();
        }

        if (displayedLength < packet.Data.Length)
        {
            detail.AppendLine($"... {packet.Data.Length - displayedLength:N0} bytes omitted from this view");
        }

        return detail.ToString();
    }
}

public sealed record ProcessListItem(uint ProcessId, string ProcessName)
{
    public string Display => $"{ProcessName} ({ProcessId})";
}

public sealed record HttpSessionListItem(string Timestamp, string Method, string Status, string Url, string Duration, string Detail, Func<string>? DetailLoader = null)
{
    public string GetDetail() => DetailLoader?.Invoke() ?? Detail;

    public static HttpSessionListItem Create(HttpTransaction transaction)
    {
        var detail = new StringBuilder();
        detail.AppendLine($"Started: {transaction.StartedAt:O}");
        detail.AppendLine($"Completed: {transaction.CompletedAt:O}");
        detail.AppendLine($"Request: {transaction.Method} {transaction.Url} {transaction.HttpVersion}");
        detail.AppendLine($"Response: {transaction.Status} {transaction.StatusText}");
        detail.AppendLine();
        detail.AppendLine("Request headers:");
        detail.AppendLine(transaction.RequestHeaders);
        detail.AppendLine();
        detail.AppendLine("Response headers:");
        detail.AppendLine(transaction.ResponseHeaders);
        AppendBody(detail, "Request body", transaction.RequestBody);
        AppendBody(detail, "Response body", transaction.ResponseBody);
        return new HttpSessionListItem(
            transaction.StartedAt.LocalDateTime.ToString("HH:mm:ss.fff"),
            transaction.Method,
            $"{transaction.Status} {transaction.StatusText}",
            transaction.Url,
            $"{Math.Max(0, (transaction.CompletedAt - transaction.StartedAt).TotalMilliseconds):F0} ms",
            detail.ToString());
    }

    private static void AppendBody(StringBuilder detail, string title, HttpBody body)
    {
        detail.AppendLine();
        detail.AppendLine($"{title}: {body.Data.Length:N0} bytes{(string.IsNullOrWhiteSpace(body.ContentType) ? string.Empty : $" ({body.ContentType})")}");
        if (body.FilePath is not null)
        {
            detail.AppendLine($"Saved: {body.FilePath}");
        }
        if (body.Data.Length == 0)
        {
            return;
        }

        var data = DecodeBody(body, out var decodingError);
        if (decodingError is not null)
        {
            detail.AppendLine(decodingError);
            return;
        }

        if (IsTextContent(body.ContentType))
        {
            var text = Encoding.UTF8.GetString(data);
            if (body.ContentType.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    text = JsonSerializer.Serialize(JsonDocument.Parse(text), new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    });
                }
                catch (JsonException)
                {
                }
            }

            detail.AppendLine(text);
            return;
        }

        var displayedLength = Math.Min(data.Length, 4_096);
        for (var offset = 0; offset < displayedLength; offset += 16)
        {
            detail.Append($"{offset:X4}  ");
            var lineLength = Math.Min(16, displayedLength - offset);
            for (var index = 0; index < lineLength; index++)
            {
                detail.Append($"{data[offset + index]:X2} ");
            }

            detail.AppendLine();
        }

        if (displayedLength < data.Length)
        {
            detail.AppendLine($"... {data.Length - displayedLength:N0} bytes omitted from this view");
        }
    }

    private static byte[] DecodeBody(HttpBody body, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(body.ContentEncoding) || string.Equals(body.ContentEncoding, "identity", StringComparison.OrdinalIgnoreCase))
        {
            return body.Data;
        }

        try
        {
            using var input = new MemoryStream(body.Data, writable: false);
            using Stream decoder = body.ContentEncoding.ToLowerInvariant() switch
            {
                "gzip" => new GZipStream(input, CompressionMode.Decompress),
                "deflate" => new DeflateStream(input, CompressionMode.Decompress),
                "br" => new BrotliStream(input, CompressionMode.Decompress),
                _ => throw new NotSupportedException($"Unsupported Content-Encoding: {body.ContentEncoding}"),
            };
            using var output = new MemoryStream();
            decoder.CopyTo(output);
            return output.ToArray();
        }
        catch (Exception exception) when (exception is InvalidDataException or NotSupportedException)
        {
            error = $"Body decode failed: {exception.Message}";
            return [];
        }
    }

    private static bool IsTextContent(string contentType) =>
        contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase);
}

public sealed record WebSocketListItem(string Timestamp, string Direction, string Type, int Length, string Summary, string Detail)
{
    public static WebSocketListItem Create(WebSocketMessage message)
    {
        var isText = message.Opcode == "Text";
        var summary = isText ? Encoding.UTF8.GetString(message.Data) : message.Opcode;
        if (summary.Length > 1_024)
        {
            summary = summary[..1_024] + "...";
        }

        var detail = new StringBuilder();
        detail.AppendLine($"Timestamp: {message.Timestamp:O}");
        detail.AppendLine($"Direction: {(message.IsRequest ? "Client → Server" : "Server → Client")}");
        detail.AppendLine($"Type: {message.Opcode}");
        detail.AppendLine($"Length: {message.Data.Length:N0} bytes");
        if (message.FilePath is not null)
        {
            detail.AppendLine($"Saved: {message.FilePath}");
        }
        detail.AppendLine();
        if (isText)
        {
            detail.AppendLine(Encoding.UTF8.GetString(message.Data));
        }
        else
        {
            var displayedLength = Math.Min(message.Data.Length, 4_096);
            for (var offset = 0; offset < displayedLength; offset += 16)
            {
                detail.Append($"{offset:X4}  ");
                var lineLength = Math.Min(16, displayedLength - offset);
                for (var index = 0; index < lineLength; index++)
                {
                    detail.Append($"{message.Data[offset + index]:X2} ");
                }

                detail.AppendLine();
            }

            if (displayedLength < message.Data.Length)
            {
                detail.AppendLine($"... {message.Data.Length - displayedLength:N0} bytes omitted from this view");
            }
        }

        return new WebSocketListItem(
            message.Timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
            message.IsRequest ? "Client → Server" : "Server → Client",
            message.Opcode,
            message.Data.Length,
            summary,
            detail.ToString());
    }
}

public sealed record FlowUpdate(string Key, FlowRecord Flow, int Length, PacketDirection Direction, uint? TcpSequenceNumber, byte[] Payload)
{
    public static string GetKey(FlowRecord flow) => $"{flow.Process.ProcessId}:{flow.Process.StartedAt.UtcTicks}:{flow.Key.Protocol}:{flow.Key.LocalAddress}:{flow.Key.LocalPort}:{flow.Key.RemoteAddress}:{flow.Key.RemotePort}";
}

public sealed class FlowSessionListItem : INotifyPropertyChanged
{
    private long _packetCount;
    private long _byteCount;
    private readonly TcpStreamAssembler _inboundStream = new();
    private readonly TcpStreamAssembler _outboundStream = new();
    private readonly Func<string>? _storedStreamDetailLoader;

    public FlowSessionListItem(FlowRecord flow)
    {
        ProcessId = flow.Process.ProcessId.ToString();
        ProcessName = flow.Process.ProcessName;
        Protocol = flow.Key.Protocol == 6 ? "TCP" : "UDP";
        LocalEndpoint = $"{flow.Key.LocalAddress}:{flow.Key.LocalPort}";
        RemoteEndpoint = $"{flow.Key.RemoteAddress}:{flow.Key.RemotePort}";
        Detail = $"Process: {ProcessName} ({ProcessId}){Environment.NewLine}Protocol: {Protocol}{Environment.NewLine}Local: {LocalEndpoint}{Environment.NewLine}Remote: {RemoteEndpoint}";
    }

    public FlowSessionListItem(string processId, string processName, string protocol, string localEndpoint, string remoteEndpoint, long packetCount, long byteCount, Func<string>? storedStreamDetailLoader)
    {
        ProcessId = processId;
        ProcessName = processName;
        Protocol = protocol;
        LocalEndpoint = localEndpoint;
        RemoteEndpoint = remoteEndpoint;
        _packetCount = packetCount;
        _byteCount = byteCount;
        _storedStreamDetailLoader = storedStreamDetailLoader;
        Detail = $"Process: {ProcessName} ({ProcessId}){Environment.NewLine}Protocol: {Protocol}{Environment.NewLine}Local: {LocalEndpoint}{Environment.NewLine}Remote: {RemoteEndpoint}{Environment.NewLine}Packets: {_packetCount:N0}{Environment.NewLine}Bytes: {_byteCount:N0}";
    }

    public string ProcessId { get; }
    public string ProcessName { get; }
    public string Protocol { get; }
    public string LocalEndpoint { get; }
    public string RemoteEndpoint { get; }
    public long PacketCount => _packetCount;
    public long ByteCount => _byteCount;
    public string Detail { get; private set; }
    public event PropertyChangedEventHandler? PropertyChanged;

    public string GetDetail() => _storedStreamDetailLoader is null ? Detail : $"{Detail}{Environment.NewLine}{Environment.NewLine}{_storedStreamDetailLoader()}";

    public void AddPacket(FlowUpdate update)
    {
        _packetCount++;
        _byteCount += update.Length;
        if (Protocol == "TCP" && update.TcpSequenceNumber is { } sequence && update.Payload.Length > 0)
        {
            var stream = update.Direction == PacketDirection.Outbound ? _outboundStream : _inboundStream;
            stream.Append(sequence, update.Payload);
        }

        Detail = $"Process: {ProcessName} ({ProcessId}){Environment.NewLine}Protocol: {Protocol}{Environment.NewLine}Local: {LocalEndpoint}{Environment.NewLine}Remote: {RemoteEndpoint}{Environment.NewLine}Packets: {_packetCount:N0}{Environment.NewLine}Bytes: {_byteCount:N0}{CreateTcpStreamDetail()}";
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(PacketCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ByteCount)));
    }

    private string CreateTcpStreamDetail()
    {
        if (Protocol != "TCP")
        {
            return string.Empty;
        }

        return $"{Environment.NewLine}{Environment.NewLine}Outbound stream preview:{Environment.NewLine}{FormatStream(_outboundStream)}{Environment.NewLine}{Environment.NewLine}Inbound stream preview:{Environment.NewLine}{FormatStream(_inboundStream)}";
    }

    internal static string FormatStream(TcpStreamAssembler stream)
    {
        var data = stream.Contiguous;
        var preview = data.Span[..Math.Min(data.Length, 16_384)];
        var text = new StringBuilder(preview.Length + 4_096);
        text.AppendLine($"Retransmissions: {stream.RetransmissionCount:N0}");
        text.AppendLine($"Out of order: {stream.OutOfOrderCount:N0}");
        text.AppendLine($"Missing bytes: {stream.MissingByteCount:N0}");
        text.AppendLine();
        text.AppendLine("Text preview:");
        foreach (var value in preview)
        {
            text.Append(value is >= 32 and <= 126 or 10 or 13 or 9 ? (char)value : '.');
        }

        if (data.Length > preview.Length)
        {
            text.AppendLine();
            text.Append($"... {data.Length - preview.Length:N0} bytes omitted");
        }

        text.AppendLine();
        text.AppendLine();
        text.AppendLine("Hex:");
        var hexLength = Math.Min(data.Length, 4_096);
        for (var offset = 0; offset < hexLength; offset += 16)
        {
            text.Append($"{offset:X4}  ");
            var lineLength = Math.Min(16, hexLength - offset);
            for (var index = 0; index < 16; index++)
            {
                text.Append(index < lineLength ? $"{data.Span[offset + index]:X2} " : "   ");
            }

            text.Append(" ");
            for (var index = 0; index < lineLength; index++)
            {
                var value = data.Span[offset + index];
                text.Append(value is >= 32 and <= 126 ? (char)value : '.');
            }

            text.AppendLine();
        }

        if (hexLength < data.Length)
        {
            text.AppendLine($"... {data.Length - hexLength:N0} bytes omitted from the hex view");
        }

        return text.ToString();
    }
}

public sealed class KcpConversationListItem : INotifyPropertyChanged
{
    public KcpConversationListItem(KcpConversationUpdate update)
    {
        ConversationId = update.ConversationId.ToString();
        EndpointA = update.EndpointA;
        EndpointB = update.EndpointB;
        Update(update);
    }

    public KcpConversationListItem(string conversationId, string endpointA, string endpointB, string lastCommand, long lastSequenceNumber, long segmentCount, long messageCount, long messageBytes)
    {
        ConversationId = conversationId;
        EndpointA = endpointA;
        EndpointB = endpointB;
        SegmentCount = segmentCount;
        MessageCount = messageCount;
        MessageBytes = messageBytes;
        Detail = $"conv: {ConversationId}{Environment.NewLine}Endpoint A: {EndpointA}{Environment.NewLine}Endpoint B: {EndpointB}{Environment.NewLine}Last command: {lastCommand}{Environment.NewLine}Last sequence number: {lastSequenceNumber}{Environment.NewLine}Segments: {SegmentCount:N0}{Environment.NewLine}Reassembled messages: {MessageCount:N0}{Environment.NewLine}Reassembled bytes: {MessageBytes:N0}";
    }

    public string ConversationId { get; }
    public string EndpointA { get; }
    public string EndpointB { get; }
    public long SegmentCount { get; private set; }
    public long MessageCount { get; private set; }
    public long MessageBytes { get; private set; }
    public string Detail { get; private set; } = string.Empty;
    public event PropertyChangedEventHandler? PropertyChanged;

    public void Update(KcpConversationUpdate update)
    {
        SegmentCount = update.SegmentCount;
        MessageCount = update.ReassembledMessageCount;
        MessageBytes = update.ReassembledByteCount;
        Detail = $"conv: {ConversationId}{Environment.NewLine}Endpoint A: {EndpointA}{Environment.NewLine}Endpoint B: {EndpointB}{Environment.NewLine}Last command: {update.LastCommand}{Environment.NewLine}Last sequence number: {update.LastSequenceNumber}{Environment.NewLine}Segments: {SegmentCount:N0}{Environment.NewLine}Reassembled messages: {MessageCount:N0}{Environment.NewLine}Reassembled bytes: {MessageBytes:N0}";
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SegmentCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(MessageCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(MessageBytes)));
    }
}
