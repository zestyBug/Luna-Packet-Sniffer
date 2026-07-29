using System.IO;
using System.Runtime.ExceptionServices;
using LunaPacketSniffer.App.ViewModels;
using LunaPacketSniffer.Capture;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Networking;
using LunaPacketSniffer.Persistence;
using LunaPacketSniffer.Protocols;

namespace LunaPacketSniffer.App.Recording;

/// <summary>
/// Owns one capture run: the output writers, the WinDivert session, and the pump task that moves
/// packets from the capture channel into the writers. Observers are raised on the pump thread, so
/// the UI must marshal them itself.
/// </summary>
internal sealed class CaptureRunner : IAsyncDisposable
{
    private readonly CaptureSession _captureSession = new();
    private readonly PcapNgWriter _writer;
    private readonly CaptureIndexWriter _indexWriter;
    private readonly CaptureSessionJsonWriter _sessionWriter;
    private readonly ProtocolAnalyzerSession _protocolAnalyzer = new();
    private Task? _pumpTask;
    private bool _stopped;

    private CaptureRunner(
        string outputDirectory,
        PcapNgWriter writer,
        CaptureIndexWriter indexWriter,
        HttpHarWriter harWriter,
        CaptureSessionJsonWriter sessionWriter,
        IEnumerable<CaptureFilter> filters)
    {
        OutputDirectory = outputDirectory;
        _writer = writer;
        _indexWriter = indexWriter;
        HarWriter = harWriter;
        _sessionWriter = sessionWriter;

        HarWriter.TransactionObserved += transaction =>
        {
            HttpTransactionObserved?.Invoke(transaction);
            _indexWriter.WriteHttpTransaction(transaction);
        };
        HarWriter.WebSocketMessageObserved += message =>
        {
            WebSocketMessageObserved?.Invoke(message);
            _indexWriter.WriteWebSocketMessage(message);
        };
        _protocolAnalyzer.KcpConversationObserved += update =>
        {
            KcpConversationObserved?.Invoke(update);
            _indexWriter.WriteKcpConversation(update);
        };

        foreach (var filter in filters)
        {
            _captureSession.Filters.Add(filter);
        }
    }

    public string OutputDirectory { get; }

    /// <summary>Exposed so the HTTPS proxy can feed decrypted traffic into the same HAR writer.</summary>
    public HttpHarWriter HarWriter { get; }

    public long CapturedPacketCount => _captureSession.CapturedPacketCount;

    public event Action<PacketListItem>? PacketObserved;
    public event Action<FlowUpdate>? FlowObserved;
    public event Action<HttpTransaction>? HttpTransactionObserved;
    public event Action<WebSocketMessage>? WebSocketMessageObserved;
    public event Action<KcpConversationUpdate>? KcpConversationObserved;

    /// <summary>
    /// Creates the output files for a capture folder. If any writer fails to open, the ones already
    /// created are disposed before the exception propagates.
    /// </summary>
    public static async ValueTask<CaptureRunner> CreateAsync(string outputDirectory, IEnumerable<CaptureFilter> filters)
    {
        PcapNgWriter? writer = null;
        CaptureIndexWriter? indexWriter = null;
        HttpHarWriter? harWriter = null;
        CaptureSessionJsonWriter? sessionWriter = null;
        try
        {
            writer = new PcapNgWriter(Path.Combine(outputDirectory, CaptureOutput.PcapFileName));
            indexWriter = new CaptureIndexWriter(Path.Combine(outputDirectory, CaptureOutput.IndexFileName));
            harWriter = new HttpHarWriter(Path.Combine(outputDirectory, CaptureOutput.HarFileName));
            sessionWriter = new CaptureSessionJsonWriter(Path.Combine(outputDirectory, CaptureOutput.SessionsFileName));
            return new CaptureRunner(outputDirectory, writer, indexWriter, harWriter, sessionWriter, filters);
        }
        catch
        {
            await DisposeIfNotNullAsync(writer);
            await DisposeIfNotNullAsync(indexWriter);
            await DisposeIfNotNullAsync(harWriter);
            await DisposeIfNotNullAsync(sessionWriter);
            throw;
        }
    }

    /// <summary>Opens WinDivert and begins pumping packets into the writers.</summary>
    public void Start()
    {
        _captureSession.Start();
        _pumpTask = PumpAsync();
    }

    /// <summary>Stops the capture, drains the pump, and closes every output file. Safe to call twice.</summary>
    public async ValueTask StopAsync()
    {
        if (_stopped)
        {
            return;
        }

        _stopped = true;
        Exception? captureFailure = null;
        try
        {
            await _captureSession.StopAsync();
            if (_pumpTask is not null)
            {
                await _pumpTask;
            }
        }
        catch (Exception exception)
        {
            captureFailure = exception;
        }

        var disposeFailure = await DisposeOutputsAsync();
        if (captureFailure is not null)
        {
            ExceptionDispatchInfo.Capture(captureFailure).Throw();
        }

        if (disposeFailure is not null)
        {
            ExceptionDispatchInfo.Capture(disposeFailure).Throw();
        }
    }

    public ValueTask DisposeAsync() => StopAsync();

    private async Task PumpAsync()
    {
        await foreach (var packet in _captureSession.Packets.ReadAllAsync())
        {
            // Decode once and share the result with every consumer on this path.
            PacketDecoder.TryDecode(packet.Data, out var decoded);
            var offset = await _writer.WritePacketAsync(packet);
            await _indexWriter.WritePacketAsync(packet, offset);
            HarWriter.Observe(packet, decoded);
            _sessionWriter.Observe(packet);
            PacketObserved?.Invoke(PacketListItem.Create(packet, _protocolAnalyzer.Analyze(packet.Data, decoded)));
            if (packet.Flow is { } flow)
            {
                FlowObserved?.Invoke(new FlowUpdate(
                    FlowUpdate.GetKey(flow),
                    flow,
                    packet.Data.Length,
                    packet.Direction,
                    decoded?.TcpSequenceNumber,
                    decoded?.Payload.ToArray() ?? []));
            }
        }
    }

    private async ValueTask<Exception?> DisposeOutputsAsync()
    {
        List<Exception>? failures = null;
        foreach (var output in new IAsyncDisposable[] { _writer, _indexWriter, HarWriter, _sessionWriter })
        {
            try
            {
                await output.DisposeAsync();
            }
            catch (Exception exception)
            {
                (failures ??= []).Add(exception);
            }
        }

        return failures switch
        {
            null => null,
            [var failure] => failure,
            _ => new AggregateException(failures),
        };
    }

    private static ValueTask DisposeIfNotNullAsync(IAsyncDisposable? disposable) =>
        disposable?.DisposeAsync() ?? ValueTask.CompletedTask;
}
