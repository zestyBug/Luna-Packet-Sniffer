using System.Threading.Channels;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.NativeInterop;

namespace LunaPacketSniffer.Capture;

public sealed class CaptureSession : IAsyncDisposable
{
    private static readonly uint CurrentProcessId = checked((uint)Environment.ProcessId);
    private readonly Channel<CapturedPacket> _packets = Channel.CreateBounded<CapturedPacket>(
        new BoundedChannelOptions(16_384)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true,
        });

    private NativeCaptureSession? _nativeSession;
    private readonly FlowTable _flowTable = new();
    private long _capturedPacketCount;
    public IList<CaptureFilter> Filters { get; } = new List<CaptureFilter>();

    public ChannelReader<CapturedPacket> Packets => _packets.Reader;

    public long CapturedPacketCount => Interlocked.Read(ref _capturedPacketCount);

    public void Start(string filter = "true")
    {
        if (_nativeSession is not null)
        {
            throw new InvalidOperationException("Capture is already running.");
        }

        _flowTable.SeedExistingSockets();
        _nativeSession = new NativeCaptureSession(WritePacket, _flowTable.Apply);
        _nativeSession.Start(filter);
    }

    public async ValueTask StopAsync()
    {
        var nativeSession = Interlocked.Exchange(ref _nativeSession, null);
        nativeSession?.Dispose();
        _packets.Writer.TryComplete();
        await Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => StopAsync();

    private void WritePacket(CapturedPacket packet)
    {
        var packetWithFlow = packet with { Flow = _flowTable.Find(packet.Data) };
        if (packetWithFlow.Flow?.Process.ProcessId == CurrentProcessId)
        {
            return;
        }

        if (Filters.GroupBy(filter => filter.Type).Any(group => !group.Any(filter => filter.Matches(packetWithFlow))))
        {
            return;
        }

        _packets.Writer.WriteAsync(packetWithFlow).AsTask().GetAwaiter().GetResult();
        Interlocked.Increment(ref _capturedPacketCount);
    }

}
