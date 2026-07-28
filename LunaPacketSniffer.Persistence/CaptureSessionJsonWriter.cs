using System.Text.Json;
using LunaPacketSniffer.Core;

namespace LunaPacketSniffer.Persistence;

public sealed class CaptureSessionJsonWriter : IAsyncDisposable
{
    private readonly string _path;
    private readonly Dictionary<SessionKey, SessionAccumulator> _sessions = [];
    private bool _disposed;

    public CaptureSessionJsonWriter(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    }

    public void Observe(CapturedPacket packet)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (packet.Flow is not { } flow)
        {
            return;
        }

        var key = new SessionKey(flow.Process, flow.Key);
        if (!_sessions.TryGetValue(key, out var session))
        {
            session = new SessionAccumulator(flow, packet.Timestamp);
            _sessions.Add(key, session);
        }

        session.Add(packet);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        var sessions = _sessions.Values.Select(session => session.ToRecord()).ToArray();
        await using var stream = new FileStream(_path, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
        await JsonSerializer.SerializeAsync(stream, sessions, new JsonSerializerOptions { WriteIndented = true });
        _disposed = true;
    }

    private readonly record struct SessionKey(ProcessIdentity Process, FlowKey Flow);

    private sealed class SessionAccumulator
    {
        private readonly FlowRecord _flow;
        private readonly DateTimeOffset _startedAt;
        private DateTimeOffset _lastPacketAt;
        private long _packetCount;
        private long _byteCount;

        public SessionAccumulator(FlowRecord flow, DateTimeOffset startedAt)
        {
            _flow = flow;
            _startedAt = startedAt;
            _lastPacketAt = startedAt;
        }

        public void Add(CapturedPacket packet)
        {
            _lastPacketAt = packet.Timestamp;
            _packetCount++;
            _byteCount += packet.Data.Length;
        }

        public SessionRecord ToRecord() => new(
            _flow.Process.ProcessId,
            _flow.Process.StartedAt,
            _flow.Process.ProcessName,
            _flow.Process.ImagePath,
            _flow.Key.Protocol == 6 ? "TCP" : "UDP",
            $"{_flow.Key.LocalAddress}:{_flow.Key.LocalPort}",
            $"{_flow.Key.RemoteAddress}:{_flow.Key.RemotePort}",
            _startedAt,
            _lastPacketAt,
            _packetCount,
            _byteCount);
    }

    private sealed record SessionRecord(
        uint ProcessId,
        DateTimeOffset ProcessStartedAt,
        string ProcessName,
        string ImagePath,
        string Protocol,
        string LocalEndpoint,
        string RemoteEndpoint,
        DateTimeOffset StartedAt,
        DateTimeOffset LastPacketAt,
        long PacketCount,
        long ByteCount);
}
