using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.NativeInterop;

namespace LunaPacketSniffer.Capture;

internal sealed class FlowTable
{
    private const byte FlowEstablished = 1;
    private const byte FlowDeleted = 2;
    private readonly ConcurrentDictionary<FlowKey, FlowRecord> _flows = new();
    private readonly ConcurrentDictionary<UdpSocketKey, ProcessIdentity> _udpSockets = new();
    private readonly ConcurrentDictionary<uint, ProcessIdentity> _processes = new();

    public void Apply(NativeFlowEvent flowEvent)
    {
        var key = new FlowKey(
            flowEvent.Protocol,
            flowEvent.LocalAddress,
            flowEvent.LocalPort,
            flowEvent.RemoteAddress,
            flowEvent.RemotePort);

        if (flowEvent.EventType == FlowEstablished)
        {
            Add(key, flowEvent.ProcessId);
        }
        else if (flowEvent.EventType == FlowDeleted)
        {
            _flows.TryRemove(key, out _);
        }
    }

    public void SeedExistingSockets()
    {
        foreach (var owner in WindowsSocketTable.GetOwners())
        {
            if (owner.Protocol == 6)
            {
                Add(new FlowKey(owner.Protocol, owner.LocalAddress, owner.LocalPort, owner.RemoteAddress!, owner.RemotePort!.Value), owner.ProcessId);
            }
            else
            {
                AddUdpSocket(owner.LocalAddress, owner.LocalPort, owner.ProcessId);
            }
        }
    }

    public FlowRecord? Find(byte[] packet)
    {
        if (!TryParse(packet, out var packetKey))
        {
            return null;
        }

        var flow = _flows.GetValueOrDefault(packetKey) ?? _flows.GetValueOrDefault(packetKey.Reverse());
        if (flow is not null || packetKey.Protocol != 17)
        {
            return flow;
        }

        return FindUdpOwner(packetKey, packetKey.LocalAddress, packetKey.LocalPort) ??
               FindUdpOwner(packetKey, packetKey.RemoteAddress, packetKey.RemotePort);
    }

    private void Add(FlowKey key, uint processId)
    {
        if (!TryCreateProcessIdentity(processId, out var process))
        {
            return;
        }

        process = _processes.AddOrUpdate(processId, process, (_, existing) => existing.StartedAt == process.StartedAt ? existing : process);
        _flows[key] = new FlowRecord(process, key, DateTimeOffset.UtcNow);
        if (key.Protocol == 17)
        {
            _udpSockets[new UdpSocketKey(key.LocalAddress, key.LocalPort)] = process;
        }
    }

    private void AddUdpSocket(IPAddress address, ushort port, uint processId)
    {
        if (!TryCreateProcessIdentity(processId, out var process))
        {
            return;
        }

        process = _processes.AddOrUpdate(processId, process, (_, existing) => existing.StartedAt == process.StartedAt ? existing : process);
        _udpSockets[new UdpSocketKey(address, port)] = process;
    }

    private FlowRecord? FindUdpOwner(FlowKey packetKey, IPAddress address, ushort port) =>
        _udpSockets.TryGetValue(new UdpSocketKey(address, port), out var process)
            ? new FlowRecord(process, packetKey, DateTimeOffset.UtcNow)
            : null;

    private static bool TryCreateProcessIdentity(uint processId, out ProcessIdentity processIdentity)
    {
        try
        {
            using var process = Process.GetProcessById(checked((int)processId));
            processIdentity = new ProcessIdentity(
                processId,
                new DateTimeOffset(process.StartTime.ToUniversalTime()),
                process.ProcessName,
                TryGetImagePath(process));
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or Win32Exception)
        {
            processIdentity = default;
            return false;
        }
    }

    private static string TryGetImagePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName ?? string.Empty;
        }
        catch (Win32Exception)
        {
            return string.Empty;
        }
    }

    private static bool TryParse(byte[] packet, out FlowKey key)
    {
        key = default;
        if (packet.Length < 20)
        {
            return false;
        }

        var version = packet[0] >> 4;
        if (version == 4)
        {
            var headerLength = (packet[0] & 0x0F) * 4;
            if (headerLength < 20 || packet.Length < headerLength + 4)
            {
                return false;
            }

            var protocol = packet[9];
            if (protocol is not 6 and not 17)
            {
                return false;
            }

            key = new FlowKey(
                protocol,
                new IPAddress(packet.AsSpan(12, 4)),
                ReadPort(packet, headerLength),
                new IPAddress(packet.AsSpan(16, 4)),
                ReadPort(packet, headerLength + 2));
            return true;
        }

        if (version == 6 && packet.Length >= 44 && packet[6] is 6 or 17)
        {
            key = new FlowKey(
                packet[6],
                new IPAddress(packet.AsSpan(8, 16)),
                ReadPort(packet, 40),
                new IPAddress(packet.AsSpan(24, 16)),
                ReadPort(packet, 42));
            return true;
        }

        return false;
    }

    private static ushort ReadPort(byte[] packet, int offset) =>
        (ushort)((packet[offset] << 8) | packet[offset + 1]);

    private readonly record struct UdpSocketKey(IPAddress Address, ushort Port);
}
