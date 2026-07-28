using System.Net;

namespace LunaPacketSniffer.Core;

public readonly record struct ProcessIdentity(uint ProcessId, DateTimeOffset StartedAt, string ProcessName, string ImagePath);

public readonly record struct FlowKey(
    byte Protocol,
    IPAddress LocalAddress,
    ushort LocalPort,
    IPAddress RemoteAddress,
    ushort RemotePort)
{
    public FlowKey Reverse() => new(Protocol, RemoteAddress, RemotePort, LocalAddress, LocalPort);
}

public sealed record FlowRecord(
    ProcessIdentity Process,
    FlowKey Key,
    DateTimeOffset CreatedAt);
