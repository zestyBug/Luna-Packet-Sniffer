namespace LunaPacketSniffer.Core;

public enum PacketDirection : byte
{
    Inbound,
    Outbound,
}

public sealed record CapturedPacket(
    DateTimeOffset Timestamp,
    PacketDirection Direction,
    uint InterfaceIndex,
    byte[] Data,
    FlowRecord? Flow = null);
