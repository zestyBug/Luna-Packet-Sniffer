using LunaPacketSniffer.Core;

namespace LunaPacketSniffer.App.ViewModels;

/// <summary>A single packet's contribution to a flow row, handed from the capture thread to the UI thread.</summary>
public sealed record FlowUpdate(
    string Key,
    FlowRecord Flow,
    int Length,
    PacketDirection Direction,
    uint? TcpSequenceNumber,
    byte[] Payload)
{
    public static string GetKey(FlowRecord flow) =>
        $"{flow.Process.ProcessId}:{flow.Process.StartedAt.UtcTicks}:{flow.Key.Protocol}:{flow.Key.LocalAddress}:{flow.Key.LocalPort}:{flow.Key.RemoteAddress}:{flow.Key.RemotePort}";
}
