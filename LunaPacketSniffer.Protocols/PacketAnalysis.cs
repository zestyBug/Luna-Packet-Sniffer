namespace LunaPacketSniffer.Protocols;

/// <summary>The one-line classification of a packet shown in the Packets grid.</summary>
public sealed record PacketAnalysis(string Protocol, string Summary, string Source, string Destination);
