namespace LunaPacketSniffer.Networking;

/// <summary>IANA IP protocol numbers used across the capture and analysis layers.</summary>
public static class IpProtocol
{
    public const byte Icmp = 1;
    public const byte Tcp = 6;
    public const byte Udp = 17;
    public const byte IcmpV6 = 58;

    public static string GetName(long protocolNumber) => protocolNumber switch
    {
        Tcp => "TCP",
        Udp => "UDP",
        _ => "Unknown",
    };
}
