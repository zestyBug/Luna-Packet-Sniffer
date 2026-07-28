using LunaPacketSniffer.Core;

namespace LunaPacketSniffer.Capture;

public enum CaptureFilterType
{
    ProcessId,
    ProcessName,
    ProcessPath,
    Protocol,
}

public sealed record CaptureFilter(CaptureFilterType Type, string Value)
{
    public static CaptureFilter Create(CaptureFilterType type, string value) => type switch
    {
        CaptureFilterType.ProcessId when uint.TryParse(value, out var processId) => new(type, processId.ToString()),
        CaptureFilterType.ProcessName when !string.IsNullOrWhiteSpace(value) => new(type, Path.GetFileNameWithoutExtension(value)),
        CaptureFilterType.ProcessPath when Path.IsPathFullyQualified(value) => new(type, Path.GetFullPath(value)),
        CaptureFilterType.Protocol when string.Equals(value, "TCP", StringComparison.OrdinalIgnoreCase) => new(type, "TCP"),
        CaptureFilterType.Protocol when string.Equals(value, "UDP", StringComparison.OrdinalIgnoreCase) => new(type, "UDP"),
        CaptureFilterType.Protocol when string.Equals(value, "HTTP", StringComparison.OrdinalIgnoreCase) => new(type, "HTTP"),
        _ => throw new ArgumentException("Invalid filter value.", nameof(value)),
    };

    public bool Matches(CapturedPacket packet)
    {
        return Type switch
        {
            CaptureFilterType.ProcessId => packet.Flow?.Process.ProcessId.ToString() == Value,
            CaptureFilterType.ProcessName => string.Equals(packet.Flow?.Process.ProcessName, Value, StringComparison.OrdinalIgnoreCase),
            CaptureFilterType.ProcessPath => string.Equals(packet.Flow?.Process.ImagePath, Value, StringComparison.OrdinalIgnoreCase),
            CaptureFilterType.Protocol => TryGetProtocol(packet.Data, out var protocol) && Value == protocol,
            _ => false,
        };
    }

    public override string ToString() => $"{Type}: {Value}";

    private static bool TryGetProtocol(byte[] packet, out string protocol)
    {
        protocol = string.Empty;
        if (packet.Length < 20)
        {
            return false;
        }

        var version = packet[0] >> 4;
        var (protocolNumber, transportOffset) = version switch
        {
            4 => (packet[9], (packet[0] & 0x0F) * 4),
            6 when packet.Length >= 40 => (packet[6], 40),
            _ => (0, 0),
        };

        if (protocolNumber == 6 && transportOffset > 0 && packet.Length >= transportOffset + 4)
        {
            var sourcePort = (packet[transportOffset] << 8) | packet[transportOffset + 1];
            var destinationPort = (packet[transportOffset + 2] << 8) | packet[transportOffset + 3];
            if (sourcePort is 80 or 443 || destinationPort is 80 or 443)
            {
                protocol = "HTTP";
                return true;
            }
        }

        protocol = protocolNumber switch
        {
            6 => "TCP",
            17 => "UDP",
            _ => string.Empty,
        };
        return protocol.Length > 0;
    }
}
