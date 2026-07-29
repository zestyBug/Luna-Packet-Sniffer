using System.Buffers.Binary;
using System.IO;

namespace LunaPacketSniffer.App.Loading;

/// <summary>
/// Reads a single packet back out of a capture.pcapng using the offset stored in the SQLite index.
/// </summary>
internal static class PcapPacketReader
{
    private const uint EnhancedPacketBlockType = 0x00000006;
    private const int EnhancedPacketBlockHeaderLength = 28;
    private const int CapturedLengthOffset = 20;

    public static byte[] ReadPacket(string pcapPath, long pcapOffset, int capturedLength)
    {
        using var stream = new FileStream(pcapPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        stream.Position = pcapOffset;
        Span<byte> header = stackalloc byte[EnhancedPacketBlockHeaderLength];
        stream.ReadExactly(header);
        if (BinaryPrimitives.ReadUInt32LittleEndian(header) != EnhancedPacketBlockType)
        {
            throw new InvalidDataException("The PCAPNG offset does not point to an enhanced packet block.");
        }

        var packetLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(header[CapturedLengthOffset..]));
        if (packetLength != capturedLength)
        {
            throw new InvalidDataException("The indexed packet length does not match the PCAPNG packet length.");
        }

        var data = GC.AllocateUninitializedArray<byte>(packetLength);
        stream.ReadExactly(data);
        return data;
    }
}
