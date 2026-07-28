using System.Buffers.Binary;
using LunaPacketSniffer.Core;

namespace LunaPacketSniffer.Persistence;

public sealed class PcapNgWriter : IAsyncDisposable
{
    private const uint SectionHeaderBlock = 0x0A0D0D0A;
    private const uint InterfaceDescriptionBlock = 0x00000001;
    private const uint EnhancedPacketBlock = 0x00000006;
    private const ushort LinkTypeRaw = 101;

    private readonly FileStream _stream;
    private bool _disposed;

    public PcapNgWriter(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        _stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1_048_576, FileOptions.Asynchronous);
        WriteInitialBlocks();
    }

    public async ValueTask<long> WritePacketAsync(CapturedPacket packet, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var offset = _stream.Position;
        var paddedLength = (packet.Data.Length + 3) & ~3;
        var blockLength = checked(32 + paddedLength);
        var buffer = GC.AllocateUninitializedArray<byte>(blockLength);
        var timestampMicroseconds = (packet.Timestamp.UtcDateTime.Ticks - DateTime.UnixEpoch.Ticks) / 10;

        WriteUInt32(buffer, 0, EnhancedPacketBlock);
        WriteUInt32(buffer, 4, (uint)blockLength);
        WriteUInt32(buffer, 8, 0);
        WriteUInt32(buffer, 12, (uint)(timestampMicroseconds >> 32));
        WriteUInt32(buffer, 16, (uint)timestampMicroseconds);
        WriteUInt32(buffer, 20, (uint)packet.Data.Length);
        WriteUInt32(buffer, 24, (uint)packet.Data.Length);
        packet.Data.CopyTo(buffer, 28);
        WriteUInt32(buffer, blockLength - 4, (uint)blockLength);

        await _stream.WriteAsync(buffer, cancellationToken);
        return offset;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _stream.FlushAsync();
        await _stream.DisposeAsync();
        _disposed = true;
    }

    private void WriteInitialBlocks()
    {
        Span<byte> sectionHeader = stackalloc byte[28];
        WriteUInt32(sectionHeader, 0, SectionHeaderBlock);
        WriteUInt32(sectionHeader, 4, 28);
        WriteUInt32(sectionHeader, 8, 0x1A2B3C4D);
        BinaryPrimitives.WriteUInt16LittleEndian(sectionHeader[12..], 1);
        BinaryPrimitives.WriteUInt16LittleEndian(sectionHeader[14..], 0);
        BinaryPrimitives.WriteInt64LittleEndian(sectionHeader[16..], -1);
        WriteUInt32(sectionHeader, 24, 28);
        _stream.Write(sectionHeader);

        Span<byte> interfaceDescription = stackalloc byte[20];
        WriteUInt32(interfaceDescription, 0, InterfaceDescriptionBlock);
        WriteUInt32(interfaceDescription, 4, 20);
        BinaryPrimitives.WriteUInt16LittleEndian(interfaceDescription[8..], LinkTypeRaw);
        WriteUInt32(interfaceDescription, 12, 65_535);
        WriteUInt32(interfaceDescription, 16, 20);
        _stream.Write(interfaceDescription);
    }

    private static void WriteUInt32(Span<byte> buffer, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(buffer[offset..], value);
}
