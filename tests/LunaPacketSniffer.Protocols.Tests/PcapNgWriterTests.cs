using System.Buffers.Binary;
using LunaPacketSniffer.Core;
using LunaPacketSniffer.Persistence;
using Xunit;

namespace LunaPacketSniffer.Protocols.Tests;

public sealed class PcapNgWriterTests
{
    [Fact]
    public async Task WritesValidSectionInterfaceAndPacketBlocks()
    {
        var directory = Path.Combine(Path.GetTempPath(), "LunaPacketSniffer.Tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "capture.pcapng");
        try
        {
            Directory.CreateDirectory(directory);
            await using (var writer = new PcapNgWriter(path))
            {
                var offset = await writer.WritePacketAsync(new CapturedPacket(DateTimeOffset.UtcNow, PacketDirection.Outbound, 1, [0x45, 0x00, 0x00]));
                Assert.Equal(48, offset);
            }

            var bytes = await File.ReadAllBytesAsync(path);
            Assert.Equal(84, bytes.Length);
            Assert.Equal(0x0A0D0D0Au, ReadUInt32(bytes, 0));
            Assert.Equal(28u, ReadUInt32(bytes, 4));
            Assert.Equal(1u, ReadUInt32(bytes, 28));
            Assert.Equal(20u, ReadUInt32(bytes, 32));
            Assert.Equal(6u, ReadUInt32(bytes, 48));
            Assert.Equal(36u, ReadUInt32(bytes, 52));
            Assert.Equal(3u, ReadUInt32(bytes, 68));
            Assert.Equal(36u, ReadUInt32(bytes, 80));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private static uint ReadUInt32(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
}
