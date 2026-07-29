using System.Buffers.Binary;
using System.Text;

namespace LunaPacketSniffer.Protocols;

/// <summary>
/// Reads the SNI host name out of a TLS ClientHello, which is the only part of a TLS session that
/// stays readable without decryption.
/// </summary>
internal static class TlsParser
{
    private const byte HandshakeRecordType = 22;
    private const byte ClientHelloMessageType = 1;
    private const int ServerNameExtensionType = 0;

    public static bool TryGetServerName(ReadOnlySpan<byte> payload, out string serverName)
    {
        serverName = string.Empty;
        if (payload.Length < 9 || payload[0] != HandshakeRecordType || payload[5] != ClientHelloMessageType)
        {
            return false;
        }

        var recordLength = ReadUInt16BigEndian(payload, 3);
        var handshakeLength = ReadUInt24BigEndian(payload, 6);
        if (payload.Length < 5 + recordLength || handshakeLength + 4 > recordLength)
        {
            return false;
        }

        // Skip the handshake header, the protocol version, and the 32-byte client random.
        var offset = 9 + 2 + 32;
        if (offset >= payload.Length)
        {
            return false;
        }

        var sessionIdLength = payload[offset++];
        offset += sessionIdLength;
        if (!TryReadLengthPrefixedSection(payload, ref offset, 2, out _) ||          // cipher suites
            !TryReadLengthPrefixedSection(payload, ref offset, 1, out _) ||          // compression methods
            !TryReadLengthPrefixedSection(payload, ref offset, 2, out var extensions))
        {
            return false;
        }

        var extensionOffset = 0;
        while (extensionOffset + 4 <= extensions.Length)
        {
            var extensionType = ReadUInt16BigEndian(extensions, extensionOffset);
            var extensionLength = ReadUInt16BigEndian(extensions, extensionOffset + 2);
            extensionOffset += 4;
            if (extensionOffset + extensionLength > extensions.Length)
            {
                return false;
            }

            if (extensionType == ServerNameExtensionType &&
                TryGetServerNameExtension(extensions.Slice(extensionOffset, extensionLength), out serverName))
            {
                return true;
            }

            extensionOffset += extensionLength;
        }

        return false;
    }

    private static bool TryGetServerNameExtension(ReadOnlySpan<byte> extension, out string serverName)
    {
        serverName = string.Empty;
        if (extension.Length < 5)
        {
            return false;
        }

        var listLength = ReadUInt16BigEndian(extension, 0);
        if (listLength + 2 > extension.Length || extension[2] != 0)
        {
            return false;
        }

        var nameLength = ReadUInt16BigEndian(extension, 3);
        if (nameLength == 0 || nameLength + 5 > extension.Length)
        {
            return false;
        }

        serverName = Encoding.ASCII.GetString(extension.Slice(5, nameLength));
        return true;
    }

    private static bool TryReadLengthPrefixedSection(ReadOnlySpan<byte> source, ref int offset, int lengthSize, out ReadOnlySpan<byte> section)
    {
        section = default;
        if (offset + lengthSize > source.Length)
        {
            return false;
        }

        var length = lengthSize == 1 ? source[offset] : ReadUInt16BigEndian(source, offset);
        offset += lengthSize;
        if (offset + length > source.Length)
        {
            return false;
        }

        section = source.Slice(offset, length);
        offset += length;
        return true;
    }

    private static int ReadUInt16BigEndian(ReadOnlySpan<byte> source, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(source[offset..]);

    private static int ReadUInt24BigEndian(ReadOnlySpan<byte> source, int offset) =>
        (source[offset] << 16) | (source[offset + 1] << 8) | source[offset + 2];
}
