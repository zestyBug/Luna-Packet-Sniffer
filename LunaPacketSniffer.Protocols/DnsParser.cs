using System.Text;

namespace LunaPacketSniffer.Protocols;

/// <summary>Reads the first question name out of a DNS message for the packet summary column.</summary>
internal static class DnsParser
{
    private const int HeaderLength = 12;
    private const byte CompressionPointerMask = 0xC0;

    public static bool TryGetQuestion(ReadOnlySpan<byte> payload, out string question)
    {
        question = string.Empty;
        if (payload.Length < HeaderLength || ((payload[4] << 8) | payload[5]) == 0)
        {
            return false;
        }

        var offset = HeaderLength;
        var labels = new List<string>();
        while (offset < payload.Length)
        {
            var length = payload[offset++];
            if (length == 0)
            {
                break;
            }

            // A compression pointer cannot appear in the first question of a query.
            if ((length & CompressionPointerMask) != 0 || offset + length > payload.Length)
            {
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(payload.Slice(offset, length)));
            offset += length;
        }

        if (labels.Count == 0 || offset + 4 > payload.Length)
        {
            return false;
        }

        question = string.Join('.', labels);
        return true;
    }
}
