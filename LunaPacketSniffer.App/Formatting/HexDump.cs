using System.Text;

namespace LunaPacketSniffer.App.Formatting;

/// <summary>
/// Renders byte buffers as offset/hex(/ASCII) dumps for the detail pane.
/// </summary>
internal static class HexDump
{
    /// <summary>The number of bytes shown before the dump is truncated.</summary>
    public const int DefaultMaxBytes = 4_096;

    private const int BytesPerLine = 16;

    public static string Format(
        ReadOnlySpan<byte> data,
        int maxBytes = DefaultMaxBytes,
        bool includeText = true,
        string omittedNote = "from this view")
    {
        var text = new StringBuilder(Math.Min(data.Length, maxBytes) * 4);
        Append(text, data, maxBytes, includeText, omittedNote);
        return text.ToString();
    }

    public static void Append(
        StringBuilder text,
        ReadOnlySpan<byte> data,
        int maxBytes = DefaultMaxBytes,
        bool includeText = true,
        string omittedNote = "from this view")
    {
        var displayedLength = Math.Min(data.Length, maxBytes);
        for (var offset = 0; offset < displayedLength; offset += BytesPerLine)
        {
            var lineLength = Math.Min(BytesPerLine, displayedLength - offset);
            text.Append($"{offset:X4}  ");

            // Pad short lines only when the ASCII column follows and needs to stay aligned.
            var hexColumns = includeText ? BytesPerLine : lineLength;
            for (var index = 0; index < hexColumns; index++)
            {
                text.Append(index < lineLength ? $"{data[offset + index]:X2} " : "   ");
            }

            if (includeText)
            {
                text.Append(' ');
                for (var index = 0; index < lineLength; index++)
                {
                    text.Append(ToPrintable(data[offset + index]));
                }
            }

            text.AppendLine();
        }

        if (displayedLength < data.Length)
        {
            text.AppendLine($"... {data.Length - displayedLength:N0} bytes omitted {omittedNote}");
        }
    }

    /// <summary>Maps a byte to its printable ASCII character, or '.' when it is not printable.</summary>
    public static char ToPrintable(byte value) => value is >= 32 and <= 126 ? (char)value : '.';
}
