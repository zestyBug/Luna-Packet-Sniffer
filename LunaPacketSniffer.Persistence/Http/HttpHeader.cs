namespace LunaPacketSniffer.Persistence.Http;

/// <summary>
/// One HTTP header. HAR entries use the same <c>{name, value}</c> shape, so this type is serialized
/// into the HAR document directly.
/// </summary>
internal sealed record HttpHeader(string Name, string Value)
{
    /// <summary>Parses the header block, skipping the request or status line.</summary>
    public static List<HttpHeader> Parse(string headerText)
    {
        var headers = new List<HttpHeader>();
        foreach (var line in headerText.Split("\r\n", StringSplitOptions.None).Skip(1))
        {
            var separator = line.IndexOf(':');
            if (separator > 0)
            {
                headers.Add(new HttpHeader(line[..separator], line[(separator + 1)..].Trim()));
            }
        }

        return headers;
    }

    public static string? GetValue(IEnumerable<HttpHeader> headers, string name) =>
        headers.FirstOrDefault(header => string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;

    public static string Format(IEnumerable<HttpHeader> headers) =>
        string.Join(Environment.NewLine, headers.Select(header => $"{header.Name}: {header.Value}"));
}
