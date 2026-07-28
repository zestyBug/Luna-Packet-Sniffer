using System.IO;
using System.Text;

namespace LunaPacketSniffer.App;

internal static class ApplicationLog
{
    private static readonly Lock SyncRoot = new();
    private static readonly string LogPath = Path.Combine(AppContext.BaseDirectory, "LunaPacketSniffer.log");

    public static void Clear()
    {
        File.WriteAllText(LogPath, string.Empty, new UTF8Encoding(false));
    }

    public static void Write(string message)
    {
        lock (SyncRoot)
        {
            File.AppendAllText(LogPath, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}", new UTF8Encoding(false));
        }
    }

    public static void Write(Exception exception) => Write(exception.ToString());
}
