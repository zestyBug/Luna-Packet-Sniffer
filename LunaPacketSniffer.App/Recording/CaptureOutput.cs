using System.IO;

namespace LunaPacketSniffer.App.Recording;

/// <summary>
/// The on-disk layout of a capture folder, shared by the writers and the capture loader.
/// </summary>
internal static class CaptureOutput
{
    public const string PcapFileName = "capture.pcapng";
    public const string IndexFileName = "capture.index.sqlite";
    public const string HarFileName = "capture.http.har";
    public const string SessionsFileName = "sessions.json";
    public const string BodiesDirectoryName = "bodies";

    /// <summary>The <c>out</c> folder beside the executable that holds every capture folder.</summary>
    public static string RootDirectory => Path.Combine(AppContext.BaseDirectory, "out");

    /// <summary>Creates a new timestamped capture folder under <see cref="RootDirectory"/>.</summary>
    public static string CreateCaptureDirectory()
    {
        var directory = Path.Combine(RootDirectory, DateTimeOffset.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
