using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace LunaPacketSniffer.Proxy;

public sealed class WindowsProxySession : IDisposable
{
    private const string InternetSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;

    private static readonly string[] SettingNames = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"];

    private readonly Dictionary<string, RegistryValueSnapshot> _originalSettings;
    private bool _disposed;

    private WindowsProxySession(Dictionary<string, RegistryValueSnapshot> originalSettings)
    {
        _originalSettings = originalSettings;
    }

    public static WindowsProxySession Start(int port)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);
        using var settings = Registry.CurrentUser.CreateSubKey(InternetSettingsPath, writable: true)
            ?? throw new InvalidOperationException("Could not open the Windows Internet settings registry key.");

        var originalSettings = SettingNames.ToDictionary(
            name => name,
            name => RegistryValueSnapshot.Read(settings, name),
            StringComparer.Ordinal);
        var session = new WindowsProxySession(originalSettings);
        try
        {
            settings.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            settings.SetValue("ProxyServer", $"https=127.0.0.1:{port}", RegistryValueKind.String);
            settings.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
            settings.SetValue("AutoDetect", 0, RegistryValueKind.DWord);
            Refresh();
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        using var settings = Registry.CurrentUser.CreateSubKey(InternetSettingsPath, writable: true)
            ?? throw new InvalidOperationException("Could not open the Windows Internet settings registry key.");
        foreach (var (name, snapshot) in _originalSettings)
        {
            snapshot.Restore(settings, name);
        }

        Refresh();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private static void Refresh()
    {
        if (!InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0) ||
            !InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int bufferLength);

    private sealed record RegistryValueSnapshot(bool Exists, object? Value, RegistryValueKind Kind)
    {
        public static RegistryValueSnapshot Read(RegistryKey key, string name)
        {
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is null
                ? new RegistryValueSnapshot(false, null, RegistryValueKind.None)
                : new RegistryValueSnapshot(true, value, key.GetValueKind(name));
        }

        public void Restore(RegistryKey key, string name)
        {
            if (!Exists)
            {
                key.DeleteValue(name, throwOnMissingValue: false);
                return;
            }

            key.SetValue(name, Value!, Kind);
        }
    }
}
