using System.Collections.Concurrent;
using System.Diagnostics;
using LunaPacketSniffer.Capture;
using LunaPacketSniffer.Persistence;
using LunaPacketSniffer.Proxy;

namespace LunaPacketSniffer.App.Recording;

/// <summary>
/// Runs the local HTTPS MITM proxy for the duration of a capture: installs the root CA, redirects the
/// Windows proxy setting, and forwards decrypted traffic that matches the capture's process filters.
/// </summary>
internal sealed class HttpsMitmController
{
    private readonly RootCertificateAuthority _rootCertificateAuthority;

    /// <summary>Caches the filter verdict per source port, since the owning process cannot change mid-connection.</summary>
    private readonly ConcurrentDictionary<int, bool> _decryptedPortMatches = new();

    private HttpsMitmProxy? _proxy;
    private WindowsProxySession? _windowsProxySession;
    private IReadOnlyList<CaptureFilter> _processFilters = [];

    public HttpsMitmController(RootCertificateAuthority rootCertificateAuthority) =>
        _rootCertificateAuthority = rootCertificateAuthority;

    public void Start(HttpHarWriter harWriter, IEnumerable<CaptureFilter> filters)
    {
        _rootCertificateAuthority.EnsureInstalled();
        _processFilters = filters
            .Where(filter => filter.Type is CaptureFilterType.ProcessId or CaptureFilterType.ProcessName)
            .ToArray();
        _decryptedPortMatches.Clear();

        _proxy = new HttpsMitmProxy(_rootCertificateAuthority);
        _proxy.DecryptedData += data =>
        {
            if (ShouldSaveDecryptedData(data.SourcePort))
            {
                harWriter.ObserveDecrypted(data.ConnectionKey, data.IsRequest, data.Data);
            }
        };
        _proxy.Faulted += ApplicationLog.Write;
        _proxy.Start();
        _windowsProxySession = WindowsProxySession.Start(_proxy.Port);
        ApplicationLog.Write($"Windows proxy set to 127.0.0.1:{_proxy.Port}.");
    }

    /// <summary>Restores the Windows proxy setting and shuts the proxy down. Safe to call when not started.</summary>
    public async ValueTask StopAsync()
    {
        if (_windowsProxySession is not null)
        {
            _windowsProxySession.Dispose();
            _windowsProxySession = null;
            ApplicationLog.Write("Windows proxy settings restored.");
        }

        if (_proxy is not null)
        {
            await _proxy.DisposeAsync();
            _proxy = null;
        }

        _decryptedPortMatches.Clear();
        _processFilters = [];
    }

    /// <summary>
    /// Everything on the machine flows through the proxy, so decrypted data is kept only when the
    /// connection's owning process matches a PID or process-name filter. No such filter means keep all.
    /// </summary>
    private bool ShouldSaveDecryptedData(int sourcePort)
    {
        if (_processFilters.Count == 0)
        {
            return true;
        }

        if (_decryptedPortMatches.TryGetValue(sourcePort, out var matches))
        {
            return matches;
        }

        if (_proxy is null || !TcpConnectionOwnerLookup.TryGetProcessId((ushort)sourcePort, (ushort)_proxy.Port, out var processId))
        {
            return false;
        }

        matches = _processFilters.Any(filter =>
            filter.Type == CaptureFilterType.ProcessId && filter.Value == processId.ToString());
        if (!matches)
        {
            try
            {
                using var process = Process.GetProcessById(checked((int)processId));
                matches = _processFilters.Any(filter =>
                    filter.Type == CaptureFilterType.ProcessName && string.Equals(filter.Value, process.ProcessName, StringComparison.OrdinalIgnoreCase));
            }
            catch (ArgumentException)
            {
                // The process exited before it could be identified; treat it as a non-match.
            }
        }

        _decryptedPortMatches.TryAdd(sourcePort, matches);
        return matches;
    }
}
