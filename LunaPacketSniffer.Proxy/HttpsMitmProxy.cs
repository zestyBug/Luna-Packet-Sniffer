using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace LunaPacketSniffer.Proxy;

public sealed class HttpsMitmProxy : IAsyncDisposable
{
    private readonly RootCertificateAuthority _certificateAuthority;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cancellation = new();
    private readonly ConcurrentDictionary<string, X509Certificate2> _leafCertificates = new(StringComparer.OrdinalIgnoreCase);
    private Task? _acceptLoop;

    public event Action<DecryptedHttpData>? DecryptedData;
    public event Action<Exception>? Faulted;

    public HttpsMitmProxy(RootCertificateAuthority certificateAuthority, int port = 0)
    {
        _certificateAuthority = certificateAuthority;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public void Start()
    {
        _listener.Start();
        _acceptLoop = AcceptLoopAsync(_cancellation.Token);
    }

    public async ValueTask DisposeAsync()
    {
        _cancellation.Cancel();
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            await _acceptLoop;
        }

        _cancellation.Dispose();
        foreach (var certificate in _leafCertificates.Values)
        {
            certificate.Dispose();
        }

        _leafCertificates.Clear();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                _ = HandleClientAsync(client, cancellationToken).ContinueWith(
                    task => Faulted?.Invoke(task.Exception!.GetBaseException()),
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted,
                    TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        await using (var clientStream = client.GetStream())
        {
            var sourcePort = ((IPEndPoint)client.Client.RemoteEndPoint!).Port;
            var request = await ReadConnectRequestAsync(clientStream, cancellationToken);
            if (request is null)
            {
                return;
            }

            var (host, port) = request.Value;
            await clientStream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), cancellationToken);
            await using var incomingTls = new SslStream(clientStream, leaveInnerStreamOpen: true);
            var certificate = _leafCertificates.GetOrAdd(host, _certificateAuthority.CreateLeafCertificate);
            await incomingTls.AuthenticateAsServerAsync(certificate, clientCertificateRequired: false, checkCertificateRevocation: false);

            using var upstream = new TcpClient();
            await upstream.ConnectAsync(host, port, cancellationToken);
            await using var upstreamTls = new SslStream(upstream.GetStream(), leaveInnerStreamOpen: false);
            await upstreamTls.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions { TargetHost = host },
                cancellationToken);

            var connectionKey = $"{host}:{port}:{sourcePort}";
            await Task.WhenAny(
                RelayAsync(incomingTls, upstreamTls, connectionKey, sourcePort, true, cancellationToken),
                RelayAsync(upstreamTls, incomingTls, connectionKey, sourcePort, false, cancellationToken));
        }
    }

    private async Task RelayAsync(Stream source, Stream destination, string connectionKey, int sourcePort, bool isRequest, CancellationToken cancellationToken)
    {
        var buffer = new byte[32_768];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                await destination.FlushAsync(cancellationToken);
                return;
            }

            DecryptedData?.Invoke(new DecryptedHttpData(connectionKey, sourcePort, isRequest, buffer.AsMemory(0, read).ToArray()));
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static async Task<(string Host, int Port)?> ReadConnectRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken);
            if (read == 0)
            {
                return null;
            }

            length += read;
            var text = System.Text.Encoding.ASCII.GetString(buffer, 0, length);
            var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end < 0)
            {
                continue;
            }

            var lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
            var parts = text[..lineEnd].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 3 || !string.Equals(parts[0], "CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var separator = parts[1].LastIndexOf(':');
            return separator <= 0 || !int.TryParse(parts[1][(separator + 1)..], out var port)
                ? null
                : (parts[1][..separator], port);
        }

        return null;
    }
}

public sealed record DecryptedHttpData(string ConnectionKey, int SourcePort, bool IsRequest, byte[] Data);
