using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LunaPacketSniffer.Proxy;

/// <summary>
/// A local CONNECT proxy that terminates TLS with a generated leaf certificate, re-establishes TLS to
/// the real server, and reports the cleartext flowing in both directions.
/// </summary>
public sealed class HttpsMitmProxy : IAsyncDisposable
{
    /// <summary>How long the surviving direction may keep delivering after its peer stops sending.</summary>
    private static readonly TimeSpan RelayDrainTimeout = TimeSpan.FromSeconds(10);

    /// <summary>How long disposal waits for in-flight connections before giving up on them.</summary>
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(5);

    private const int RelayBufferSize = 32_768;
    private const int MaxConnectRequestSize = 8_192;

    private readonly RootCertificateAuthority _certificateAuthority;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cancellation = new();

    // Lazy so that concurrent requests for the same host create exactly one certificate.
    // ConcurrentDictionary.GetOrAdd may run its factory more than once, and a discarded
    // X509Certificate2 would leak its key handle.
    private readonly ConcurrentDictionary<string, Lazy<X509Certificate2>> _leafCertificates = new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<Task, byte> _clientTasks = new();
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
        await _cancellation.CancelAsync();
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            await _acceptLoop;
        }

        // In-flight connections hold tokens linked to _cancellation, so they must finish before it
        // is disposed. They are already cancelled; the timeout only guards against a stuck socket.
        try
        {
            await Task.WhenAll(_clientTasks.Keys).WaitAsync(ShutdownTimeout);
        }
        catch (TimeoutException)
        {
        }

        _cancellation.Dispose();
        foreach (var certificate in _leafCertificates.Values.Where(value => value.IsValueCreated))
        {
            certificate.Value.Dispose();
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
                TrackClient(RunClientAsync(client, cancellationToken));
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException)
        {
        }
    }

    private void TrackClient(Task clientTask)
    {
        _clientTasks.TryAdd(clientTask, 0);
        _ = clientTask.ContinueWith(
            static (task, state) => ((ConcurrentDictionary<Task, byte>)state!).TryRemove(task, out _),
            _clientTasks,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    /// <summary>Never throws, so disposal can await every connection without handling failures again.</summary>
    private async Task RunClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            await HandleClientAsync(client, cancellationToken);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception)
        {
            Faulted?.Invoke(exception);
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
            await incomingTls.AuthenticateAsServerAsync(GetLeafCertificate(host), clientCertificateRequired: false, checkCertificateRevocation: false);

            using var upstream = new TcpClient();
            await upstream.ConnectAsync(host, port, cancellationToken);
            await using var upstreamTls = new SslStream(upstream.GetStream(), leaveInnerStreamOpen: false);
            await upstreamTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cancellationToken);

            await RelayUntilClosedAsync(incomingTls, upstreamTls, $"{host}:{port}:{sourcePort}", sourcePort, cancellationToken);
        }
    }

    /// <summary>
    /// Pumps both directions until the tunnel ends. Both tasks are awaited before returning, because
    /// returning early would dispose the streams underneath the direction still running — which
    /// truncates a response whose client has already stopped sending.
    /// </summary>
    internal async Task RelayUntilClosedAsync(Stream clientStream, Stream serverStream, string connectionKey, int sourcePort, CancellationToken cancellationToken)
    {
        using var connectionCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var toServer = RelayAsync(clientStream, serverStream, connectionKey, sourcePort, true, connectionCancellation.Token);
        var toClient = RelayAsync(serverStream, clientStream, connectionKey, sourcePort, false, connectionCancellation.Token);

        await Task.WhenAny(toServer, toClient);

        // One peer closed. Let the other finish delivering what is still in flight, but do not hold
        // the connection open indefinitely for a peer that never closes.
        connectionCancellation.CancelAfter(RelayDrainTimeout);
        await AwaitRelayAsync(toServer, connectionCancellation.Token);
        await AwaitRelayAsync(toClient, connectionCancellation.Token);
    }

    /// <summary>Awaits a relay, ignoring only the failures that ending the tunnel itself produces.</summary>
    private static async Task AwaitRelayAsync(Task relay, CancellationToken connectionCancellation)
    {
        try
        {
            await relay;
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception) when (connectionCancellation.IsCancellationRequested &&
                                          exception is IOException or ObjectDisposedException)
        {
        }
    }

    private X509Certificate2 GetLeafCertificate(string host) =>
        _leafCertificates.GetOrAdd(
            host,
            name => new Lazy<X509Certificate2>(
                () => _certificateAuthority.CreateLeafCertificate(name),
                LazyThreadSafetyMode.ExecutionAndPublication)).Value;

    private async Task RelayAsync(Stream source, Stream destination, string connectionKey, int sourcePort, bool isRequest, CancellationToken cancellationToken)
    {
        var buffer = new byte[RelayBufferSize];
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
        var buffer = new byte[MaxConnectRequestSize];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken);
            if (read == 0)
            {
                return null;
            }

            length += read;
            var text = Encoding.ASCII.GetString(buffer, 0, length);
            if (!text.Contains("\r\n\r\n", StringComparison.Ordinal))
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
