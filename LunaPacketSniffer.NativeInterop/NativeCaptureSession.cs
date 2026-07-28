using System.Runtime.InteropServices;
using System.Net;
using LunaPacketSniffer.Core;

namespace LunaPacketSniffer.NativeInterop;

public sealed class NativeCaptureSession : IDisposable
{
    private readonly NativeMethods.PacketCallback _callback;
    private readonly NativeMethods.FlowCallback _flowCallback;
    private readonly Action<CapturedPacket> _packetReceived;
    private readonly Action<NativeFlowEvent> _flowReceived;
    private IntPtr _handle;
    private bool _disposed;

    public NativeCaptureSession(Action<CapturedPacket> packetReceived, Action<NativeFlowEvent> flowReceived)
    {
        _packetReceived = packetReceived;
        _flowReceived = flowReceived;
        _callback = OnPacket;
        _flowCallback = OnFlow;
    }

    public void Start(string filter = "true")
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var result = NativeMethods.PcCaptureStart(filter, _callback, _flowCallback, IntPtr.Zero, out _handle, out var failureStage);
        if (result != 0)
        {
            throw new NativeCaptureException(result, failureStage);
        }
    }

    public void Stop()
    {
        if (_handle == IntPtr.Zero)
        {
            return;
        }

        NativeMethods.PcCaptureStop(_handle);
        _handle = IntPtr.Zero;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private void OnPacket(IntPtr context, in NativeMethods.NativePacket packet)
    {
        var data = new byte[packet.Length];
        Marshal.Copy(packet.Data, data, 0, checked((int)packet.Length));
        _packetReceived(new CapturedPacket(
            DateTimeOffset.UnixEpoch.AddTicks(packet.TimestampUnixNanoseconds / 100),
            packet.Direction == 0 ? PacketDirection.Inbound : PacketDirection.Outbound,
            packet.InterfaceIndex,
            data));
    }

    private void OnFlow(IntPtr context, in NativeMethods.NativeFlowEvent flowEvent)
    {
        var localAddress = new byte[flowEvent.AddressLength];
        var remoteAddress = new byte[flowEvent.AddressLength];
        Marshal.Copy(flowEvent.LocalAddress, localAddress, 0, localAddress.Length);
        Marshal.Copy(flowEvent.RemoteAddress, remoteAddress, 0, remoteAddress.Length);
        _flowReceived(new NativeFlowEvent(
            flowEvent.ProcessId,
            flowEvent.Protocol,
            flowEvent.EventType,
            new IPAddress(localAddress),
            new IPAddress(remoteAddress),
            flowEvent.LocalPort,
            flowEvent.RemotePort));
    }
}

public sealed record NativeFlowEvent(
    uint ProcessId,
    byte Protocol,
    byte EventType,
    IPAddress LocalAddress,
    IPAddress RemoteAddress,
    ushort LocalPort,
    ushort RemotePort);

public sealed class NativeCaptureException(int errorCode, int failureStage)
    : Exception($"WinDivert could not open the {GetStageName(failureStage)} handle. Win32 error: {errorCode}.")
{
    public int ErrorCode { get; } = errorCode;

    public int FailureStage { get; } = failureStage;

    private static string GetStageName(int failureStage) => failureStage switch
    {
        1 => "NETWORK",
        2 => "FLOW",
        _ => "capture",
    };
}

internal static class NativeMethods
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct NativePacket
    {
        public readonly IntPtr Data;
        public readonly uint Length;
        public readonly long TimestampUnixNanoseconds;
        public readonly byte Direction;
        public readonly uint InterfaceIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct NativeFlowEvent
    {
        public readonly uint ProcessId;
        public readonly byte Protocol;
        public readonly byte EventType;
        public readonly byte AddressLength;
        public readonly IntPtr LocalAddress;
        public readonly IntPtr RemoteAddress;
        public readonly ushort LocalPort;
        public readonly ushort RemotePort;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void PacketCallback(IntPtr context, in NativePacket packet);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void FlowCallback(IntPtr context, in NativeFlowEvent flowEvent);

    [DllImport("LunaPacketSniffer.Native", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern int PcCaptureStart(
        string filter,
        PacketCallback callback,
        FlowCallback flowCallback,
        IntPtr context,
        out IntPtr handle,
        out int failureStage);

    [DllImport("LunaPacketSniffer.Native", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void PcCaptureStop(IntPtr handle);

}
