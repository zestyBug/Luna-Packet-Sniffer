using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace LunaPacketSniffer.Capture;

internal static class WindowsSocketTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int ErrorInsufficientBuffer = 122;

    public static IEnumerable<SocketOwner> GetOwners()
    {
        foreach (var row in ReadTable<MibTcpRowOwnerPid, TcpTableClass>(GetExtendedTcpTable, AfInet, TcpTableClass.OwnerPidAll))
        {
            yield return new SocketOwner(6, ToAddress(row.LocalAddress), ToPort(row.LocalPort), ToAddress(row.RemoteAddress), ToPort(row.RemotePort), row.OwningPid);
        }

        foreach (var row in ReadTable<MibTcp6RowOwnerPid, TcpTableClass>(GetExtendedTcpTable, AfInet6, TcpTableClass.OwnerPidAll))
        {
            yield return new SocketOwner(6, new IPAddress(row.LocalAddress), ToPort(row.LocalPort), new IPAddress(row.RemoteAddress), ToPort(row.RemotePort), row.OwningPid);
        }

        foreach (var row in ReadTable<MibUdpRowOwnerPid, UdpTableClass>(GetExtendedUdpTable, AfInet, UdpTableClass.OwnerPid))
        {
            yield return new SocketOwner(17, ToAddress(row.LocalAddress), ToPort(row.LocalPort), null, null, row.OwningPid);
        }

        foreach (var row in ReadTable<MibUdp6RowOwnerPid, UdpTableClass>(GetExtendedUdpTable, AfInet6, UdpTableClass.OwnerPid))
        {
            yield return new SocketOwner(17, new IPAddress(row.LocalAddress), ToPort(row.LocalPort), null, null, row.OwningPid);
        }
    }

    private static IEnumerable<T> ReadTable<T, TTableClass>(GetTable<TTableClass> getTable, int addressFamily, TTableClass tableClass)
        where T : struct
        where TTableClass : Enum
    {
        var length = 0;
        var result = getTable(IntPtr.Zero, ref length, false, addressFamily, tableClass, 0);
        if (result != ErrorInsufficientBuffer)
        {
            throw new Win32Exception((int)result, "Unable to read the Windows socket table.");
        }

        var buffer = Marshal.AllocHGlobal(length);
        try
        {
            result = getTable(buffer, ref length, false, addressFamily, tableClass, 0);
            if (result != 0)
            {
                throw new Win32Exception((int)result, "Unable to read the Windows socket table.");
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<T>();
            for (var index = 0; index < count; index++)
            {
                yield return Marshal.PtrToStructure<T>(IntPtr.Add(buffer, sizeof(uint) + index * rowSize));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IPAddress ToAddress(uint address) =>
        new([(byte)address, (byte)(address >> 8), (byte)(address >> 16), (byte)(address >> 24)]);

    private static ushort ToPort(uint port) =>
        (ushort)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));

    private delegate uint GetTable<TTableClass>(IntPtr table, ref int length, bool order, int addressFamily, TTableClass tableClass, uint reserved)
        where TTableClass : Enum;

    private enum TcpTableClass
    {
        OwnerPidAll = 5,
    }

    private enum UdpTableClass
    {
        OwnerPid = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddress;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddress;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    internal readonly record struct SocketOwner(
        byte Protocol,
        IPAddress LocalAddress,
        ushort LocalPort,
        IPAddress? RemoteAddress,
        ushort? RemotePort,
        uint ProcessId);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref int length,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        TcpTableClass tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr table,
        ref int length,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        UdpTableClass tableClass,
        uint reserved);
}
