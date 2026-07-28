namespace LunaPacketSniffer.Capture;

public static class TcpConnectionOwnerLookup
{
    public static bool TryGetProcessId(ushort localPort, ushort remotePort, out uint processId)
    {
        foreach (var owner in WindowsSocketTable.GetOwners())
        {
            if (owner.Protocol == 6 && owner.LocalPort == localPort && owner.RemotePort == remotePort)
            {
                processId = owner.ProcessId;
                return true;
            }
        }

        processId = 0;
        return false;
    }
}
