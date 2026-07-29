namespace LunaPacketSniffer.App.ViewModels;

public sealed record ProcessListItem(uint ProcessId, string ProcessName)
{
    public string Display => $"{ProcessName} ({ProcessId})";
}
