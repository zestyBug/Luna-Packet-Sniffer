using System.ComponentModel;
using LunaPacketSniffer.Protocols;

namespace LunaPacketSniffer.App.ViewModels;

public sealed class KcpConversationListItem : INotifyPropertyChanged
{
    public KcpConversationListItem(KcpConversationUpdate update)
    {
        ConversationId = update.ConversationId.ToString();
        EndpointA = update.EndpointA;
        EndpointB = update.EndpointB;
        Update(update);
    }

    public KcpConversationListItem(
        string conversationId,
        string endpointA,
        string endpointB,
        string lastCommand,
        long lastSequenceNumber,
        long segmentCount,
        long messageCount,
        long messageBytes)
    {
        ConversationId = conversationId;
        EndpointA = endpointA;
        EndpointB = endpointB;
        SegmentCount = segmentCount;
        MessageCount = messageCount;
        MessageBytes = messageBytes;
        Detail = CreateDetail(lastCommand, lastSequenceNumber);
    }

    public string ConversationId { get; }
    public string EndpointA { get; }
    public string EndpointB { get; }
    public long SegmentCount { get; private set; }
    public long MessageCount { get; private set; }
    public long MessageBytes { get; private set; }
    public string Detail { get; private set; } = string.Empty;
    public event PropertyChangedEventHandler? PropertyChanged;

    public void Update(KcpConversationUpdate update)
    {
        SegmentCount = update.SegmentCount;
        MessageCount = update.ReassembledMessageCount;
        MessageBytes = update.ReassembledByteCount;
        Detail = CreateDetail(update.LastCommand, update.LastSequenceNumber);
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SegmentCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(MessageCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(MessageBytes)));
    }

    private string CreateDetail(string lastCommand, long lastSequenceNumber)
    {
        var newLine = Environment.NewLine;
        return $"conv: {ConversationId}{newLine}Endpoint A: {EndpointA}{newLine}Endpoint B: {EndpointB}" +
               $"{newLine}Last command: {lastCommand}{newLine}Last sequence number: {lastSequenceNumber}" +
               $"{newLine}Segments: {SegmentCount:N0}{newLine}Reassembled messages: {MessageCount:N0}{newLine}Reassembled bytes: {MessageBytes:N0}";
    }
}
