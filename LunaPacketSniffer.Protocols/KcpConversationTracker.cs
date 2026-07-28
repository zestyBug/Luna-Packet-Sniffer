using System.Net;
using LunaPacketSniffer.Networking;

namespace LunaPacketSniffer.Protocols;

public sealed record KcpConversationUpdate(
    uint ConversationId,
    string EndpointA,
    string EndpointB,
    string LastCommand,
    uint LastSequenceNumber,
    long SegmentCount,
    long ReassembledMessageCount,
    long ReassembledByteCount);

internal sealed class KcpConversationTracker
{
    private readonly Dictionary<KcpConversationKey, KcpConversationState> _conversations = [];

    public KcpConversationUpdate? Observe(DecodedPacket packet)
    {
        if (packet.Protocol != 17 || !KcpParser.TryParse(packet.Payload.Span, out var segment))
        {
            return null;
        }

        var key = KcpConversationKey.Create(packet.Source, packet.Destination, segment.ConversationId);
        if (!_conversations.TryGetValue(key, out var state))
        {
            state = new KcpConversationState(key);
            _conversations.Add(key, state);
        }

        state.Add(segment);
        return state.ToUpdate(segment);
    }

    private readonly record struct KcpConversationKey(uint ConversationId, IPEndPoint EndpointA, IPEndPoint EndpointB)
    {
        public static KcpConversationKey Create(IPEndPoint first, IPEndPoint second, uint conversationId) =>
            string.CompareOrdinal(first.ToString(), second.ToString()) <= 0
                ? new KcpConversationKey(conversationId, first, second)
                : new KcpConversationKey(conversationId, second, first);
    }

    private sealed class KcpConversationState
    {
        private readonly KcpConversationKey _key;
        private readonly Dictionary<uint, KcpSegment> _fragments = [];
        private long _segmentCount;
        private long _reassembledMessageCount;
        private long _reassembledByteCount;

        public KcpConversationState(KcpConversationKey key)
        {
            _key = key;
        }

        public void Add(KcpSegment segment)
        {
            _segmentCount++;
            if (segment.Command != "PUSH")
            {
                return;
            }

            _fragments[segment.SequenceNumber] = segment;
            if (segment.FragmentCount != 0)
            {
                return;
            }

            var fragmentCount = 1;
            var byteCount = segment.Payload.Length;
            for (var sequence = segment.SequenceNumber; sequence > 0 && _fragments.TryGetValue(sequence - 1, out var previous) && previous.FragmentCount == fragmentCount; sequence--)
            {
                fragmentCount++;
                byteCount += previous.Payload.Length;
            }

            if (fragmentCount == 1 || _fragments.ContainsKey(segment.SequenceNumber - (uint)(fragmentCount - 1)))
            {
                _reassembledMessageCount++;
                _reassembledByteCount += byteCount;
                for (var index = 0; index < fragmentCount; index++)
                {
                    _fragments.Remove(segment.SequenceNumber - (uint)index);
                }
            }
        }

        public KcpConversationUpdate ToUpdate(KcpSegment segment) => new(
            _key.ConversationId,
            _key.EndpointA.ToString(),
            _key.EndpointB.ToString(),
            segment.Command,
            segment.SequenceNumber,
            _segmentCount,
            _reassembledMessageCount,
            _reassembledByteCount);
    }
}
