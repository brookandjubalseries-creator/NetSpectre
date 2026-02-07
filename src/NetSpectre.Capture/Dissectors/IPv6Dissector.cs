using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class IPv6Dissector : IDissector
{
    public bool CanDissect(Packet packet) => packet is IPv6Packet;

    public ProtocolLayer Dissect(Packet packet)
    {
        var ip6 = (IPv6Packet)packet;
        var layer = new ProtocolLayer
        {
            Name = "Internet Protocol Version 6",
            HeaderOffset = ip6.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = IPv6Fields.HeaderLength
        };
        layer.AddField("Version", "6");
        layer.AddField("Traffic Class", $"0x{ip6.TrafficClass:X2}");
        layer.AddField("Flow Label", $"0x{ip6.FlowLabel:X5}");
        layer.AddField("Payload Length", $"{ip6.PayloadLength}");
        layer.AddField("Next Header", $"{ip6.NextHeader} ({(int)ip6.NextHeader})");
        layer.AddField("Hop Limit", $"{ip6.HopLimit}");
        layer.AddField("Source Address", ip6.SourceAddress.ToString());
        layer.AddField("Destination Address", ip6.DestinationAddress.ToString());
        return layer;
    }
}
