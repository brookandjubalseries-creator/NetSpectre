using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class EthernetDissector : IDissector
{
    public bool CanDissect(Packet packet) => packet is EthernetPacket;

    public ProtocolLayer Dissect(Packet packet)
    {
        var eth = (EthernetPacket)packet;
        var layer = new ProtocolLayer
        {
            Name = "Ethernet II",
            HeaderOffset = 0,
            HeaderLength = EthernetFields.HeaderLength
        };
        layer.AddField("Source MAC", eth.SourceHardwareAddress.ToString(), 6, 6);
        layer.AddField("Destination MAC", eth.DestinationHardwareAddress.ToString(), 0, 6);
        layer.AddField("Type", $"0x{(ushort)eth.Type:X4} ({eth.Type})", 12, 2);
        return layer;
    }
}
