using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class UdpDissector : IDissector
{
    public bool CanDissect(Packet packet) => packet is UdpPacket;

    public ProtocolLayer Dissect(Packet packet)
    {
        var udp = (UdpPacket)packet;
        var layer = new ProtocolLayer
        {
            Name = "User Datagram Protocol",
            HeaderOffset = udp.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = UdpFields.HeaderLength
        };
        layer.AddField("Source Port", $"{udp.SourcePort}");
        layer.AddField("Destination Port", $"{udp.DestinationPort}");
        layer.AddField("Length", $"{udp.Length}");
        layer.AddField("Checksum", $"0x{udp.Checksum:X4}");
        if (udp.PayloadData?.Length > 0)
            layer.AddField("Payload", $"{udp.PayloadData.Length} bytes");
        return layer;
    }
}
