using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class ArpDissector : IDissector
{
    public bool CanDissect(Packet packet) => packet is ArpPacket;

    public ProtocolLayer Dissect(Packet packet)
    {
        var arp = (ArpPacket)packet;
        var layer = new ProtocolLayer
        {
            Name = "Address Resolution Protocol",
            HeaderOffset = arp.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = arp.HeaderData.Length
        };
        layer.AddField("Hardware Type", $"{arp.HardwareAddressType}");
        layer.AddField("Protocol Type", $"0x{(ushort)arp.ProtocolAddressType:X4}");
        layer.AddField("Operation", $"{arp.Operation}");
        layer.AddField("Sender MAC", arp.SenderHardwareAddress.ToString());
        layer.AddField("Sender IP", arp.SenderProtocolAddress.ToString());
        layer.AddField("Target MAC", arp.TargetHardwareAddress.ToString());
        layer.AddField("Target IP", arp.TargetProtocolAddress.ToString());
        return layer;
    }
}
