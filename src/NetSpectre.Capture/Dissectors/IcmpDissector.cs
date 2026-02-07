using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class IcmpDissector : IDissector
{
    public bool CanDissect(Packet packet) => packet is IcmpV4Packet or IcmpV6Packet;

    public ProtocolLayer Dissect(Packet packet)
    {
        if (packet is IcmpV4Packet icmp4)
            return DissectV4(icmp4);
        var icmp6 = (IcmpV6Packet)packet;
        return DissectV6(icmp6);
    }

    private static ProtocolLayer DissectV4(IcmpV4Packet icmp)
    {
        var layer = new ProtocolLayer
        {
            Name = "Internet Control Message Protocol",
            HeaderOffset = icmp.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = icmp.HeaderData.Length
        };
        layer.AddField("Type", $"{(int)icmp.TypeCode >> 8} ({icmp.TypeCode})");
        layer.AddField("Code", $"{(int)icmp.TypeCode & 0xFF}");
        layer.AddField("Checksum", $"0x{icmp.Checksum:X4}");
        layer.AddField("Identifier", $"{icmp.Id}");
        layer.AddField("Sequence", $"{icmp.Sequence}");
        return layer;
    }

    private static ProtocolLayer DissectV6(IcmpV6Packet icmp6)
    {
        var layer = new ProtocolLayer
        {
            Name = "ICMPv6",
            HeaderOffset = icmp6.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = icmp6.HeaderData.Length
        };
        layer.AddField("Type", $"{icmp6.Type}");
        layer.AddField("Code", $"{icmp6.Code}");
        layer.AddField("Checksum", $"0x{icmp6.Checksum:X4}");
        return layer;
    }
}
