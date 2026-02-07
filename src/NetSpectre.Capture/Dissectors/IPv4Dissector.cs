using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class IPv4Dissector : IDissector
{
    public bool CanDissect(Packet packet) => packet is IPv4Packet;

    public ProtocolLayer Dissect(Packet packet)
    {
        var ip = (IPv4Packet)packet;
        var layer = new ProtocolLayer
        {
            Name = "Internet Protocol Version 4",
            HeaderOffset = ip.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = ip.HeaderLength
        };
        layer.AddField("Version", "4");
        layer.AddField("Header Length", $"{ip.HeaderLength} bytes");
        layer.AddField("Total Length", $"{ip.TotalLength}");
        layer.AddField("Identification", $"0x{ip.Id:X4} ({ip.Id})");
        layer.AddField("TTL", $"{ip.TimeToLive}");
        layer.AddField("Protocol", $"{ip.Protocol} ({(int)ip.Protocol})");
        layer.AddField("Source Address", ip.SourceAddress.ToString());
        layer.AddField("Destination Address", ip.DestinationAddress.ToString());
        layer.AddField("Header Checksum", $"0x{ip.Checksum:X4}");
        return layer;
    }
}
