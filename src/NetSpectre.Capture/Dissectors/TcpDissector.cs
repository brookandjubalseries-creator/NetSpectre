using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class TcpDissector : IDissector
{
    public bool CanDissect(Packet packet) => packet is TcpPacket;

    public ProtocolLayer Dissect(Packet packet)
    {
        var tcp = (TcpPacket)packet;
        var layer = new ProtocolLayer
        {
            Name = "Transmission Control Protocol",
            HeaderOffset = tcp.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = tcp.DataOffset * 4
        };
        layer.AddField("Source Port", $"{tcp.SourcePort}");
        layer.AddField("Destination Port", $"{tcp.DestinationPort}");
        layer.AddField("Sequence Number", $"{tcp.SequenceNumber}");
        layer.AddField("Acknowledgment Number", $"{tcp.AcknowledgmentNumber}");
        layer.AddField("Data Offset", $"{tcp.DataOffset * 4} bytes");
        layer.AddField("Flags", FormatFlags(tcp));
        layer.AddField("Window Size", $"{tcp.WindowSize}");
        layer.AddField("Checksum", $"0x{tcp.Checksum:X4}");
        layer.AddField("Urgent Pointer", $"{tcp.UrgentPointer}");
        if (tcp.PayloadData?.Length > 0)
            layer.AddField("Payload", $"{tcp.PayloadData.Length} bytes");
        return layer;
    }

    private static string FormatFlags(TcpPacket tcp)
    {
        var flags = new List<string>();
        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Push) flags.Add("PSH");
        if (tcp.Urgent) flags.Add("URG");
        return string.Join(", ", flags);
    }
}
