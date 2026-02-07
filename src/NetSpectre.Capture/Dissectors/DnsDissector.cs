using System.Text;
using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public sealed class DnsDissector : IDissector
{
    public bool CanDissect(Packet packet)
    {
        if (packet is UdpPacket udp)
            return udp.SourcePort == 53 || udp.DestinationPort == 53;
        if (packet is TcpPacket tcp)
            return tcp.SourcePort == 53 || tcp.DestinationPort == 53;
        return false;
    }

    public ProtocolLayer Dissect(Packet packet)
    {
        var layer = new ProtocolLayer
        {
            Name = "Domain Name System",
            HeaderOffset = packet.ParentPacket?.HeaderData.Length ?? 0,
            HeaderLength = packet.PayloadData?.Length ?? 0
        };

        var payload = packet.PayloadData;
        if (payload == null || payload.Length < 12)
        {
            layer.AddField("Error", "Truncated DNS packet");
            return layer;
        }

        var transactionId = (ushort)((payload[0] << 8) | payload[1]);
        var flags = (ushort)((payload[2] << 8) | payload[3]);
        var qdCount = (ushort)((payload[4] << 8) | payload[5]);
        var anCount = (ushort)((payload[6] << 8) | payload[7]);
        var isResponse = (flags & 0x8000) != 0;

        layer.AddField("Transaction ID", $"0x{transactionId:X4}");
        layer.AddField("Type", isResponse ? "Response" : "Query");
        layer.AddField("Questions", $"{qdCount}");
        layer.AddField("Answers", $"{anCount}");

        if (qdCount > 0 && payload.Length > 12)
        {
            var name = ParseDnsName(payload, 12, out _);
            layer.AddField("Query Name", name);
        }

        return layer;
    }

    internal static string ParseDnsName(byte[] data, int offset, out int newOffset)
    {
        var sb = new StringBuilder();
        newOffset = offset;
        var maxIterations = 128;

        while (newOffset < data.Length && maxIterations-- > 0)
        {
            var labelLen = data[newOffset];
            if (labelLen == 0)
            {
                newOffset++;
                break;
            }

            if ((labelLen & 0xC0) == 0xC0)
            {
                if (newOffset + 1 >= data.Length) break;
                var pointer = ((labelLen & 0x3F) << 8) | data[newOffset + 1];
                newOffset += 2;
                var pointed = ParseDnsName(data, pointer, out _);
                if (sb.Length > 0) sb.Append('.');
                sb.Append(pointed);
                return sb.ToString();
            }

            newOffset++;
            if (newOffset + labelLen > data.Length) break;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(data, newOffset, labelLen));
            newOffset += labelLen;
        }

        return sb.Length > 0 ? sb.ToString() : "<empty>";
    }
}
