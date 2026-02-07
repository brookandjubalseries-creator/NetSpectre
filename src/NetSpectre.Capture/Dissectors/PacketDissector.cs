using NetSpectre.Core.Models;
using PacketDotNet;
using SharpPcap;

namespace NetSpectre.Capture.Dissectors;

public sealed class PacketDissector
{
    private readonly List<IDissector> _dissectors;
    private readonly DnsDissector _dnsDissector = new();

    public PacketDissector()
    {
        _dissectors = new List<IDissector>
        {
            new EthernetDissector(),
            new IPv4Dissector(),
            new IPv6Dissector(),
            new TcpDissector(),
            new UdpDissector(),
            new IcmpDissector(),
            new ArpDissector(),
        };
    }

    public PacketRecord Dissect(RawCapture rawCapture, int packetNumber)
    {
        var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
        var record = new PacketRecord
        {
            Number = packetNumber,
            Timestamp = rawCapture.Timeval.Date.ToLocalTime(),
            RawData = rawCapture.Data,
            Length = rawCapture.Data.Length,
        };

        var layers = new PacketLayers();

        // Walk the packet stack and dissect each layer
        var current = packet;
        while (current != null)
        {
            foreach (var dissector in _dissectors)
            {
                if (dissector.CanDissect(current))
                {
                    layers.AddLayer(dissector.Dissect(current));
                    break;
                }
            }
            current = current.PayloadPacket;
        }

        // Determine protocol and addresses
        DetermineProtocolInfo(packet, record);

        // Check for DNS overlay on UDP/TCP
        var udp = packet.Extract<UdpPacket>();
        var tcp = packet.Extract<TcpPacket>();
        if (udp != null && _dnsDissector.CanDissect(udp))
        {
            layers.AddLayer(_dnsDissector.Dissect(udp));
            record.Protocol = "DNS";
            record.Info = BuildDnsInfo(udp);
        }
        else if (tcp != null && _dnsDissector.CanDissect(tcp))
        {
            layers.AddLayer(_dnsDissector.Dissect(tcp));
            record.Protocol = "DNS";
        }

        record.Layers = layers;
        return record;
    }

    private static void DetermineProtocolInfo(Packet packet, PacketRecord record)
    {
        var ipv4 = packet.Extract<IPv4Packet>();
        var ipv6 = packet.Extract<IPv6Packet>();
        var tcp = packet.Extract<TcpPacket>();
        var udp = packet.Extract<UdpPacket>();
        var icmpv4 = packet.Extract<IcmpV4Packet>();
        var icmpv6 = packet.Extract<IcmpV6Packet>();
        var arp = packet.Extract<ArpPacket>();

        // Set addresses
        if (ipv4 != null)
        {
            record.SourceAddress = ipv4.SourceAddress.ToString();
            record.DestinationAddress = ipv4.DestinationAddress.ToString();
        }
        else if (ipv6 != null)
        {
            record.SourceAddress = ipv6.SourceAddress.ToString();
            record.DestinationAddress = ipv6.DestinationAddress.ToString();
        }
        else if (arp != null)
        {
            record.SourceAddress = arp.SenderProtocolAddress.ToString();
            record.DestinationAddress = arp.TargetProtocolAddress.ToString();
        }
        else if (packet is EthernetPacket eth)
        {
            record.SourceAddress = eth.SourceHardwareAddress.ToString();
            record.DestinationAddress = eth.DestinationHardwareAddress.ToString();
        }

        // Set protocol and info
        if (arp != null)
        {
            record.Protocol = "ARP";
            record.Info = $"ARP {arp.Operation}: Who has {arp.TargetProtocolAddress}? Tell {arp.SenderProtocolAddress}";
        }
        else if (icmpv4 != null)
        {
            record.Protocol = "ICMP";
            record.Info = $"ICMP {icmpv4.TypeCode} id={icmpv4.Id} seq={icmpv4.Sequence}";
        }
        else if (icmpv6 != null)
        {
            record.Protocol = "ICMPv6";
            record.Info = $"ICMPv6 {icmpv6.Type}";
        }
        else if (tcp != null)
        {
            record.Protocol = "TCP";
            record.Info = BuildTcpInfo(tcp);
        }
        else if (udp != null)
        {
            record.Protocol = "UDP";
            record.Info = $"{udp.SourcePort} -> {udp.DestinationPort} Len={udp.Length}";
        }
        else if (ipv4 != null)
        {
            record.Protocol = "IPv4";
            record.Info = $"Protocol={ipv4.Protocol}";
        }
        else if (ipv6 != null)
        {
            record.Protocol = "IPv6";
            record.Info = $"Next Header={ipv6.NextHeader}";
        }
        else
        {
            record.Protocol = packet.GetType().Name.Replace("Packet", "");
            record.Info = $"{record.Length} bytes";
        }
    }

    private static string BuildTcpInfo(TcpPacket tcp)
    {
        var flags = new List<string>();
        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Push) flags.Add("PSH");
        if (tcp.Urgent) flags.Add("URG");

        var flagStr = flags.Count > 0 ? $"[{string.Join(", ", flags)}]" : "";
        return $"{tcp.SourcePort} -> {tcp.DestinationPort} {flagStr} Seq={tcp.SequenceNumber} Ack={tcp.AcknowledgmentNumber} Win={tcp.WindowSize} Len={tcp.PayloadData?.Length ?? 0}";
    }

    private static string BuildDnsInfo(UdpPacket udp)
    {
        var payload = udp.PayloadData;
        if (payload == null || payload.Length < 12)
            return "DNS (truncated)";

        var flags = (ushort)((payload[2] << 8) | payload[3]);
        var isResponse = (flags & 0x8000) != 0;
        var qdCount = (ushort)((payload[4] << 8) | payload[5]);

        if (qdCount > 0 && payload.Length > 12)
        {
            var name = DnsDissector.ParseDnsName(payload, 12, out _);
            return isResponse ? $"DNS Response: {name}" : $"DNS Query: {name}";
        }

        return isResponse ? "DNS Response" : "DNS Query";
    }
}
