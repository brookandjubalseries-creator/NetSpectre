using NetSpectre.Core.Models;

namespace NetSpectre.Core.Filtering;

public sealed class FilterFieldRegistry
{
    private readonly Dictionary<string, Func<PacketRecord, string?>> _fields = new(StringComparer.OrdinalIgnoreCase);

    public FilterFieldRegistry()
    {
        RegisterDefaults();
    }

    public void Register(string fieldName, Func<PacketRecord, string?> accessor)
    {
        _fields[fieldName] = accessor;
    }

    public string? GetFieldValue(PacketRecord packet, string fieldName)
    {
        return _fields.TryGetValue(fieldName, out var accessor) ? accessor(packet) : null;
    }

    public bool HasField(string fieldName) => _fields.ContainsKey(fieldName);

    private void RegisterDefaults()
    {
        // IP fields
        Register("ip.src", p => p.SourceAddress);
        Register("ip.dst", p => p.DestinationAddress);
        Register("ip.addr", p => p.SourceAddress); // simplified — in real Wireshark this matches either

        // TCP fields
        Register("tcp.srcport", p => GetLayerFieldValue(p, "Transmission Control Protocol", "Source Port"));
        Register("tcp.dstport", p => GetLayerFieldValue(p, "Transmission Control Protocol", "Destination Port"));
        Register("tcp.port", p =>
        {
            var src = GetLayerFieldValue(p, "Transmission Control Protocol", "Source Port");
            var dst = GetLayerFieldValue(p, "Transmission Control Protocol", "Destination Port");
            return src ?? dst;
        });
        Register("tcp.flags", p => GetLayerFieldValue(p, "Transmission Control Protocol", "Flags"));
        Register("tcp.seq", p => GetLayerFieldValue(p, "Transmission Control Protocol", "Sequence Number"));
        Register("tcp.ack", p => GetLayerFieldValue(p, "Transmission Control Protocol", "Acknowledgment Number"));
        Register("tcp.window", p => GetLayerFieldValue(p, "Transmission Control Protocol", "Window Size"));
        Register("tcp.len", p => GetLayerFieldValue(p, "Transmission Control Protocol", "Payload"));

        // UDP fields
        Register("udp.srcport", p => GetLayerFieldValue(p, "User Datagram Protocol", "Source Port"));
        Register("udp.dstport", p => GetLayerFieldValue(p, "User Datagram Protocol", "Destination Port"));
        Register("udp.port", p =>
        {
            var src = GetLayerFieldValue(p, "User Datagram Protocol", "Source Port");
            var dst = GetLayerFieldValue(p, "User Datagram Protocol", "Destination Port");
            return src ?? dst;
        });
        Register("udp.length", p => GetLayerFieldValue(p, "User Datagram Protocol", "Length"));

        // DNS fields
        Register("dns.qname", p => GetLayerFieldValue(p, "Domain Name System", "Query Name"));
        Register("dns.id", p => GetLayerFieldValue(p, "Domain Name System", "Transaction ID"));

        // ICMP fields
        Register("icmp.type", p => GetLayerFieldValue(p, "Internet Control Message Protocol", "Type"));
        Register("icmp.code", p => GetLayerFieldValue(p, "Internet Control Message Protocol", "Code"));

        // ARP fields
        Register("arp.src.proto", p => GetLayerFieldValue(p, "Address Resolution Protocol", "Sender IP"));
        Register("arp.dst.proto", p => GetLayerFieldValue(p, "Address Resolution Protocol", "Target IP"));

        // Ethernet fields
        Register("eth.src", p => GetLayerFieldValue(p, "Ethernet II", "Source MAC"));
        Register("eth.dst", p => GetLayerFieldValue(p, "Ethernet II", "Destination MAC"));

        // Generic fields
        Register("frame.len", p => p.Length.ToString());
        Register("frame.number", p => p.Number.ToString());
        Register("frame.protocols", p => p.Protocol);
    }

    private static string? GetLayerFieldValue(PacketRecord packet, string layerName, string fieldName)
    {
        var layer = packet.Layers.GetLayer(layerName);
        return layer?.Fields.FirstOrDefault(f => f.Name == fieldName)?.Value;
    }
}
