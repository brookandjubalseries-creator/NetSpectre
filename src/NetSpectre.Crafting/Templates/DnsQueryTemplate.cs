using System.Text;

namespace NetSpectre.Crafting.Templates;

public sealed class DnsQueryTemplate : PacketTemplate
{
    public override string Name => "DNS Query";
    public override string Description => "DNS A-record query via UDP port 53.";

    public string SourceIp { get; set; } = "192.168.1.1";
    public string DnsServer { get; set; } = "8.8.8.8";
    public string QueryName { get; set; } = "example.com";
    public ushort TransactionId { get; set; } = 0x1234;

    public override PacketBuilder Apply(PacketBuilder builder)
    {
        var dnsPayload = BuildDnsQuery();
        return builder
            .SetEthernet("00-11-22-33-44-55", "FF-FF-FF-FF-FF-FF")
            .SetIPv4(SourceIp, DnsServer)
            .SetUdp(53, 53)
            .SetPayload(dnsPayload);
    }

    private byte[] BuildDnsQuery()
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Transaction ID
        writer.Write((byte)(TransactionId >> 8));
        writer.Write((byte)(TransactionId & 0xFF));

        // Flags: standard query, recursion desired
        writer.Write((byte)0x01);
        writer.Write((byte)0x00);

        // Questions: 1, Answers: 0, Authority: 0, Additional: 0
        writer.Write((byte)0x00); writer.Write((byte)0x01);
        writer.Write((byte)0x00); writer.Write((byte)0x00);
        writer.Write((byte)0x00); writer.Write((byte)0x00);
        writer.Write((byte)0x00); writer.Write((byte)0x00);

        // Query name
        var labels = QueryName.Split('.');
        foreach (var label in labels)
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            writer.Write((byte)bytes.Length);
            writer.Write(bytes);
        }
        writer.Write((byte)0x00); // End of name

        // Type: A (1)
        writer.Write((byte)0x00); writer.Write((byte)0x01);
        // Class: IN (1)
        writer.Write((byte)0x00); writer.Write((byte)0x01);

        return ms.ToArray();
    }
}
