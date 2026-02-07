namespace NetSpectre.Crafting.Templates;

public sealed class TcpSynTemplate : PacketTemplate
{
    public override string Name => "TCP SYN";
    public override string Description => "TCP SYN packet to initiate a three-way handshake.";

    public string SourceIp { get; set; } = "192.168.1.1";
    public string DestinationIp { get; set; } = "192.168.1.2";
    public ushort SourcePort { get; set; } = 12345;
    public ushort DestinationPort { get; set; } = 80;

    public override PacketBuilder Apply(PacketBuilder builder)
    {
        return builder
            .SetEthernet("00-11-22-33-44-55", "FF-FF-FF-FF-FF-FF")
            .SetIPv4(SourceIp, DestinationIp)
            .SetTcp(SourcePort, DestinationPort, syn: true);
    }
}
