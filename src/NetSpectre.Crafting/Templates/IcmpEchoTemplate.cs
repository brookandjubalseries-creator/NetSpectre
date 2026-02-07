namespace NetSpectre.Crafting.Templates;

public sealed class IcmpEchoTemplate : PacketTemplate
{
    public override string Name => "ICMP Echo Request";
    public override string Description => "ICMP Echo (ping) request packet.";

    public string SourceIp { get; set; } = "192.168.1.1";
    public string DestinationIp { get; set; } = "192.168.1.2";
    public ushort Id { get; set; } = 1;
    public ushort Sequence { get; set; } = 1;

    public override PacketBuilder Apply(PacketBuilder builder)
    {
        return builder
            .SetEthernet("00-11-22-33-44-55", "FF-FF-FF-FF-FF-FF")
            .SetIPv4(SourceIp, DestinationIp)
            .SetIcmpEchoRequest(Id, Sequence)
            .SetPayload(new byte[32]); // 32 bytes padding like standard ping
    }
}
