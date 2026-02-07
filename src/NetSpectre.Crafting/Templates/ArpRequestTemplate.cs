using PacketDotNet;

namespace NetSpectre.Crafting.Templates;

public sealed class ArpRequestTemplate : PacketTemplate
{
    public override string Name => "ARP Request";
    public override string Description => "ARP Who-Has request to resolve an IP to a MAC address.";

    public string SenderMac { get; set; } = "00-11-22-33-44-55";
    public string SenderIp { get; set; } = "192.168.1.1";
    public string TargetIp { get; set; } = "192.168.1.2";

    public override PacketBuilder Apply(PacketBuilder builder)
    {
        return builder
            .SetEthernet(SenderMac, "FF-FF-FF-FF-FF-FF", EthernetType.Arp)
            .SetArp(ArpOperation.Request, SenderMac, SenderIp, "00-00-00-00-00-00", TargetIp);
    }
}
