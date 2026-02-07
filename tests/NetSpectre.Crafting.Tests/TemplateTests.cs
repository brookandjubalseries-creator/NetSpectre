using NetSpectre.Crafting.Templates;
using PacketDotNet;
using Xunit;

namespace NetSpectre.Crafting.Tests;

public class TemplateTests
{
    [Fact]
    public void ArpRequestTemplate_Build_ProducesArpPacket()
    {
        var template = new ArpRequestTemplate
        {
            SenderMac = "00-11-22-33-44-55",
            SenderIp = "192.168.1.1",
            TargetIp = "192.168.1.2",
        };

        var bytes = template.Build();
        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var eth = packet as EthernetPacket;

        Assert.NotNull(eth);
        Assert.Equal(EthernetType.Arp, eth.Type);
    }

    [Fact]
    public void IcmpEchoTemplate_Build_ProducesIcmpPacket()
    {
        var template = new IcmpEchoTemplate
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            Id = 100,
            Sequence = 5,
        };

        var bytes = template.Build();
        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var ip = (packet as EthernetPacket)?.PayloadPacket as IPv4Packet;

        Assert.NotNull(ip);
        Assert.Equal(ProtocolType.Icmp, ip.Protocol);
    }

    [Fact]
    public void TcpSynTemplate_Build_ProducesSynPacket()
    {
        var template = new TcpSynTemplate
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 4000,
            DestinationPort = 443,
        };

        var bytes = template.Build();
        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var tcp = ((packet as EthernetPacket)?.PayloadPacket as IPv4Packet)?.PayloadPacket as TcpPacket;

        Assert.NotNull(tcp);
        Assert.True(tcp.Synchronize);
        Assert.Equal(4000, tcp.SourcePort);
        Assert.Equal(443, tcp.DestinationPort);
    }

    [Fact]
    public void DnsQueryTemplate_Build_ProducesUdpPacket()
    {
        var template = new DnsQueryTemplate
        {
            SourceIp = "192.168.1.1",
            DnsServer = "8.8.8.8",
            QueryName = "example.com",
        };

        var bytes = template.Build();
        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var udp = ((packet as EthernetPacket)?.PayloadPacket as IPv4Packet)?.PayloadPacket as UdpPacket;

        Assert.NotNull(udp);
        Assert.True(udp.PayloadData.Length > 0);
    }

    [Fact]
    public void HttpGetTemplate_Build_ProducesTcpPacket()
    {
        var template = new HttpGetTemplate
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            Host = "example.com",
            Path = "/index.html",
        };

        var bytes = template.Build();
        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var tcp = ((packet as EthernetPacket)?.PayloadPacket as IPv4Packet)?.PayloadPacket as TcpPacket;

        Assert.NotNull(tcp);
        Assert.Equal(80, tcp.DestinationPort);
        Assert.True(tcp.Push);
    }

    [Fact]
    public void PacketCraftingService_GetTemplateNames_ReturnsAllFive()
    {
        var service = new PacketCraftingService();
        var names = service.GetTemplateNames();

        Assert.Equal(5, names.Count);
        Assert.Contains("ARP Request", names);
        Assert.Contains("ICMP Echo Request", names);
        Assert.Contains("TCP SYN", names);
        Assert.Contains("DNS Query", names);
        Assert.Contains("HTTP GET", names);
    }

    [Fact]
    public void PacketCraftingService_BuildFromTemplate_ReturnsBytes()
    {
        var service = new PacketCraftingService();
        var bytes = service.BuildFromTemplate("TCP SYN");
        Assert.True(bytes.Length > 0);
    }

    [Fact]
    public void PacketCraftingService_BuildFromTemplate_UnknownThrows()
    {
        var service = new PacketCraftingService();
        Assert.Throws<ArgumentException>(() => service.BuildFromTemplate("Nonexistent"));
    }

    [Fact]
    public void PacketCraftingService_GetTemplate_ReturnsTemplate()
    {
        var service = new PacketCraftingService();
        var template = service.GetTemplate("TCP SYN");
        Assert.NotNull(template);
        Assert.Equal("TCP SYN", template.Name);
    }

    [Fact]
    public void PacketCraftingService_GetTemplate_UnknownReturnsNull()
    {
        var service = new PacketCraftingService();
        Assert.Null(service.GetTemplate("Nonexistent"));
    }

    [Fact]
    public void AllTemplates_HaveNameAndDescription()
    {
        PacketTemplate[] templates =
        [
            new ArpRequestTemplate(),
            new IcmpEchoTemplate(),
            new TcpSynTemplate(),
            new DnsQueryTemplate(),
            new HttpGetTemplate(),
        ];

        foreach (var t in templates)
        {
            Assert.False(string.IsNullOrWhiteSpace(t.Name));
            Assert.False(string.IsNullOrWhiteSpace(t.Description));
        }
    }
}
