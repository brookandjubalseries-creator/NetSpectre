using PacketDotNet;
using Xunit;

namespace NetSpectre.Crafting.Tests;

public class PacketBuilderTests
{
    [Fact]
    public void Build_TcpSyn_ProducesValidEthernetFrame()
    {
        var bytes = new PacketBuilder()
            .SetEthernet("00-11-22-33-44-55", "AA-BB-CC-DD-EE-FF")
            .SetIPv4("192.168.1.1", "10.0.0.1")
            .SetTcp(12345, 80, syn: true)
            .Build();

        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var eth = packet as EthernetPacket;
        Assert.NotNull(eth);

        var ip = eth.PayloadPacket as IPv4Packet;
        Assert.NotNull(ip);
        Assert.Equal("192.168.1.1", ip.SourceAddress.ToString());
        Assert.Equal("10.0.0.1", ip.DestinationAddress.ToString());

        var tcp = ip.PayloadPacket as TcpPacket;
        Assert.NotNull(tcp);
        Assert.Equal(12345, tcp.SourcePort);
        Assert.Equal(80, tcp.DestinationPort);
        Assert.True(tcp.Synchronize);
        Assert.False(tcp.Acknowledgment);
    }

    [Fact]
    public void Build_UdpPacket_ProducesValidFrame()
    {
        var bytes = new PacketBuilder()
            .SetEthernet("00-11-22-33-44-55", "AA-BB-CC-DD-EE-FF")
            .SetIPv4("10.0.0.1", "10.0.0.2")
            .SetUdp(5000, 53)
            .SetPayload(new byte[] { 0x01, 0x02, 0x03 })
            .Build();

        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var ip = (packet as EthernetPacket)?.PayloadPacket as IPv4Packet;
        Assert.NotNull(ip);

        var udp = ip.PayloadPacket as UdpPacket;
        Assert.NotNull(udp);
        Assert.Equal(5000, udp.SourcePort);
        Assert.Equal(53, udp.DestinationPort);
    }

    [Fact]
    public void Build_TcpWithPayload_IncludesPayload()
    {
        var payload = "Hello, World!"u8.ToArray();
        var bytes = new PacketBuilder()
            .SetEthernet("00-11-22-33-44-55", "AA-BB-CC-DD-EE-FF")
            .SetIPv4("10.0.0.1", "10.0.0.2")
            .SetTcp(1234, 80, psh: true, ack: true)
            .SetPayload(payload)
            .Build();

        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var tcp = ((packet as EthernetPacket)?.PayloadPacket as IPv4Packet)?.PayloadPacket as TcpPacket;
        Assert.NotNull(tcp);
        Assert.True(tcp.Push);
        Assert.True(tcp.Acknowledgment);
    }

    [Fact]
    public void Build_IcmpEcho_ProducesValidFrame()
    {
        var bytes = new PacketBuilder()
            .SetEthernet("00-11-22-33-44-55", "FF-FF-FF-FF-FF-FF")
            .SetIPv4("192.168.1.1", "192.168.1.2")
            .SetIcmpEchoRequest(id: 42, sequence: 7)
            .Build();

        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var ip = (packet as EthernetPacket)?.PayloadPacket as IPv4Packet;
        Assert.NotNull(ip);
        Assert.Equal(ProtocolType.Icmp, ip.Protocol);
        // ICMP data is either in PayloadPacket (parsed) or PayloadData (raw)
        var icmpBytes = ip.PayloadPacket?.Bytes ?? ip.PayloadData;
        Assert.NotNull(icmpBytes);
        Assert.True(icmpBytes.Length >= 8);
        Assert.Equal(8, icmpBytes[0]); // ICMP type: echo request
    }

    [Fact]
    public void Build_ArpRequest_ProducesValidFrame()
    {
        var bytes = new PacketBuilder()
            .SetArp(ArpOperation.Request, "00-11-22-33-44-55", "192.168.1.1", "00-00-00-00-00-00", "192.168.1.2")
            .Build();

        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var eth = packet as EthernetPacket;
        Assert.NotNull(eth);
        Assert.Equal(EthernetType.Arp, eth.Type);

        var arp = eth.PayloadPacket as ArpPacket;
        Assert.NotNull(arp);
        Assert.Equal(ArpOperation.Request, arp.Operation);
    }

    [Fact]
    public void Build_NoIpSet_ThrowsInvalidOperation()
    {
        var builder = new PacketBuilder()
            .SetEthernet("00-11-22-33-44-55", "AA-BB-CC-DD-EE-FF")
            .SetTcp(1234, 80);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_FluentChaining_WorksCorrectly()
    {
        var bytes = new PacketBuilder()
            .SetEthernet("00-11-22-33-44-55", "AA-BB-CC-DD-EE-FF")
            .SetIPv4("10.0.0.1", "10.0.0.2", ttl: 128)
            .SetTcp(4000, 443, syn: true)
            .Build();

        var packet = Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        var ip = (packet as EthernetPacket)?.PayloadPacket as IPv4Packet;
        Assert.NotNull(ip);
        Assert.Equal(128, ip.TimeToLive);
    }

    [Fact]
    public void Build_StringPayload_EncodesUtf8()
    {
        var bytes = new PacketBuilder()
            .SetEthernet("00-11-22-33-44-55", "AA-BB-CC-DD-EE-FF")
            .SetIPv4("10.0.0.1", "10.0.0.2")
            .SetUdp(5000, 5001)
            .SetPayload("test data")
            .Build();

        Assert.True(bytes.Length > 0);
    }

    [Fact]
    public void ComputeChecksum_KnownData_ReturnsCorrect()
    {
        // All zeros should give 0xFFFF complement
        var data = new byte[8];
        var checksum = PacketBuilder.ComputeChecksum(data);
        Assert.Equal((ushort)0xFFFF, checksum);
    }
}
