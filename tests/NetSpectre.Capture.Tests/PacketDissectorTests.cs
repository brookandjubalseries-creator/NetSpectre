using System.Net;
using System.Net.NetworkInformation;
using NetSpectre.Capture.Dissectors;
using PacketDotNet;
using SharpPcap;
using Xunit;

namespace NetSpectre.Capture.Tests;

public class PacketDissectorTests
{
    private readonly PacketDissector _dissector = new();

    private static RawCapture CreateTcpRawCapture(
        string srcIp = "192.168.1.1",
        string dstIp = "10.0.0.1",
        ushort srcPort = 12345,
        ushort dstPort = 80,
        bool syn = false,
        bool ack = false)
    {
        var srcMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-01");
        var dstMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-02");

        var tcp = new TcpPacket(srcPort, dstPort)
        {
            Synchronize = syn,
            Acknowledgment = ack,
        };
        var ip = new IPv4Packet(IPAddress.Parse(srcIp), IPAddress.Parse(dstIp));
        var eth = new EthernetPacket(srcMac, dstMac, EthernetType.IPv4);
        ip.PayloadPacket = tcp;
        eth.PayloadPacket = ip;
        tcp.UpdateTcpChecksum();
        ip.UpdateIPChecksum();

        return new RawCapture(LinkLayers.Ethernet, new PosixTimeval(DateTime.UtcNow), eth.Bytes);
    }

    private static RawCapture CreateUdpRawCapture(
        string srcIp = "192.168.1.1",
        string dstIp = "10.0.0.1",
        ushort srcPort = 5000,
        ushort dstPort = 53,
        byte[]? payload = null)
    {
        var srcMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-01");
        var dstMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-02");

        var udp = new UdpPacket(srcPort, dstPort);
        if (payload != null)
            udp.PayloadData = payload;
        var ip = new IPv4Packet(IPAddress.Parse(srcIp), IPAddress.Parse(dstIp));
        var eth = new EthernetPacket(srcMac, dstMac, EthernetType.IPv4);
        ip.PayloadPacket = udp;
        eth.PayloadPacket = ip;
        udp.UpdateUdpChecksum();
        ip.UpdateIPChecksum();

        return new RawCapture(LinkLayers.Ethernet, new PosixTimeval(DateTime.UtcNow), eth.Bytes);
    }

    [Fact]
    public void Dissect_TcpSynPacket_ExtractsCorrectProtocol()
    {
        var raw = CreateTcpRawCapture(syn: true);
        var record = _dissector.Dissect(raw, 1);

        Assert.Equal("TCP", record.Protocol);
        Assert.Equal("192.168.1.1", record.SourceAddress);
        Assert.Equal("10.0.0.1", record.DestinationAddress);
        Assert.Contains("SYN", record.Info);
        Assert.Equal(1, record.Number);
    }

    [Fact]
    public void Dissect_TcpPacket_HasEthernetAndIpAndTcpLayers()
    {
        var raw = CreateTcpRawCapture(syn: true, ack: true);
        var record = _dissector.Dissect(raw, 1);

        Assert.NotNull(record.Layers.GetLayer("Ethernet II"));
        Assert.NotNull(record.Layers.GetLayer("Internet Protocol Version 4"));
        Assert.NotNull(record.Layers.GetLayer("Transmission Control Protocol"));
    }

    [Fact]
    public void Dissect_UdpPacket_ExtractsCorrectProtocol()
    {
        var raw = CreateUdpRawCapture(srcPort: 5000, dstPort: 8080);
        var record = _dissector.Dissect(raw, 2);

        Assert.Equal("UDP", record.Protocol);
        Assert.Equal("192.168.1.1", record.SourceAddress);
        Assert.Equal("10.0.0.1", record.DestinationAddress);
    }

    [Fact]
    public void Dissect_DnsQuery_IdentifiesAsDns()
    {
        // Build a minimal DNS query payload for "example.com"
        var dnsPayload = new byte[]
        {
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Query: example.com
            0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            0x03, (byte)'c', (byte)'o', (byte)'m',
            0x00, // End
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        };

        var raw = CreateUdpRawCapture(dstPort: 53, payload: dnsPayload);
        var record = _dissector.Dissect(raw, 3);

        Assert.Equal("DNS", record.Protocol);
        Assert.Contains("example.com", record.Info);
    }

    [Fact]
    public void Dissect_ArpPacket_ExtractsCorrectProtocol()
    {
        var srcMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-01");
        var dstMac = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");

        var arp = new ArpPacket(
            ArpOperation.Request,
            PhysicalAddress.Parse("00-00-00-00-00-00"),
            IPAddress.Parse("10.0.0.1"),
            srcMac,
            IPAddress.Parse("192.168.1.1"));

        var eth = new EthernetPacket(srcMac, dstMac, EthernetType.Arp);
        eth.PayloadPacket = arp;

        var raw = new RawCapture(LinkLayers.Ethernet, new PosixTimeval(DateTime.UtcNow), eth.Bytes);
        var record = _dissector.Dissect(raw, 4);

        Assert.Equal("ARP", record.Protocol);
    }

    [Fact]
    public void Dissect_IcmpPacket_ExtractsCorrectProtocol()
    {
        var srcMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-01");
        var dstMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-02");

        var icmp = new IcmpV4Packet(new PacketDotNet.Utils.ByteArraySegment(new byte[8]));
        var ip = new IPv4Packet(IPAddress.Parse("192.168.1.1"), IPAddress.Parse("10.0.0.1"))
        {
            Protocol = ProtocolType.Icmp
        };
        var eth = new EthernetPacket(srcMac, dstMac, EthernetType.IPv4);
        ip.PayloadPacket = icmp;
        eth.PayloadPacket = ip;
        ip.UpdateIPChecksum();

        var raw = new RawCapture(LinkLayers.Ethernet, new PosixTimeval(DateTime.UtcNow), eth.Bytes);
        var record = _dissector.Dissect(raw, 5);

        Assert.Equal("ICMP", record.Protocol);
    }
}
