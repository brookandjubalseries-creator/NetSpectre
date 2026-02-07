using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;

namespace NetSpectre.Crafting;

public sealed class PacketBuilder
{
    private PhysicalAddress _srcMac = PhysicalAddress.Parse("00-00-00-00-00-00");
    private PhysicalAddress _dstMac = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");
    private EthernetType _ethernetType = EthernetType.IPv4;

    private IPAddress? _srcIp;
    private IPAddress? _dstIp;
    private byte _ttl = 64;

    private ushort _srcPort;
    private ushort _dstPort;

    private bool _syn;
    private bool _ack;
    private bool _fin;
    private bool _rst;
    private bool _psh;

    private TransportProtocol _transport = TransportProtocol.Tcp;
    private byte[]? _payload;

    private bool _isIcmp;
    private ushort _icmpId = 1;
    private ushort _icmpSeq = 1;

    private bool _isArp;
    private ArpOperation _arpOp = ArpOperation.Request;
    private PhysicalAddress? _arpSenderMac;
    private IPAddress? _arpSenderIp;
    private PhysicalAddress? _arpTargetMac;
    private IPAddress? _arpTargetIp;

    public enum TransportProtocol { Tcp, Udp }

    public PacketBuilder SetEthernet(string srcMac, string dstMac, EthernetType type = EthernetType.IPv4)
    {
        _srcMac = PhysicalAddress.Parse(srcMac.Replace(':', '-').ToUpperInvariant());
        _dstMac = PhysicalAddress.Parse(dstMac.Replace(':', '-').ToUpperInvariant());
        _ethernetType = type;
        return this;
    }

    public PacketBuilder SetIPv4(string srcIp, string dstIp, byte ttl = 64)
    {
        _srcIp = IPAddress.Parse(srcIp);
        _dstIp = IPAddress.Parse(dstIp);
        _ttl = ttl;
        _isArp = false;
        _isIcmp = false;
        return this;
    }

    public PacketBuilder SetTcp(ushort srcPort, ushort dstPort, bool syn = false, bool ack = false, bool fin = false, bool rst = false, bool psh = false)
    {
        _transport = TransportProtocol.Tcp;
        _srcPort = srcPort;
        _dstPort = dstPort;
        _syn = syn;
        _ack = ack;
        _fin = fin;
        _rst = rst;
        _psh = psh;
        _isIcmp = false;
        _isArp = false;
        return this;
    }

    public PacketBuilder SetUdp(ushort srcPort, ushort dstPort)
    {
        _transport = TransportProtocol.Udp;
        _srcPort = srcPort;
        _dstPort = dstPort;
        _isIcmp = false;
        _isArp = false;
        return this;
    }

    public PacketBuilder SetIcmpEchoRequest(ushort id = 1, ushort sequence = 1)
    {
        _isIcmp = true;
        _isArp = false;
        _icmpId = id;
        _icmpSeq = sequence;
        return this;
    }

    public PacketBuilder SetArp(ArpOperation operation, string senderMac, string senderIp, string targetMac, string targetIp)
    {
        _isArp = true;
        _isIcmp = false;
        _arpOp = operation;
        _arpSenderMac = PhysicalAddress.Parse(senderMac.Replace(':', '-').ToUpperInvariant());
        _arpSenderIp = IPAddress.Parse(senderIp);
        _arpTargetMac = PhysicalAddress.Parse(targetMac.Replace(':', '-').ToUpperInvariant());
        _arpTargetIp = IPAddress.Parse(targetIp);
        _ethernetType = EthernetType.Arp;
        return this;
    }

    public PacketBuilder SetPayload(byte[] data)
    {
        _payload = data;
        return this;
    }

    public PacketBuilder SetPayload(string text)
    {
        _payload = System.Text.Encoding.UTF8.GetBytes(text);
        return this;
    }

    public byte[] Build()
    {
        if (_isArp)
            return BuildArp();

        if (_srcIp == null || _dstIp == null)
            throw new InvalidOperationException("IPv4 source and destination addresses are required.");

        var ipPacket = new IPv4Packet(_srcIp, _dstIp)
        {
            TimeToLive = _ttl,
        };

        if (_isIcmp)
        {
            return BuildIcmp(ipPacket);
        }

        Packet transportPacket;
        if (_transport == TransportProtocol.Tcp)
        {
            var tcp = new TcpPacket(_srcPort, _dstPort)
            {
                Synchronize = _syn,
                Acknowledgment = _ack,
                Finished = _fin,
                Reset = _rst,
                Push = _psh,
                WindowSize = 65535,
            };
            if (_payload != null)
                tcp.PayloadData = _payload;
            transportPacket = tcp;
        }
        else
        {
            var udp = new UdpPacket(_srcPort, _dstPort);
            if (_payload != null)
                udp.PayloadData = _payload;
            transportPacket = udp;
        }

        ipPacket.PayloadPacket = transportPacket;

        var eth = new EthernetPacket(_srcMac, _dstMac, _ethernetType)
        {
            PayloadPacket = ipPacket,
        };

        if (_transport == TransportProtocol.Tcp)
            ((TcpPacket)transportPacket).UpdateTcpChecksum();
        else
            ((UdpPacket)transportPacket).UpdateUdpChecksum();

        ipPacket.UpdateIPChecksum();

        return eth.Bytes;
    }

    private byte[] BuildIcmp(IPv4Packet ipPacket)
    {
        // Build ICMP echo request manually: type=8, code=0, checksum, id, seq, optional payload
        var icmpData = new byte[8 + (_payload?.Length ?? 0)];
        icmpData[0] = 8; // Type: Echo Request
        icmpData[1] = 0; // Code
        // Checksum placeholder at [2..3]
        icmpData[4] = (byte)(_icmpId >> 8);
        icmpData[5] = (byte)(_icmpId & 0xFF);
        icmpData[6] = (byte)(_icmpSeq >> 8);
        icmpData[7] = (byte)(_icmpSeq & 0xFF);

        if (_payload != null)
            Buffer.BlockCopy(_payload, 0, icmpData, 8, _payload.Length);

        // Calculate ICMP checksum
        var checksum = ComputeChecksum(icmpData);
        icmpData[2] = (byte)(checksum >> 8);
        icmpData[3] = (byte)(checksum & 0xFF);

        ipPacket.Protocol = ProtocolType.Icmp;
        ipPacket.PayloadData = icmpData;

        var eth = new EthernetPacket(_srcMac, _dstMac, _ethernetType)
        {
            PayloadPacket = ipPacket,
        };

        ipPacket.UpdateIPChecksum();
        return eth.Bytes;
    }

    private byte[] BuildArp()
    {
        var arp = new ArpPacket(_arpOp,
            _arpTargetMac ?? PhysicalAddress.Parse("00-00-00-00-00-00"),
            _arpTargetIp ?? IPAddress.Any,
            _arpSenderMac ?? _srcMac,
            _arpSenderIp ?? IPAddress.Any);

        var eth = new EthernetPacket(_srcMac, _dstMac, EthernetType.Arp)
        {
            PayloadPacket = arp,
        };

        return eth.Bytes;
    }

    internal static ushort ComputeChecksum(byte[] data)
    {
        uint sum = 0;
        for (int i = 0; i < data.Length - 1; i += 2)
            sum += (uint)(data[i] << 8 | data[i + 1]);
        if (data.Length % 2 != 0)
            sum += (uint)(data[^1] << 8);
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
