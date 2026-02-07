using NetSpectre.Core.Analysis;
using NetSpectre.Core.Models;
using Xunit;

namespace NetSpectre.Core.Tests;

public class TcpStreamReassemblerTests
{
    private static PacketRecord MakeTcpPacket(int number, string src, string dst, int srcPort, int dstPort)
    {
        var layers = new PacketLayers();
        layers.LayerStack.Add(new ProtocolLayer
        {
            Name = "TCP",
            Fields =
            {
                new ProtocolField { Name = "Source Port", Value = srcPort.ToString() },
                new ProtocolField { Name = "Destination Port", Value = dstPort.ToString() },
            }
        });
        return new PacketRecord
        {
            Number = number,
            Timestamp = DateTime.UtcNow,
            SourceAddress = src,
            DestinationAddress = dst,
            Protocol = "TCP",
            Length = 100,
            RawData = new byte[100],
            Layers = layers,
        };
    }

    [Fact]
    public void ProcessPacket_WithTcpPacket_CreatesStream()
    {
        var reassembler = new TcpStreamReassembler();
        var packet = MakeTcpPacket(1, "192.168.1.1", "10.0.0.1", 12345, 80);

        reassembler.ProcessPacket(packet);

        Assert.Equal(1, reassembler.StreamCount);
        var streams = reassembler.GetStreams();
        Assert.Single(streams);
        Assert.Equal("192.168.1.1", streams[0].ClientAddress);
        Assert.Equal(12345, streams[0].ClientPort);
        Assert.Equal("10.0.0.1", streams[0].ServerAddress);
        Assert.Equal(80, streams[0].ServerPort);
        Assert.Equal("HTTP", streams[0].Protocol);
    }

    [Fact]
    public void ProcessPacket_TwoPacketsSameConnection_GoToSameStream()
    {
        var reassembler = new TcpStreamReassembler();
        var packet1 = MakeTcpPacket(1, "192.168.1.1", "10.0.0.1", 12345, 443);
        var packet2 = MakeTcpPacket(2, "192.168.1.1", "10.0.0.1", 12345, 443);

        reassembler.ProcessPacket(packet1);
        reassembler.ProcessPacket(packet2);

        Assert.Equal(1, reassembler.StreamCount);
        var streams = reassembler.GetStreams();
        Assert.Single(streams);
        Assert.Equal(2, streams[0].PacketCount);
        Assert.Equal("HTTPS/TLS", streams[0].Protocol);
    }

    [Fact]
    public void ProcessPacket_BidirectionalPackets_GoToSameStream()
    {
        var reassembler = new TcpStreamReassembler();
        var clientToServer = MakeTcpPacket(1, "192.168.1.1", "10.0.0.1", 12345, 80);
        var serverToClient = MakeTcpPacket(2, "10.0.0.1", "192.168.1.1", 80, 12345);

        reassembler.ProcessPacket(clientToServer);
        reassembler.ProcessPacket(serverToClient);

        Assert.Equal(1, reassembler.StreamCount);
        var streams = reassembler.GetStreams();
        Assert.Single(streams);
        Assert.Equal(2, streams[0].PacketCount);

        // First segment should be from client, second from server
        Assert.True(streams[0].Segments[0].IsFromClient);
        Assert.False(streams[0].Segments[1].IsFromClient);
    }

    [Fact]
    public void ProcessPacket_NonTcpPacket_IsIgnored()
    {
        var reassembler = new TcpStreamReassembler();
        var udpPacket = new PacketRecord
        {
            Number = 1,
            Timestamp = DateTime.UtcNow,
            SourceAddress = "192.168.1.1",
            DestinationAddress = "10.0.0.1",
            Protocol = "UDP",
            Length = 100,
            RawData = new byte[100],
            Layers = new PacketLayers(),
        };

        reassembler.ProcessPacket(udpPacket);

        Assert.Equal(0, reassembler.StreamCount);
    }

    [Fact]
    public void StreamCount_IncrementsCorrectly()
    {
        var reassembler = new TcpStreamReassembler();
        var packet1 = MakeTcpPacket(1, "192.168.1.1", "10.0.0.1", 12345, 80);
        var packet2 = MakeTcpPacket(2, "192.168.1.2", "10.0.0.2", 54321, 443);
        var packet3 = MakeTcpPacket(3, "172.16.0.1", "10.0.0.3", 11111, 22);

        Assert.Equal(0, reassembler.StreamCount);

        reassembler.ProcessPacket(packet1);
        Assert.Equal(1, reassembler.StreamCount);

        reassembler.ProcessPacket(packet2);
        Assert.Equal(2, reassembler.StreamCount);

        reassembler.ProcessPacket(packet3);
        Assert.Equal(3, reassembler.StreamCount);
    }

    [Fact]
    public void GetStreamForPacket_FindsCorrectStream()
    {
        var reassembler = new TcpStreamReassembler();
        var packet1 = MakeTcpPacket(1, "192.168.1.1", "10.0.0.1", 12345, 80);
        var packet2 = MakeTcpPacket(2, "192.168.1.2", "10.0.0.2", 54321, 443);

        reassembler.ProcessPacket(packet1);
        reassembler.ProcessPacket(packet2);

        var stream = reassembler.GetStreamForPacket(packet1);
        Assert.NotNull(stream);
        Assert.Equal("HTTP", stream.Protocol);
        Assert.Equal("192.168.1.1", stream.ClientAddress);

        var stream2 = reassembler.GetStreamForPacket(packet2);
        Assert.NotNull(stream2);
        Assert.Equal("HTTPS/TLS", stream2.Protocol);
        Assert.Equal("192.168.1.2", stream2.ClientAddress);
    }

    [Fact]
    public void Clear_RemovesAllStreams()
    {
        var reassembler = new TcpStreamReassembler();
        reassembler.ProcessPacket(MakeTcpPacket(1, "192.168.1.1", "10.0.0.1", 12345, 80));
        reassembler.ProcessPacket(MakeTcpPacket(2, "192.168.1.2", "10.0.0.2", 54321, 443));

        Assert.Equal(2, reassembler.StreamCount);

        reassembler.Clear();

        Assert.Equal(0, reassembler.StreamCount);
        Assert.Empty(reassembler.GetStreams());
    }

    [Fact]
    public void ProcessPacket_DifferentConnections_CreateDifferentStreams()
    {
        var reassembler = new TcpStreamReassembler();

        // Same hosts but different ports = different connections
        var packet1 = MakeTcpPacket(1, "192.168.1.1", "10.0.0.1", 12345, 80);
        var packet2 = MakeTcpPacket(2, "192.168.1.1", "10.0.0.1", 12346, 80);
        var packet3 = MakeTcpPacket(3, "192.168.1.1", "10.0.0.1", 12345, 443);

        reassembler.ProcessPacket(packet1);
        reassembler.ProcessPacket(packet2);
        reassembler.ProcessPacket(packet3);

        Assert.Equal(3, reassembler.StreamCount);

        var streams = reassembler.GetStreams();
        Assert.Equal(3, streams.Count);
    }
}
