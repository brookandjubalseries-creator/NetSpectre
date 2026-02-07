using NetSpectre.Core.Analysis;
using Xunit;

namespace NetSpectre.Core.Tests;

public class ProtocolStatisticsTests
{
    [Fact]
    public void RecordPacket_IncrementsTotals()
    {
        var stats = new ProtocolStatistics();

        stats.RecordPacket("TCP", "10.0.0.1", "10.0.0.2", 500);

        Assert.Equal(500, stats.TotalBytes);
        Assert.Equal(1, stats.TotalPackets);
    }

    [Fact]
    public void GetProtocolByteBreakdown_ReturnsCorrectValues()
    {
        var stats = new ProtocolStatistics();

        stats.RecordPacket("TCP", "10.0.0.1", "10.0.0.2", 300);
        stats.RecordPacket("TCP", "10.0.0.1", "10.0.0.2", 200);
        stats.RecordPacket("UDP", "10.0.0.1", "10.0.0.3", 100);

        var breakdown = stats.GetProtocolByteBreakdown();

        Assert.Equal(500, breakdown["TCP"]);
        Assert.Equal(100, breakdown["UDP"]);
    }

    [Fact]
    public void GetTopTalkers_ReturnsSortedByBytes()
    {
        var stats = new ProtocolStatistics();

        stats.RecordPacket("TCP", "10.0.0.1", "10.0.0.2", 100);
        stats.RecordPacket("TCP", "10.0.0.3", "10.0.0.2", 500);
        stats.RecordPacket("UDP", "10.0.0.4", "10.0.0.1", 200);

        var topTalkers = stats.GetTopTalkers(3);

        // 10.0.0.2 appears as dest in two packets: 100 + 500 = 600
        // 10.0.0.3 appears as source: 500
        // 10.0.0.1 appears as source (100) + dest (200) = 300
        // 10.0.0.4 appears as source: 200
        Assert.Equal("10.0.0.2", topTalkers[0].Key);
        Assert.Equal(600, topTalkers[0].Value);
    }

    [Fact]
    public void Clear_ResetsEverything()
    {
        var stats = new ProtocolStatistics();

        stats.RecordPacket("TCP", "10.0.0.1", "10.0.0.2", 500);
        stats.RecordPacket("UDP", "10.0.0.3", "10.0.0.4", 300);

        stats.Clear();

        Assert.Equal(0, stats.TotalBytes);
        Assert.Equal(0, stats.TotalPackets);
        Assert.Empty(stats.GetProtocolByteBreakdown());
        Assert.Empty(stats.GetProtocolPacketBreakdown());
        Assert.Empty(stats.GetTopTalkers());
        Assert.Empty(stats.GetBandwidthHistory());
    }

    [Fact]
    public void MultipleProtocols_TrackedCorrectly()
    {
        var stats = new ProtocolStatistics();

        stats.RecordPacket("TCP", "10.0.0.1", "10.0.0.2", 100);
        stats.RecordPacket("UDP", "10.0.0.1", "10.0.0.3", 200);
        stats.RecordPacket("ICMP", "10.0.0.1", "10.0.0.4", 50);
        stats.RecordPacket("TCP", "10.0.0.2", "10.0.0.1", 150);
        stats.RecordPacket("DNS", "10.0.0.1", "10.0.0.5", 75);

        var byteBreakdown = stats.GetProtocolByteBreakdown();
        var packetBreakdown = stats.GetProtocolPacketBreakdown();

        Assert.Equal(4, byteBreakdown.Count);
        Assert.Equal(250, byteBreakdown["TCP"]);
        Assert.Equal(200, byteBreakdown["UDP"]);
        Assert.Equal(50, byteBreakdown["ICMP"]);
        Assert.Equal(75, byteBreakdown["DNS"]);

        Assert.Equal(2, packetBreakdown["TCP"]);
        Assert.Equal(1, packetBreakdown["UDP"]);
        Assert.Equal(1, packetBreakdown["ICMP"]);
        Assert.Equal(1, packetBreakdown["DNS"]);

        Assert.Equal(575, stats.TotalBytes);
        Assert.Equal(5, stats.TotalPackets);
    }
}
