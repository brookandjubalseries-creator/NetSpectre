using NetSpectre.Core.Models;
using NetSpectre.Detection.Analyzers;
using NetSpectre.Detection.Modules;
using Xunit;

namespace NetSpectre.Detection.Tests;

public class C2BeaconDetectorTests
{
    private static PacketRecord MakeTcpPacket(string srcIp, string dstIp, string dstPort)
    {
        var layers = new PacketLayers();
        var tcpLayer = new ProtocolLayer { Name = "Transmission Control Protocol" };
        tcpLayer.AddField("Source Port", "12345");
        tcpLayer.AddField("Destination Port", dstPort);
        layers.AddLayer(tcpLayer);

        return new PacketRecord
        {
            Protocol = "TCP",
            SourceAddress = srcIp,
            DestinationAddress = dstIp,
            Length = 64,
            Layers = layers,
        };
    }

    [Fact]
    public void ProcessPacket_FewConnections_NoAlert()
    {
        var detector = new C2BeaconDetector(minConnections: 10);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 5; i++)
        {
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", "10.0.0.1", "443"));
            Thread.Sleep(10);
        }

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_IgnoresNonTcpUdp()
    {
        var detector = new C2BeaconDetector(minConnections: 3);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 20; i++)
        {
            detector.ProcessPacket(new PacketRecord
            {
                Protocol = "ICMP",
                SourceAddress = "192.168.1.100",
                DestinationAddress = "10.0.0.1"
            });
        }

        Assert.Empty(alerts);
    }

    [Fact]
    public void Reset_ClearsTracking()
    {
        var detector = new C2BeaconDetector(minConnections: 5);
        for (int i = 0; i < 4; i++)
        {
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", "10.0.0.1", "443"));
            Thread.Sleep(10);
        }
        detector.Reset();

        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));
        for (int i = 0; i < 4; i++)
        {
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", "10.0.0.1", "443"));
            Thread.Sleep(10);
        }
        Assert.Empty(alerts);
    }
}

public class SimpleDbscanTests
{
    [Fact]
    public void Cluster_UniformPoints_SingleCluster()
    {
        var points = new List<double> { 10.0, 10.1, 10.2, 9.9, 10.05 };
        var clusters = SimpleDbscan.Cluster(points, epsilon: 0.5, minPoints: 2);
        Assert.Single(clusters);
    }

    [Fact]
    public void Cluster_TwoDistinctGroups_TwoClusters()
    {
        var points = new List<double> { 1.0, 1.1, 1.2, 10.0, 10.1, 10.2 };
        var clusters = SimpleDbscan.Cluster(points, epsilon: 0.5, minPoints: 2);
        Assert.Equal(2, clusters.Count);
    }

    [Fact]
    public void GetDominantClusterRatio_SingleCluster_ReturnsOne()
    {
        var points = new List<double> { 5.0, 5.1, 5.2, 5.0, 4.9 };
        var ratio = SimpleDbscan.GetDominantClusterRatio(points, epsilon: 0.5, minPoints: 2);
        Assert.NotNull(ratio);
        Assert.True(ratio >= 0.8);
    }

    [Fact]
    public void GetDominantClusterRatio_Empty_ReturnsNull()
    {
        var ratio = SimpleDbscan.GetDominantClusterRatio(new List<double>(), epsilon: 0.5, minPoints: 2);
        Assert.Null(ratio);
    }

    [Fact]
    public void CoefficientOfVariation_ConstantValues_ReturnsZero()
    {
        var values = new List<double> { 5.0, 5.0, 5.0, 5.0, 5.0 };
        var cv = CoefficientOfVariation.Calculate(values);
        Assert.True(cv < 0.01);
    }

    [Fact]
    public void CoefficientOfVariation_HighVariation_ReturnsHigh()
    {
        var values = new List<double> { 1.0, 100.0, 1.0, 100.0 };
        var cv = CoefficientOfVariation.Calculate(values);
        Assert.True(cv > 0.5);
    }

    [Fact]
    public void CoefficientOfVariation_SingleValue_ReturnsMax()
    {
        var cv = CoefficientOfVariation.Calculate(new List<double> { 5.0 });
        Assert.Equal(double.MaxValue, cv);
    }
}
