using NetSpectre.Core.Models;
using NetSpectre.Detection.Analyzers;
using NetSpectre.Detection.Modules;
using Xunit;

namespace NetSpectre.Detection.Tests;

public class ShannonEntropyTests
{
    [Fact]
    public void Calculate_LowEntropy_ReturnsLow()
    {
        var entropy = ShannonEntropy.Calculate("aaaaaaa");
        Assert.True(entropy < 0.5);
    }

    [Fact]
    public void Calculate_HighEntropy_ReturnsHigh()
    {
        var entropy = ShannonEntropy.Calculate("a8x3k9m2p7w4");
        Assert.True(entropy > 3.0);
    }

    [Fact]
    public void Calculate_Empty_ReturnsZero()
    {
        Assert.Equal(0, ShannonEntropy.Calculate(""));
    }

    [Fact]
    public void Calculate_NormalDomain_ModerateEntropy()
    {
        var entropy = ShannonEntropy.Calculate("google");
        Assert.True(entropy > 1.0 && entropy < 3.0);
    }
}

public class DnsAnomalyDetectorTests
{
    private static PacketRecord MakeDnsPacket(string queryName, string srcIp = "192.168.1.1")
    {
        var layers = new PacketLayers();
        var dnsLayer = new ProtocolLayer { Name = "Domain Name System" };
        dnsLayer.AddField("Query Name", queryName);
        layers.AddLayer(dnsLayer);

        return new PacketRecord
        {
            Protocol = "DNS",
            SourceAddress = srcIp,
            DestinationAddress = "8.8.8.8",
            Length = 72,
            Layers = layers,
        };
    }

    [Fact]
    public void ProcessPacket_NormalDomain_NoAlert()
    {
        var detector = new DnsAnomalyDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakeDnsPacket("www.google.com"));
        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_HighEntropyDomain_RaisesAlert()
    {
        var detector = new DnsAnomalyDetector(suspiciousEntropy: 2.0, highEntropy: 3.0, criticalEntropy: 4.0);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // High entropy subdomain
        detector.ProcessPacket(MakeDnsPacket("a8x3k9m2p7w4q5.malicious.com"));
        Assert.NotEmpty(alerts);
    }

    [Fact]
    public void ProcessPacket_LongLabel_DetectsTunneling()
    {
        var detector = new DnsAnomalyDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        var longLabel = new string('a', 45);
        detector.ProcessPacket(MakeDnsPacket($"{longLabel}.tunnel.com"));
        Assert.Contains(alerts, a => a.Title.Contains("Tunneling"));
    }

    [Fact]
    public void ProcessPacket_IgnoresNonDns()
    {
        var detector = new DnsAnomalyDetector(suspiciousEntropy: 0.1);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        var packet = new PacketRecord
        {
            Protocol = "TCP",
            SourceAddress = "192.168.1.1",
            DestinationAddress = "10.0.0.1"
        };
        detector.ProcessPacket(packet);
        Assert.Empty(alerts);
    }
}
