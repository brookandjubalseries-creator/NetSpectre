using System.Reactive.Linq;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Modules;
using Xunit;

namespace NetSpectre.Detection.Tests;

public class PortScanDetectorTests
{
    private static PacketRecord MakeTcpPacket(string srcIp, ushort dstPort, string flags = "SYN", string dstIp = "10.0.0.1")
    {
        var layers = new PacketLayers();
        var tcpLayer = new ProtocolLayer { Name = "Transmission Control Protocol" };
        tcpLayer.AddField("Source Port", "12345");
        tcpLayer.AddField("Destination Port", dstPort.ToString());
        tcpLayer.AddField("Flags", flags);
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
    public void ProcessPacket_BelowThreshold_NoAlert()
    {
        var detector = new PortScanDetector(infoThreshold: 10);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (ushort i = 0; i < 5; i++)
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", i));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_ReachesInfoThreshold_RaisesInfoAlert()
    {
        var detector = new PortScanDetector(infoThreshold: 5, warningThreshold: 15, criticalThreshold: 50);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (ushort i = 0; i < 6; i++)
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", i));

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Info);
    }

    [Fact]
    public void ProcessPacket_ReachesWarningThreshold_RaisesWarningAlert()
    {
        var detector = new PortScanDetector(infoThreshold: 5, warningThreshold: 10, criticalThreshold: 50);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (ushort i = 0; i < 11; i++)
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", i));

        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Warning);
    }

    [Fact]
    public void ProcessPacket_ReachesCriticalThreshold_RaisesCriticalAlert()
    {
        var detector = new PortScanDetector(infoThreshold: 5, warningThreshold: 10, criticalThreshold: 20);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (ushort i = 0; i < 21; i++)
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", i));

        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Critical);
    }

    [Fact]
    public void ProcessPacket_IgnoresNonTcp()
    {
        var detector = new PortScanDetector(infoThreshold: 3);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 20; i++)
        {
            detector.ProcessPacket(new PacketRecord
            {
                Protocol = "UDP",
                SourceAddress = "192.168.1.100",
                DestinationAddress = "10.0.0.1"
            });
        }

        Assert.Empty(alerts);
    }

    [Fact]
    public void ClassifyScanType_SynFlags_ReturnsSyn()
    {
        var entries = Enumerable.Range(0, 10)
            .Select(i => new PortScanDetector.PortScanEntry((ushort)i, "SYN", "10.0.0.1"))
            .ToList();

        Assert.Equal("SYN", PortScanDetector.ClassifyScanType(entries));
    }

    [Fact]
    public void ClassifyScanType_FinFlags_ReturnsFin()
    {
        var entries = Enumerable.Range(0, 10)
            .Select(i => new PortScanDetector.PortScanEntry((ushort)i, "FIN", "10.0.0.1"))
            .ToList();

        Assert.Equal("FIN", PortScanDetector.ClassifyScanType(entries));
    }

    [Fact]
    public void ClassifyScanType_NoFlags_ReturnsNull()
    {
        var entries = Enumerable.Range(0, 10)
            .Select(i => new PortScanDetector.PortScanEntry((ushort)i, "", "10.0.0.1"))
            .ToList();

        Assert.Equal("NULL", PortScanDetector.ClassifyScanType(entries));
    }

    [Fact]
    public void Reset_ClearsTracking()
    {
        var detector = new PortScanDetector(infoThreshold: 5);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (ushort i = 0; i < 4; i++)
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", i));

        detector.Reset();
        alerts.Clear();

        // After reset, need to build up again
        for (ushort i = 0; i < 4; i++)
            detector.ProcessPacket(MakeTcpPacket("192.168.1.100", i));

        Assert.Empty(alerts);
    }
}
