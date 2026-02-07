using System.Reactive.Linq;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Modules;
using Xunit;

namespace NetSpectre.Detection.Tests;

public class BruteForceDetectorTests
{
    private static PacketRecord MakeTcpPacket(string srcIp, string dstIp, int dstPort, string flags = "SYN")
    {
        var layers = new PacketLayers();
        var tcpLayer = new ProtocolLayer { Name = "Transmission Control Protocol" };
        tcpLayer.AddField("Source Port", "54321");
        tcpLayer.AddField("Destination Port", dstPort.ToString());
        tcpLayer.AddField("Flags", flags);
        layers.AddLayer(tcpLayer);

        return new PacketRecord
        {
            Protocol = "TCP",
            SourceAddress = srcIp,
            DestinationAddress = dstIp,
            Length = 64,
            Info = $"54321 -> {dstPort} [{flags}]",
            Layers = layers,
        };
    }

    [Fact]
    public void ProcessPacket_BelowThreshold_NoAlert()
    {
        var detector = new BruteForceDetector(warningThreshold: 10, criticalThreshold: 25);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 5; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 22));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_ExceedsWarningThreshold_WarningAlert()
    {
        var detector = new BruteForceDetector(warningThreshold: 5, criticalThreshold: 20);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 6; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 22));

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Warning);
        Assert.Contains(alerts, a => a.Title.Contains("SSH"));
    }

    [Fact]
    public void ProcessPacket_ExceedsCriticalThreshold_CriticalAlert()
    {
        var detector = new BruteForceDetector(warningThreshold: 5, criticalThreshold: 10);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 11; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 3389));

        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Critical);
        Assert.Contains(alerts, a => a.Title.Contains("RDP"));
    }

    [Fact]
    public void ProcessPacket_NonTargetPort_Ignored()
    {
        var detector = new BruteForceDetector(warningThreshold: 3, criticalThreshold: 5);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // Port 80 (HTTP) is not in the target list
        for (int i = 0; i < 20; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 80));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_NonTcpProtocol_Ignored()
    {
        var detector = new BruteForceDetector(warningThreshold: 3, criticalThreshold: 5);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 20; i++)
        {
            detector.ProcessPacket(new PacketRecord
            {
                Protocol = "UDP",
                SourceAddress = "10.0.0.100",
                DestinationAddress = "192.168.1.1",
            });
        }

        Assert.Empty(alerts);
    }

    [Fact]
    public void Reset_ClearsTracking()
    {
        var detector = new BruteForceDetector(warningThreshold: 5, criticalThreshold: 10);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 4; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 22));

        detector.Reset();
        alerts.Clear();

        // After reset, need to build up again from zero
        for (int i = 0; i < 4; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 22));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_DifferentTargetPorts_TrackedSeparately()
    {
        var detector = new BruteForceDetector(warningThreshold: 5, criticalThreshold: 10);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // 4 attempts to SSH, 4 attempts to RDP - neither exceeds threshold of 5
        for (int i = 0; i < 4; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 22));
        for (int i = 0; i < 4; i++)
            detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", 3389));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_AllTargetPorts_Detected()
    {
        var detector = new BruteForceDetector(warningThreshold: 3, criticalThreshold: 10);
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        var targetPorts = new[] { 22, 23, 3389, 3306, 5432, 445 };

        foreach (var port in targetPorts)
        {
            for (int i = 0; i < 4; i++)
                detector.ProcessPacket(MakeTcpPacket("10.0.0.100", "192.168.1.1", port));
        }

        // Each port should have triggered at least one alert
        Assert.True(alerts.Count >= targetPorts.Length);
    }
}
