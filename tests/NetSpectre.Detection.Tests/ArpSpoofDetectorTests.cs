using System.Reactive.Linq;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Modules;
using Xunit;

namespace NetSpectre.Detection.Tests;

public class ArpSpoofDetectorTests
{
    private static PacketRecord MakeArpPacket(string ip, string mac, string dstIp = "0.0.0.0")
    {
        var layers = new PacketLayers();
        var arpLayer = new ProtocolLayer { Name = "Address Resolution Protocol" };
        arpLayer.AddField("Sender MAC address", mac);
        arpLayer.AddField("Sender IP address", ip);
        layers.AddLayer(arpLayer);

        return new PacketRecord
        {
            Protocol = "ARP",
            SourceAddress = ip,
            DestinationAddress = dstIp,
            Length = 42,
            Info = $"{mac} is at {ip}",
            Layers = layers,
        };
    }

    [Fact]
    public void ProcessPacket_NewIpMacMapping_NoAlert()
    {
        var detector = new ArpSpoofDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:01"));
        detector.ProcessPacket(MakeArpPacket("192.168.1.2", "AA:BB:CC:DD:EE:02"));
        detector.ProcessPacket(MakeArpPacket("192.168.1.3", "AA:BB:CC:DD:EE:03"));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_MacChangedForSameIp_WarningAlert()
    {
        var detector = new ArpSpoofDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:01"));
        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:99"));

        Assert.Single(alerts);
        Assert.Equal(AlertSeverity.Warning, alerts[0].Severity);
        Assert.Equal("ARP Spoofing Detected", alerts[0].Title);
        Assert.Contains("AA:BB:CC:DD:EE:01", alerts[0].Description);
        Assert.Contains("AA:BB:CC:DD:EE:99", alerts[0].Description);
    }

    [Fact]
    public void ProcessPacket_MultipleMacChanges_EscalatesToCritical()
    {
        var detector = new ArpSpoofDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // First mapping (no alert)
        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:01"));
        // Second MAC - first change (warning, 2 unique MACs in history)
        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:02"));
        // Third MAC - second change (critical, 3 unique MACs in 60s window)
        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:03"));

        Assert.Equal(2, alerts.Count);
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Critical);
    }

    [Fact]
    public void Reset_ClearsMappings()
    {
        var detector = new ArpSpoofDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:01"));
        detector.Reset();
        alerts.Clear();

        // After reset, same IP with different MAC should not trigger alert
        // because the original mapping was cleared
        detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:99"));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_NonArpPackets_Ignored()
    {
        var detector = new ArpSpoofDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        for (int i = 0; i < 20; i++)
        {
            detector.ProcessPacket(new PacketRecord
            {
                Protocol = "TCP",
                SourceAddress = "192.168.1.1",
                DestinationAddress = "10.0.0.1",
                Info = $"AA:BB:CC:DD:EE:{i:X2} is at 192.168.1.1",
            });
        }

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_SameMacRepeated_NoAlert()
    {
        var detector = new ArpSpoofDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // Same IP and same MAC repeated many times should not trigger
        for (int i = 0; i < 10; i++)
        {
            detector.ProcessPacket(MakeArpPacket("192.168.1.1", "AA:BB:CC:DD:EE:01"));
        }

        Assert.Empty(alerts);
    }
}
