using System.Reactive.Linq;
using System.Text;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Modules;
using Xunit;

namespace NetSpectre.Detection.Tests;

public class PayloadPatternDetectorTests
{
    private static PacketRecord MakePacketWithPayload(string payload, string protocol = "TCP")
    {
        return new PacketRecord
        {
            Protocol = protocol,
            SourceAddress = "10.0.0.100",
            DestinationAddress = "192.168.1.1",
            Length = payload.Length,
            RawData = Encoding.UTF8.GetBytes(payload),
        };
    }

    [Fact]
    public void ProcessPacket_SqlInjectionPattern_TriggersAlert()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakePacketWithPayload("SELECT * FROM users WHERE id=1 UNION SELECT username, password FROM admin"));

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Title == "SQL Injection Attempt");
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Warning);
    }

    [Fact]
    public void ProcessPacket_SqlInjectionOrEquals_TriggersAlert()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakePacketWithPayload("login?user=admin' OR 1=1 --"));

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Title == "SQL Injection Attempt");
    }

    [Fact]
    public void ProcessPacket_DirectoryTraversal_TriggersAlert()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakePacketWithPayload("GET /files/../../etc/passwd HTTP/1.1"));

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Title == "Directory Traversal");
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Warning);
    }

    [Fact]
    public void ProcessPacket_ShellCommandInjection_CriticalAlert()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakePacketWithPayload("input=test; cat /etc/passwd"));

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Title == "Shell Command Injection");
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Critical);
    }

    [Fact]
    public void ProcessPacket_Base64EncodedPayload_InfoAlert()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // A suspiciously long base64 string (50+ chars)
        var base64Payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            "This is a long string that will produce a base64 output over 50 characters for testing purposes"));
        detector.ProcessPacket(MakePacketWithPayload(base64Payload));

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Title == "Base64 Encoded Payload");
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Info);
    }

    [Fact]
    public void ProcessPacket_CleanPayload_NoAlert()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(MakePacketWithPayload("GET /index.html HTTP/1.1\r\nHost: example.com\r\n"));

        Assert.Empty(alerts);
    }

    [Fact]
    public void ProcessPacket_EmptyRawData_NoAlert()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.ProcessPacket(new PacketRecord
        {
            Protocol = "TCP",
            SourceAddress = "10.0.0.100",
            DestinationAddress = "192.168.1.1",
            RawData = Array.Empty<byte>(),
        });

        Assert.Empty(alerts);
    }

    [Fact]
    public void AddRule_CustomRule_CanBeMatched()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.AddRule(new SignatureRule(
            "Custom Test Rule",
            @"EVIL_PATTERN_\d+",
            AlertSeverity.Critical,
            "Custom malicious pattern detected"));

        detector.ProcessPacket(MakePacketWithPayload("This contains EVIL_PATTERN_42 in the data"));

        Assert.Contains(alerts, a => a.Title == "Custom Test Rule");
        Assert.Contains(alerts, a => a.Severity == AlertSeverity.Critical);
    }

    [Fact]
    public void RemoveRule_RuleRemoved_NoLongerMatches()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // Remove the SQL injection rule
        detector.RemoveRule("SQL Injection Attempt");

        detector.ProcessPacket(MakePacketWithPayload("SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"));

        Assert.DoesNotContain(alerts, a => a.Title == "SQL Injection Attempt");
    }

    [Fact]
    public void Reset_RestoresDefaultRules()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // Add a custom rule and then remove a default rule
        detector.AddRule(new SignatureRule(
            "Custom Rule",
            @"CUSTOM",
            AlertSeverity.Info,
            "Custom rule"));
        detector.RemoveRule("SQL Injection Attempt");

        detector.Reset();
        alerts.Clear();

        // After reset, SQL injection should work again
        detector.ProcessPacket(MakePacketWithPayload("OR 1=1"));

        Assert.Contains(alerts, a => a.Title == "SQL Injection Attempt");
    }

    [Fact]
    public void Reset_CustomRulesRemoved()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        detector.AddRule(new SignatureRule(
            "Custom Rule",
            @"CUSTOM_DATA",
            AlertSeverity.Info,
            "Custom rule"));

        detector.Reset();
        alerts.Clear();

        // After reset, custom rule should no longer match
        detector.ProcessPacket(MakePacketWithPayload("CUSTOM_DATA here"));

        Assert.DoesNotContain(alerts, a => a.Title == "Custom Rule");
    }

    [Fact]
    public void ProcessPacket_MatchedContentSnippet_TruncatedTo100Chars()
    {
        var detector = new PayloadPatternDetector();
        var alerts = new List<AlertRecord>();
        using var sub = detector.AlertStream.Subscribe(a => alerts.Add(a));

        // Create a very long base64 string to trigger the Base64 rule with a long match
        var longPayload = new string('A', 200) + "==";
        detector.ProcessPacket(MakePacketWithPayload(longPayload));

        Assert.NotEmpty(alerts);
        var base64Alert = alerts.First(a => a.Title == "Base64 Encoded Payload");
        Assert.True(base64Alert.Metadata["MatchedContent"].Length <= 100);
    }
}
