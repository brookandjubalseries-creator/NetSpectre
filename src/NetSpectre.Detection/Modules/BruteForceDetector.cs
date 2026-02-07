using System.Reactive.Linq;
using System.Reactive.Subjects;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Utilities;

namespace NetSpectre.Detection.Modules;

public sealed class BruteForceDetector : IDetectionModule
{
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly Dictionary<string, SlidingWindow<DateTime>> _connectionWindows = new();
    private readonly TimeSpan _windowSize;
    private readonly int _warningThreshold;
    private readonly int _criticalThreshold;

    private static readonly Dictionary<int, string> TargetPorts = new()
    {
        [22] = "SSH",
        [23] = "Telnet",
        [3389] = "RDP",
        [3306] = "MySQL",
        [5432] = "PostgreSQL",
        [445] = "SMB",
    };

    public string Name => "Brute Force Detector";
    public string Description => "Detects brute force login attempts by tracking connection frequency to authentication services";
    public bool IsEnabled { get; set; } = true;
    public IObservable<AlertRecord> AlertStream => _alertSubject.AsObservable();

    public BruteForceDetector(int windowSeconds = 60, int warningThreshold = 10, int criticalThreshold = 25)
    {
        _windowSize = TimeSpan.FromSeconds(windowSeconds);
        _warningThreshold = warningThreshold;
        _criticalThreshold = criticalThreshold;
    }

    public void ProcessPacket(PacketRecord packet)
    {
        if (!IsEnabled) return;

        if (!packet.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase)) return;

        var srcIp = packet.SourceAddress;
        var dstIp = packet.DestinationAddress;
        if (string.IsNullOrEmpty(srcIp) || string.IsNullOrEmpty(dstIp)) return;

        // Extract destination port from TCP layer
        var dstPort = ExtractDestinationPort(packet);
        if (dstPort is null) return;

        // Only track brute-force target ports
        if (!TargetPorts.ContainsKey(dstPort.Value)) return;

        // Build a composite key: sourceIP -> destIP:destPort
        var key = $"{srcIp}->{dstIp}:{dstPort.Value}";

        if (!_connectionWindows.TryGetValue(key, out var window))
        {
            window = new SlidingWindow<DateTime>(_windowSize);
            _connectionWindows[key] = window;
        }

        window.Add(DateTime.UtcNow);

        var count = window.Count;
        var severity = GetSeverity(count);
        if (severity is null) return;

        var serviceName = TargetPorts[dstPort.Value];

        _alertSubject.OnNext(new AlertRecord
        {
            Timestamp = DateTime.UtcNow,
            Severity = severity.Value,
            DetectorName = Name,
            Title = $"Brute Force Attack Detected ({serviceName})",
            Description = $"Source {srcIp} made {count} connection attempts to {dstIp}:{dstPort.Value} ({serviceName}) in {_windowSize.TotalSeconds}s",
            SourceAddress = srcIp,
            DestinationAddress = dstIp,
            Metadata = new Dictionary<string, string>
            {
                ["TargetPort"] = dstPort.Value.ToString(),
                ["ServiceName"] = serviceName,
                ["ConnectionCount"] = count.ToString(),
                ["WindowSeconds"] = _windowSize.TotalSeconds.ToString(),
            }
        });
    }

    public void Reset()
    {
        _connectionWindows.Clear();
    }

    private AlertSeverity? GetSeverity(int count)
    {
        if (count >= _criticalThreshold) return AlertSeverity.Critical;
        if (count >= _warningThreshold) return AlertSeverity.Warning;
        return null;
    }

    private static int? ExtractDestinationPort(PacketRecord packet)
    {
        // Try to get from TCP layer fields
        var tcpLayer = packet.Layers.GetLayer("Transmission Control Protocol");
        if (tcpLayer is not null)
        {
            var dstPortField = tcpLayer.Fields.FirstOrDefault(f => f.Name == "Destination Port");
            if (dstPortField is not null && int.TryParse(dstPortField.Value, out var port))
                return port;
        }

        // Fallback: try to parse from Info string (format like "12345 -> 22 [SYN]")
        if (!string.IsNullOrEmpty(packet.Info))
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                packet.Info, @"->\s*(\d+)");
            if (match.Success && int.TryParse(match.Groups[1].Value, out var port))
                return port;
        }

        return null;
    }
}
