using System.Reactive.Linq;
using System.Reactive.Subjects;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Utilities;

namespace NetSpectre.Detection.Modules;

public sealed class PortScanDetector : IDetectionModule
{
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly Dictionary<string, SlidingWindow<PortScanEntry>> _sourceWindows = new();
    private readonly TimeSpan _windowSize;
    private readonly int _infoThreshold;
    private readonly int _warningThreshold;
    private readonly int _criticalThreshold;

    public string Name => "Port Scan Detector";
    public string Description => "Detects horizontal port scanning by tracking unique destination ports per source IP";
    public bool IsEnabled { get; set; } = true;
    public IObservable<AlertRecord> AlertStream => _alertSubject.AsObservable();

    public PortScanDetector(
        TimeSpan? windowSize = null,
        int infoThreshold = 10,
        int warningThreshold = 20,
        int criticalThreshold = 50)
    {
        _windowSize = windowSize ?? TimeSpan.FromSeconds(60);
        _infoThreshold = infoThreshold;
        _warningThreshold = warningThreshold;
        _criticalThreshold = criticalThreshold;
    }

    public void ProcessPacket(PacketRecord packet)
    {
        if (!IsEnabled) return;

        // Only track TCP packets
        if (!packet.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase)) return;

        var srcIp = packet.SourceAddress;
        if (string.IsNullOrEmpty(srcIp)) return;

        // Extract destination port and TCP flags from layers
        var tcpLayer = packet.Layers.GetLayer("Transmission Control Protocol");
        if (tcpLayer is null) return;

        var dstPortField = tcpLayer.Fields.FirstOrDefault(f => f.Name == "Destination Port");
        var flagsField = tcpLayer.Fields.FirstOrDefault(f => f.Name == "Flags");
        if (dstPortField is null) return;

        if (!ushort.TryParse(dstPortField.Value, out var dstPort)) return;
        var flags = flagsField?.Value ?? "";

        var entry = new PortScanEntry(dstPort, flags, packet.DestinationAddress);

        if (!_sourceWindows.TryGetValue(srcIp, out var window))
        {
            window = new SlidingWindow<PortScanEntry>(_windowSize);
            _sourceWindows[srcIp] = window;
        }

        window.Add(entry);

        // Count unique destination ports
        var entries = window.GetValues();
        var uniquePorts = entries.Select(e => e.DestPort).Distinct().Count();

        var severity = GetSeverity(uniquePorts);
        if (severity is null) return;

        var scanType = ClassifyScanType(entries);

        _alertSubject.OnNext(new AlertRecord
        {
            Timestamp = DateTime.UtcNow,
            Severity = severity.Value,
            DetectorName = Name,
            Title = $"{scanType} Port Scan Detected",
            Description = $"Source {srcIp} scanned {uniquePorts} unique ports in {_windowSize.TotalSeconds}s",
            SourceAddress = srcIp,
            DestinationAddress = packet.DestinationAddress,
            Metadata = new Dictionary<string, string>
            {
                ["UniquePortCount"] = uniquePorts.ToString(),
                ["ScanType"] = scanType,
                ["WindowSeconds"] = _windowSize.TotalSeconds.ToString(),
            }
        });
    }

    public void Reset()
    {
        _sourceWindows.Clear();
    }

    private AlertSeverity? GetSeverity(int uniquePorts)
    {
        if (uniquePorts >= _criticalThreshold) return AlertSeverity.Critical;
        if (uniquePorts >= _warningThreshold) return AlertSeverity.Warning;
        if (uniquePorts >= _infoThreshold) return AlertSeverity.Info;
        return null;
    }

    internal static string ClassifyScanType(IReadOnlyList<PortScanEntry> entries)
    {
        if (entries.Count == 0) return "Unknown";

        var flagCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            var normalized = NormalizeFlags(e.Flags);
            flagCounts.TryGetValue(normalized, out var count);
            flagCounts[normalized] = count + 1;
        }

        var dominant = flagCounts.OrderByDescending(kv => kv.Value).First().Key;

        return dominant switch
        {
            "SYN" => "SYN",
            "FIN" => "FIN",
            "FIN, PSH, URG" or "URG, PSH, FIN" => "XMAS",
            "" => "NULL",
            "ACK" => "ACK",
            _ => "TCP Connect"
        };
    }

    private static string NormalizeFlags(string flags)
    {
        var parts = flags.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        Array.Sort(parts, StringComparer.OrdinalIgnoreCase);
        return string.Join(", ", parts);
    }

    internal sealed record PortScanEntry(ushort DestPort, string Flags, string DestAddress);
}
