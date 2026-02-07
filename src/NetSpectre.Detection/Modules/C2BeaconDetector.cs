using System.Reactive.Linq;
using System.Reactive.Subjects;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Analyzers;
using NetSpectre.Detection.Utilities;

namespace NetSpectre.Detection.Modules;

public sealed class C2BeaconDetector : IDetectionModule
{
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly Dictionary<string, SlidingWindow<DateTime>> _connections = new();
    private readonly int _minConnections;
    private readonly double _criticalCvThreshold;
    private readonly double _warningCvThreshold;
    private readonly double _dbscanClusterRatio;

    public string Name => "C2 Beacon Detector";
    public string Description => "Detects command-and-control beaconing by analyzing connection periodicity";
    public bool IsEnabled { get; set; } = true;
    public IObservable<AlertRecord> AlertStream => _alertSubject.AsObservable();

    public C2BeaconDetector(
        int minConnections = 10,
        double criticalCvThreshold = 0.10,
        double warningCvThreshold = 0.15,
        double dbscanClusterRatio = 0.80)
    {
        _minConnections = minConnections;
        _criticalCvThreshold = criticalCvThreshold;
        _warningCvThreshold = warningCvThreshold;
        _dbscanClusterRatio = dbscanClusterRatio;
    }

    public void ProcessPacket(PacketRecord packet)
    {
        if (!IsEnabled) return;

        // Track TCP and UDP connections
        if (!packet.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) &&
            !packet.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
            return;

        var srcIp = packet.SourceAddress;
        var dstIp = packet.DestinationAddress;
        if (string.IsNullOrEmpty(srcIp) || string.IsNullOrEmpty(dstIp)) return;

        // Get destination port
        var layerName = packet.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase)
            ? "Transmission Control Protocol"
            : "User Datagram Protocol";

        var layer = packet.Layers.GetLayer(layerName);
        var dstPortField = layer?.Fields.FirstOrDefault(f => f.Name == "Destination Port");
        var dstPort = dstPortField?.Value ?? "0";

        var key = $"{srcIp}|{dstIp}|{dstPort}";

        if (!_connections.TryGetValue(key, out var window))
        {
            window = new SlidingWindow<DateTime>(TimeSpan.FromMinutes(10));
            _connections[key] = window;
        }

        window.Add(DateTime.UtcNow);

        var timestamps = window.GetValues();
        if (timestamps.Count < _minConnections) return;

        AnalyzeBeaconing(key, timestamps.ToList(), packet);
    }

    public void Reset()
    {
        _connections.Clear();
    }

    private void AnalyzeBeaconing(string connectionKey, List<DateTime> timestamps, PacketRecord packet)
    {
        var intervals = CoefficientOfVariation.ComputeInterArrivalTimes(timestamps);
        if (intervals.Count < 5) return;

        var cv = CoefficientOfVariation.Calculate(intervals.ToList());

        // Check CV
        if (cv <= _criticalCvThreshold)
        {
            EmitAlert(AlertSeverity.Critical, "C2 Beacon Detected",
                $"Connection {connectionKey} has CV={cv:F4} ({timestamps.Count} connections). Highly periodic.",
                packet, cv);
            return;
        }

        if (cv <= _warningCvThreshold)
        {
            EmitAlert(AlertSeverity.Warning, "Possible C2 Beacon",
                $"Connection {connectionKey} has CV={cv:F4} ({timestamps.Count} connections). Suspicious periodicity.",
                packet, cv);
            return;
        }

        // DBSCAN clustering as secondary check
        var dbscanRatio = SimpleDbscan.GetDominantClusterRatio(
            intervals.ToList(),
            epsilon: intervals.Average() * 0.1,
            minPoints: 3);

        if (dbscanRatio.HasValue && dbscanRatio.Value >= _dbscanClusterRatio)
        {
            EmitAlert(AlertSeverity.Info, "Potential C2 Beacon (Cluster Analysis)",
                $"Connection {connectionKey}: {dbscanRatio.Value:P0} of intervals in dominant cluster",
                packet, dbscanRatio.Value);
        }
    }

    private void EmitAlert(AlertSeverity severity, string title, string description,
        PacketRecord packet, double metricValue)
    {
        _alertSubject.OnNext(new AlertRecord
        {
            Timestamp = DateTime.UtcNow,
            Severity = severity,
            DetectorName = Name,
            Title = title,
            Description = description,
            SourceAddress = packet.SourceAddress,
            DestinationAddress = packet.DestinationAddress,
            Metadata = new Dictionary<string, string>
            {
                ["MetricValue"] = metricValue.ToString("F6"),
            }
        });
    }
}
