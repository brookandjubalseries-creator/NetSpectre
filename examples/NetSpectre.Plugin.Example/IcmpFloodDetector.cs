using System.Reactive.Subjects;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;

namespace NetSpectre.Plugin.Example;

public sealed class IcmpFloodDetector : IDetectionModule
{
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly Dictionary<string, List<DateTime>> _icmpTracker = new();
    private readonly TimeSpan _window = TimeSpan.FromSeconds(30);
    private readonly int _threshold;
    private int _nextAlertId;

    public string Name => "ICMP Flood Detector";
    public string Description => "Detects ICMP flood attacks (>100 ICMP packets from same source in 30s)";
    public bool IsEnabled { get; set; } = true;
    public IObservable<AlertRecord> AlertStream => _alertSubject;

    public IcmpFloodDetector(int threshold = 100)
    {
        _threshold = threshold;
    }

    public void ProcessPacket(PacketRecord packet)
    {
        if (!IsEnabled) return;
        if (!string.Equals(packet.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase))
            return;

        var source = packet.SourceAddress;
        if (string.IsNullOrEmpty(source)) return;

        if (!_icmpTracker.TryGetValue(source, out var timestamps))
        {
            timestamps = new List<DateTime>();
            _icmpTracker[source] = timestamps;
        }

        var now = DateTime.UtcNow;
        timestamps.Add(now);

        // Clean expired entries
        timestamps.RemoveAll(t => now - t > _window);

        if (timestamps.Count >= _threshold)
        {
            _alertSubject.OnNext(new AlertRecord
            {
                Id = Interlocked.Increment(ref _nextAlertId),
                Timestamp = now,
                Severity = AlertSeverity.Critical,
                DetectorName = Name,
                Title = "ICMP Flood Detected",
                Description = $"Source {source} sent {timestamps.Count} ICMP packets in {_window.TotalSeconds}s (threshold: {_threshold})",
                SourceAddress = source,
            });

            // Reset to avoid repeated alerts
            timestamps.Clear();
        }
    }

    public void Reset()
    {
        _icmpTracker.Clear();
    }
}
