using System.Reactive.Linq;
using System.Reactive.Subjects;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Analyzers;
using NetSpectre.Detection.Utilities;

namespace NetSpectre.Detection.Modules;

public sealed class DnsAnomalyDetector : IDetectionModule
{
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly Dictionary<string, SlidingWindow<bool>> _queryRates = new();
    private readonly double _suspiciousEntropyThreshold;
    private readonly double _highEntropyThreshold;
    private readonly double _criticalEntropyThreshold;

    public string Name => "DNS Anomaly Detector";
    public string Description => "Detects DNS tunneling, DGA domains, and anomalous DNS patterns";
    public bool IsEnabled { get; set; } = true;
    public IObservable<AlertRecord> AlertStream => _alertSubject.AsObservable();

    public DnsAnomalyDetector(
        double suspiciousEntropy = 3.1,
        double highEntropy = 4.0,
        double criticalEntropy = 4.5)
    {
        _suspiciousEntropyThreshold = suspiciousEntropy;
        _highEntropyThreshold = highEntropy;
        _criticalEntropyThreshold = criticalEntropy;
    }

    public void ProcessPacket(PacketRecord packet)
    {
        if (!IsEnabled) return;
        if (!packet.Protocol.Equals("DNS", StringComparison.OrdinalIgnoreCase)) return;

        var dnsLayer = packet.Layers.GetLayer("Domain Name System");
        if (dnsLayer is null) return;

        var queryNameField = dnsLayer.Fields.FirstOrDefault(f => f.Name == "Query Name");
        if (queryNameField is null) return;

        var queryName = queryNameField.Value;
        if (string.IsNullOrEmpty(queryName) || queryName == "<empty>") return;

        CheckEntropy(queryName, packet);
        CheckDga(queryName, packet);
        CheckTunneling(queryName, packet);
    }

    public void Reset()
    {
        _queryRates.Clear();
    }

    private void CheckEntropy(string queryName, PacketRecord packet)
    {
        // Calculate entropy on subdomain labels
        var parts = queryName.Split('.');
        if (parts.Length < 2) return;

        // Get all labels except TLD and SLD
        var subdomainLabels = parts.Length > 2
            ? string.Join("", parts.Take(parts.Length - 2))
            : parts[0];

        if (subdomainLabels.Length < 5) return;

        var entropy = ShannonEntropy.Calculate(subdomainLabels);

        if (entropy >= _criticalEntropyThreshold)
        {
            EmitAlert(AlertSeverity.Critical, "High Entropy DNS Query",
                $"Domain '{queryName}' has entropy {entropy:F2} (threshold: {_criticalEntropyThreshold})",
                packet, entropy);
        }
        else if (entropy >= _highEntropyThreshold)
        {
            EmitAlert(AlertSeverity.Warning, "Elevated Entropy DNS Query",
                $"Domain '{queryName}' has entropy {entropy:F2} (threshold: {_highEntropyThreshold})",
                packet, entropy);
        }
        else if (entropy >= _suspiciousEntropyThreshold)
        {
            EmitAlert(AlertSeverity.Info, "Suspicious Entropy DNS Query",
                $"Domain '{queryName}' has entropy {entropy:F2}",
                packet, entropy);
        }
    }

    private void CheckDga(string queryName, PacketRecord packet)
    {
        var score = DgaScorer.Score(queryName);
        var cvRatio = DgaScorer.GetConsonantVowelRatio(queryName.Split('.')[0]);

        if (score > 2.5 && cvRatio > 0.7)
        {
            EmitAlert(AlertSeverity.Warning, "Possible DGA Domain",
                $"Domain '{queryName}' has DGA score {score:F2}, C:V ratio {cvRatio:F2}",
                packet, score);
        }
    }

    private void CheckTunneling(string queryName, PacketRecord packet)
    {
        // Label length check
        var parts = queryName.Split('.');
        foreach (var part in parts)
        {
            if (part.Length > 40)
            {
                EmitAlert(AlertSeverity.Warning, "DNS Tunneling Suspected",
                    $"Domain '{queryName}' has label of length {part.Length}",
                    packet, part.Length);
                return;
            }
        }

        // Query rate tracking
        var baseDomain = parts.Length >= 2
            ? $"{parts[^2]}.{parts[^1]}"
            : queryName;

        if (!_queryRates.TryGetValue(baseDomain, out var window))
        {
            window = new SlidingWindow<bool>(TimeSpan.FromMinutes(1));
            _queryRates[baseDomain] = window;
        }

        window.Add(true);
        if (window.Count > 20)
        {
            EmitAlert(AlertSeverity.Warning, "High DNS Query Rate",
                $"Domain '{baseDomain}' has {window.Count} queries in 1 minute",
                packet, window.Count);
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
                ["MetricValue"] = metricValue.ToString("F4"),
            }
        });
    }
}
