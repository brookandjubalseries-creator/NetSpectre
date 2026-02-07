using System.Reactive.Linq;
using System.Reactive.Subjects;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;

namespace NetSpectre.Detection.Modules;

public sealed class ArpSpoofDetector : IDetectionModule
{
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly Dictionary<string, string> _ipToMac = new();
    private readonly Dictionary<string, List<(DateTime Timestamp, string Mac)>> _ipMacHistory = new();
    private readonly TimeSpan _escalationWindow = TimeSpan.FromSeconds(60);
    private const int CriticalMacChangeCount = 3;

    public string Name => "ARP Spoof Detector";
    public string Description => "Detects ARP spoofing by tracking MAC-to-IP mapping changes";
    public bool IsEnabled { get; set; } = true;
    public IObservable<AlertRecord> AlertStream => _alertSubject.AsObservable();

    public void ProcessPacket(PacketRecord packet)
    {
        if (!IsEnabled) return;

        if (!packet.Protocol.Equals("ARP", StringComparison.OrdinalIgnoreCase)) return;

        var ip = packet.SourceAddress;
        if (string.IsNullOrEmpty(ip)) return;

        // Extract MAC from ARP layer or Info field
        var mac = ExtractMac(packet);
        if (string.IsNullOrEmpty(mac)) return;

        if (_ipToMac.TryGetValue(ip, out var knownMac))
        {
            if (!knownMac.Equals(mac, StringComparison.OrdinalIgnoreCase))
            {
                // MAC changed for this IP - record in history
                RecordMacChange(ip, mac);

                // Check if we've seen 3+ different MACs in the escalation window
                var severity = GetSeverity(ip);

                _alertSubject.OnNext(new AlertRecord
                {
                    Timestamp = DateTime.UtcNow,
                    Severity = severity,
                    DetectorName = Name,
                    Title = "ARP Spoofing Detected",
                    Description = $"IP {ip} changed MAC from {knownMac} to {mac}",
                    SourceAddress = ip,
                    DestinationAddress = packet.DestinationAddress,
                    Metadata = new Dictionary<string, string>
                    {
                        ["OldMac"] = knownMac,
                        ["NewMac"] = mac,
                        ["IpAddress"] = ip,
                    }
                });

                // Update mapping to latest MAC
                _ipToMac[ip] = mac;
            }
        }
        else
        {
            // First time seeing this IP - record mapping
            _ipToMac[ip] = mac;
            RecordMacChange(ip, mac);
        }
    }

    public void Reset()
    {
        _ipToMac.Clear();
        _ipMacHistory.Clear();
    }

    private void RecordMacChange(string ip, string mac)
    {
        if (!_ipMacHistory.TryGetValue(ip, out var history))
        {
            history = new List<(DateTime, string)>();
            _ipMacHistory[ip] = history;
        }

        history.Add((DateTime.UtcNow, mac));
    }

    private AlertSeverity GetSeverity(string ip)
    {
        if (!_ipMacHistory.TryGetValue(ip, out var history))
            return AlertSeverity.Warning;

        var cutoff = DateTime.UtcNow - _escalationWindow;
        var recentMacs = history
            .Where(h => h.Timestamp >= cutoff)
            .Select(h => h.Mac)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        return recentMacs >= CriticalMacChangeCount ? AlertSeverity.Critical : AlertSeverity.Warning;
    }

    private static string ExtractMac(PacketRecord packet)
    {
        // Try to get MAC from ARP layer fields
        var arpLayer = packet.Layers.GetLayer("Address Resolution Protocol");
        if (arpLayer is not null)
        {
            var senderMac = arpLayer.Fields.FirstOrDefault(f =>
                f.Name.Equals("Sender MAC address", StringComparison.OrdinalIgnoreCase) ||
                f.Name.Equals("Sender Hardware Address", StringComparison.OrdinalIgnoreCase));
            if (senderMac is not null)
                return senderMac.Value;
        }

        // Fallback: try to parse from Info string (e.g., "AA:BB:CC:DD:EE:FF is at 192.168.1.1")
        var info = packet.Info;
        if (!string.IsNullOrEmpty(info))
        {
            var macMatch = System.Text.RegularExpressions.Regex.Match(
                info, @"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}");
            if (macMatch.Success)
                return macMatch.Value;
        }

        return string.Empty;
    }
}
