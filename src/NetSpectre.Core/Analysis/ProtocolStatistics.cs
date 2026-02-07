namespace NetSpectre.Core.Analysis;

public sealed class ProtocolStatistics
{
    private readonly Dictionary<string, long> _protocolBytes = new();
    private readonly Dictionary<string, long> _protocolPackets = new();
    private readonly Dictionary<string, long> _topTalkers = new(); // IP -> total bytes
    private readonly List<(DateTime Time, long Bytes)> _bandwidthHistory = new();
    private long _totalBytes;
    private long _totalPackets;
    private readonly object _lock = new();

    public void RecordPacket(string protocol, string sourceIp, string destIp, int length)
    {
        lock (_lock)
        {
            _totalBytes += length;
            _totalPackets++;

            _protocolBytes.TryGetValue(protocol, out var pb);
            _protocolBytes[protocol] = pb + length;

            _protocolPackets.TryGetValue(protocol, out var pp);
            _protocolPackets[protocol] = pp + 1;

            _topTalkers.TryGetValue(sourceIp, out var sb);
            _topTalkers[sourceIp] = sb + length;

            _topTalkers.TryGetValue(destIp, out var db);
            _topTalkers[destIp] = db + length;

            _bandwidthHistory.Add((DateTime.UtcNow, length));

            // Trim old bandwidth history (keep last 5 minutes)
            var cutoff = DateTime.UtcNow.AddMinutes(-5);
            _bandwidthHistory.RemoveAll(e => e.Time < cutoff);
        }
    }

    public Dictionary<string, long> GetProtocolByteBreakdown()
    {
        lock (_lock) return new Dictionary<string, long>(_protocolBytes);
    }

    public Dictionary<string, long> GetProtocolPacketBreakdown()
    {
        lock (_lock) return new Dictionary<string, long>(_protocolPackets);
    }

    public List<KeyValuePair<string, long>> GetTopTalkers(int count = 10)
    {
        lock (_lock)
            return _topTalkers.OrderByDescending(kv => kv.Value).Take(count).ToList();
    }

    /// <summary>
    /// Returns bandwidth data points (timestamp, bytes) for the last 5 minutes.
    /// </summary>
    public List<(DateTime Time, long Bytes)> GetBandwidthHistory()
    {
        lock (_lock) return new List<(DateTime, long)>(_bandwidthHistory);
    }

    /// <summary>
    /// Returns bytes-per-second over the last N seconds.
    /// </summary>
    public List<(DateTime Time, double BytesPerSecond)> GetBandwidthPerSecond(int lastSeconds = 60)
    {
        lock (_lock)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-lastSeconds);
            var recent = _bandwidthHistory.Where(e => e.Time >= cutoff).ToList();

            var result = new List<(DateTime, double)>();
            var grouped = recent.GroupBy(e => new DateTime(e.Time.Year, e.Time.Month, e.Time.Day,
                e.Time.Hour, e.Time.Minute, e.Time.Second));
            foreach (var g in grouped.OrderBy(g => g.Key))
            {
                result.Add((g.Key, g.Sum(e => e.Bytes)));
            }
            return result;
        }
    }

    public long TotalBytes { get { lock (_lock) return _totalBytes; } }
    public long TotalPackets { get { lock (_lock) return _totalPackets; } }

    public void Clear()
    {
        lock (_lock)
        {
            _protocolBytes.Clear();
            _protocolPackets.Clear();
            _topTalkers.Clear();
            _bandwidthHistory.Clear();
            _totalBytes = 0;
            _totalPackets = 0;
        }
    }
}
