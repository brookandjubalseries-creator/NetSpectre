namespace NetSpectre.Core.Models;

public sealed class CaptureStatistics
{
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public int PacketsPerSecond { get; set; }
    public long DroppedPackets { get; set; }
    public TimeSpan ElapsedTime { get; set; }
    public Dictionary<string, long> ProtocolCounts { get; set; } = new();
}
