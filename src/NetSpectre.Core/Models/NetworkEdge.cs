namespace NetSpectre.Core.Models;

public sealed class NetworkEdge
{
    public string SourceAddress { get; set; } = string.Empty;
    public string DestinationAddress { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public long TotalBytes { get; set; }
    public int PacketCount { get; set; }
    public float Thickness => Math.Clamp(1f + (float)Math.Log10(Math.Max(1, TotalBytes)) * 0.5f, 1f, 8f);
}
