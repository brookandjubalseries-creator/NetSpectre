namespace NetSpectre.Core.Models;

public sealed class NetworkNode
{
    public string Address { get; set; } = string.Empty;
    public float X { get; set; }
    public float Y { get; set; }
    public float VelocityX { get; set; }
    public float VelocityY { get; set; }
    public float Radius { get; set; } = 20f;
    public long TotalBytes { get; set; }
    public int ConnectionCount { get; set; }
    public bool IsPinned { get; set; }
    public bool IsFlagged { get; set; }
    public string? Label { get; set; }
}
