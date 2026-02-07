namespace NetSpectre.Core.Models;

public sealed class PacketRecord
{
    public int Number { get; set; }
    public DateTime Timestamp { get; set; }
    public string SourceAddress { get; set; } = string.Empty;
    public string DestinationAddress { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public int Length { get; set; }
    public string Info { get; set; } = string.Empty;
    public byte[] RawData { get; set; } = Array.Empty<byte>();
    public PacketLayers Layers { get; set; } = new();
    public bool IsBookmarked { get; set; }
}
