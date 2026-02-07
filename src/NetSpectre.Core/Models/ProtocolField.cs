namespace NetSpectre.Core.Models;

public sealed class ProtocolField
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public int Offset { get; set; }
    public int Length { get; set; }
}
