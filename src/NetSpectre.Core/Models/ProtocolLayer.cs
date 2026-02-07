namespace NetSpectre.Core.Models;

public sealed class ProtocolLayer
{
    public string Name { get; set; } = string.Empty;
    public int HeaderOffset { get; set; }
    public int HeaderLength { get; set; }
    public List<ProtocolField> Fields { get; set; } = new();
    
    public void AddField(string name, string value, int offset = 0, int length = 0)
    {
        Fields.Add(new ProtocolField
        {
            Name = name,
            Value = value,
            Offset = offset,
            Length = length
        });
    }
}
