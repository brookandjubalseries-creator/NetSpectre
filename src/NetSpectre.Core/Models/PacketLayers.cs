namespace NetSpectre.Core.Models;

public sealed class PacketLayers
{
    public List<ProtocolLayer> LayerStack { get; set; } = new();
    
    public void AddLayer(ProtocolLayer layer) => LayerStack.Add(layer);
    
    public ProtocolLayer? GetLayer(string protocolName) =>
        LayerStack.FirstOrDefault(l => l.Name.Equals(protocolName, StringComparison.OrdinalIgnoreCase));
}
