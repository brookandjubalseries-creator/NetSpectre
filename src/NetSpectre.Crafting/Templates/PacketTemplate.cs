namespace NetSpectre.Crafting.Templates;

public abstract class PacketTemplate
{
    public abstract string Name { get; }
    public abstract string Description { get; }

    public abstract PacketBuilder Apply(PacketBuilder builder);

    public byte[] Build()
    {
        var builder = new PacketBuilder();
        Apply(builder);
        return builder.Build();
    }
}
