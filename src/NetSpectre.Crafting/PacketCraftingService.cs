using NetSpectre.Core.Interfaces;
using NetSpectre.Crafting.Templates;
using SharpPcap;

namespace NetSpectre.Crafting;

public sealed class PacketCraftingService : IPacketCraftingService
{
    private readonly Dictionary<string, PacketTemplate> _templates = new(StringComparer.OrdinalIgnoreCase);

    public PacketCraftingService()
    {
        RegisterTemplate(new ArpRequestTemplate());
        RegisterTemplate(new IcmpEchoTemplate());
        RegisterTemplate(new TcpSynTemplate());
        RegisterTemplate(new DnsQueryTemplate());
        RegisterTemplate(new HttpGetTemplate());
    }

    public void RegisterTemplate(PacketTemplate template)
    {
        _templates[template.Name] = template;
    }

    public PacketTemplate? GetTemplate(string name)
    {
        return _templates.GetValueOrDefault(name);
    }

    public IReadOnlyList<string> GetTemplateNames()
    {
        return _templates.Keys.ToList().AsReadOnly();
    }

    public async Task<bool> SendPacketAsync(byte[] packetData, string deviceName)
    {
        return await Task.Run(() =>
        {
            try
            {
                var devices = CaptureDeviceList.Instance;
                var device = devices.FirstOrDefault(d => d.Name == deviceName);
                if (device == null)
                    return false;

                device.Open();
                try
                {
                    device.SendPacket(packetData);
                    return true;
                }
                finally
                {
                    device.Close();
                }
            }
            catch
            {
                return false;
            }
        });
    }

    public byte[] BuildFromTemplate(string templateName)
    {
        if (!_templates.TryGetValue(templateName, out var template))
            throw new ArgumentException($"Unknown template: {templateName}", nameof(templateName));
        return template.Build();
    }

    public byte[] CloneAndModify(byte[] originalPacket, Action<PacketBuilder> modifier)
    {
        var builder = new PacketBuilder();
        modifier(builder);
        return builder.Build();
    }
}
