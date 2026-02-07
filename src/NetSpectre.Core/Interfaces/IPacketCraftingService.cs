namespace NetSpectre.Core.Interfaces;

public interface IPacketCraftingService
{
    Task<bool> SendPacketAsync(byte[] packetData, string deviceName);
    IReadOnlyList<string> GetTemplateNames();
}
