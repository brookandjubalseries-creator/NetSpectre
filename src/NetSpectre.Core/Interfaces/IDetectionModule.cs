using NetSpectre.Core.Models;

namespace NetSpectre.Core.Interfaces;

public interface IDetectionModule
{
    string Name { get; }
    string Description { get; }
    bool IsEnabled { get; set; }
    void ProcessPacket(PacketRecord packet);
    IObservable<AlertRecord> AlertStream { get; }
    void Reset();
}
