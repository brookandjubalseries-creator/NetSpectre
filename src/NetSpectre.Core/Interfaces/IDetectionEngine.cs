using NetSpectre.Core.Models;

namespace NetSpectre.Core.Interfaces;

public interface IDetectionEngine : IDisposable
{
    IObservable<AlertRecord> AlertStream { get; }
    IReadOnlyList<IDetectionModule> Modules { get; }
    void RegisterModule(IDetectionModule module);
    void ProcessPacket(PacketRecord packet);
    void Start();
    void Stop();
}
