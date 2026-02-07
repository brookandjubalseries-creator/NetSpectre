using NetSpectre.Core.Models;
using PacketDotNet;

namespace NetSpectre.Capture.Dissectors;

public interface IDissector
{
    bool CanDissect(Packet packet);
    ProtocolLayer Dissect(Packet packet);
}
