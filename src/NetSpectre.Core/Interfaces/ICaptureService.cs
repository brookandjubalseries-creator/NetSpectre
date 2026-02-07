using NetSpectre.Core.Models;

namespace NetSpectre.Core.Interfaces;

public interface ICaptureService : IDisposable
{
    IObservable<PacketRecord> PacketStream { get; }
    IReadOnlyList<CaptureDeviceInfo> GetAvailableDevices();
    void StartCapture(string deviceName, string? bpfFilter = null);
    void StopCapture();
    bool IsCapturing { get; }
    CaptureStatistics Statistics { get; }
}

public sealed class CaptureDeviceInfo
{
    public string Name { get; set; } = string.Empty;
    public string FriendlyName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}
