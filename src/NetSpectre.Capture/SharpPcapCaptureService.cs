using System.Reactive.Linq;
using System.Reactive.Subjects;
using NetSpectre.Capture.Dissectors;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;
using SharpPcap;

namespace NetSpectre.Capture;

public sealed class SharpPcapCaptureService : ICaptureService
{
    private readonly Subject<PacketRecord> _packetSubject = new();
    private readonly PacketDissector _dissector = new();
    private ILiveDevice? _device;
    private int _packetNumber;
    private bool _isCapturing;
    private DateTime _captureStart;
    private readonly object _statsLock = new();
    private long _totalPackets;
    private long _totalBytes;
    private readonly Dictionary<string, long> _protocolCounts = new();

    public IObservable<PacketRecord> PacketStream => _packetSubject.AsObservable();
    public bool IsCapturing => _isCapturing;

    public CaptureStatistics Statistics
    {
        get
        {
            lock (_statsLock)
            {
                return new CaptureStatistics
                {
                    TotalPackets = _totalPackets,
                    TotalBytes = _totalBytes,
                    ElapsedTime = _isCapturing ? DateTime.UtcNow - _captureStart : TimeSpan.Zero,
                    ProtocolCounts = new Dictionary<string, long>(_protocolCounts),
                };
            }
        }
    }

    public IReadOnlyList<CaptureDeviceInfo> GetAvailableDevices()
    {
        var devices = CaptureDeviceList.Instance;
        var result = new List<CaptureDeviceInfo>();

        foreach (var dev in devices)
        {
            var friendly = GetFriendlyName(dev);
            result.Add(new CaptureDeviceInfo
            {
                Name = dev.Name,
                FriendlyName = friendly,
                Description = dev.Description ?? string.Empty,
            });
        }

        return result;
    }

    private static string GetFriendlyName(ILiveDevice dev)
    {
        // Try to get a meaningful name from the device
        if (dev is SharpPcap.LibPcap.LibPcapLiveDevice libDev)
        {
            // LibPcap devices on Windows expose the interface via Addresses
            var addresses = libDev.Addresses;
            var ipAddr = addresses
                .Where(a => a.Addr?.ipAddress != null)
                .Select(a => a.Addr!.ipAddress!.ToString())
                .Where(ip => ip != "0.0.0.0" && !ip.StartsWith("0."))
                .FirstOrDefault();

            var desc = !string.IsNullOrWhiteSpace(dev.Description) ? dev.Description : null;
            if (desc != null && ipAddr != null)
                return $"{desc} ({ipAddr})";
            if (desc != null)
                return desc;
            if (ipAddr != null)
                return $"Interface ({ipAddr})";
        }

        if (!string.IsNullOrWhiteSpace(dev.Description))
            return dev.Description;

        // Fallback: shorten the GUID name
        var name = dev.Name;
        if (name.Contains('{'))
        {
            var guid = name[(name.IndexOf('{'))..];
            return $"Interface {guid[..Math.Min(13, guid.Length)]}...";
        }

        return name;
    }

    public void StartCapture(string deviceName, string? bpfFilter = null)
    {
        if (_isCapturing) return;

        var devices = CaptureDeviceList.Instance;
        _device = devices.FirstOrDefault(d => d.Name == deviceName)
            ?? throw new InvalidOperationException($"Device '{deviceName}' not found.");

        _device.Open(DeviceModes.Promiscuous, 100);

        if (!string.IsNullOrWhiteSpace(bpfFilter))
        {
            _device.Filter = bpfFilter;
        }

        _packetNumber = 0;
        _captureStart = DateTime.UtcNow;
        _isCapturing = true;

        lock (_statsLock)
        {
            _totalPackets = 0;
            _totalBytes = 0;
            _protocolCounts.Clear();
        }

        _device.OnPacketArrival += OnPacketArrival;
        _device.StartCapture();
    }

    public void StopCapture()
    {
        if (!_isCapturing) return;
        _isCapturing = false;

        if (_device != null)
        {
            try
            {
                _device.StopCapture();
                _device.OnPacketArrival -= OnPacketArrival;
                _device.Close();
            }
            catch (Exception)
            {
                // Device may already be closed
            }
            _device = null;
        }
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var rawCapture = e.GetPacket();
            var number = Interlocked.Increment(ref _packetNumber);
            var record = _dissector.Dissect(rawCapture, number);

            lock (_statsLock)
            {
                _totalPackets++;
                _totalBytes += record.Length;
                _protocolCounts.TryGetValue(record.Protocol, out var count);
                _protocolCounts[record.Protocol] = count + 1;
            }

            _packetSubject.OnNext(record);
        }
        catch (Exception)
        {
            // Skip malformed packets silently
        }
    }

    public void Dispose()
    {
        StopCapture();
        _packetSubject.Dispose();
    }
}
