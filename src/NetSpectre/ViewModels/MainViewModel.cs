using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reactive.Linq;
using System.Threading.Channels;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NetSpectre.Capture;
using NetSpectre.Core.Analysis;
using NetSpectre.Core.Configuration;
using NetSpectre.Core.Filtering;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;
using NetSpectre.Core.Services;
using NetSpectre.Crafting;
using System.Windows;

namespace NetSpectre.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly ICaptureService? _captureService;
    private readonly IDetectionEngine? _detectionEngine;
    private readonly PcapFileService? _pcapFileService;
    private readonly ProtocolStatistics? _protocolStatistics;
    private readonly TcpStreamReassembler? _tcpStreamReassembler;
    private readonly DnsResolverCache? _dnsResolverCache;
    private readonly GeoIpService? _geoIpService;
    private readonly AlertWebhookService? _alertWebhookService;
    private readonly ConfigurationService? _configService;
    private readonly FilterEvaluator _filterEvaluator = new();
    private IDisposable? _packetSubscription;
    private IDisposable? _webhookSubscription;
    private readonly Channel<PacketRecord> _packetChannel;
    private readonly DispatcherTimer _flushTimer;
    private readonly DispatcherTimer _statsTimer;
    private DateTime _captureStartTime;
    private readonly List<PacketRecord> _allPackets = new();
    private FilterExpression? _activeFilter;

    public PacketCrafterViewModel CrafterVm { get; }

    [ObservableProperty]
    private ObservableCollection<PacketRecord> _packets = new();

    [ObservableProperty]
    private PacketRecord? _selectedPacket;

    [ObservableProperty]
    private ObservableCollection<CaptureDeviceInfo> _availableDevices = new();

    [ObservableProperty]
    private CaptureDeviceInfo? _selectedDevice;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private string _bpfFilter = string.Empty;

    [ObservableProperty]
    private bool _isCapturing;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private int _packetCount;

    [ObservableProperty]
    private int _displayedCount;

    [ObservableProperty]
    private int _packetsPerSecond;

    [ObservableProperty]
    private string _captureElapsed = "00:00:00";

    [ObservableProperty]
    private bool _hasFilterError;

    [ObservableProperty]
    private string _filterErrorMessage = string.Empty;

    [ObservableProperty]
    private int _selectedBottomTab;

    [ObservableProperty]
    private bool _showBookmarkedOnly;

    [ObservableProperty]
    private ObservableCollection<CaptureProfile> _captureProfiles = new();

    [ObservableProperty]
    private CaptureProfile? _selectedProfile;

    [ObservableProperty]
    private int _streamCount;

    public AlertsViewModel AlertsVm { get; }

    // Expose services for code-behind (statistics rendering, etc.)
    public ProtocolStatistics? ProtocolStats => _protocolStatistics;
    public TcpStreamReassembler? StreamReassembler => _tcpStreamReassembler;
    public DnsResolverCache? DnsCache => _dnsResolverCache;
    public GeoIpService? GeoIp => _geoIpService;

    public MainViewModel()
    {
        // Design-time constructor
        _packetChannel = Channel.CreateBounded<PacketRecord>(50_000);
        _flushTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _statsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        AlertsVm = new AlertsViewModel();
        CrafterVm = new PacketCrafterViewModel();
    }

    public MainViewModel(ICaptureService captureService, IDetectionEngine? detectionEngine = null,
        PacketCraftingService? craftingService = null, PcapFileService? pcapFileService = null,
        ProtocolStatistics? protocolStatistics = null, TcpStreamReassembler? tcpStreamReassembler = null,
        DnsResolverCache? dnsResolverCache = null, GeoIpService? geoIpService = null,
        AlertWebhookService? alertWebhookService = null, ConfigurationService? configService = null) : this()
    {
        _captureService = captureService;
        _detectionEngine = detectionEngine;
        _pcapFileService = pcapFileService;
        _protocolStatistics = protocolStatistics;
        _tcpStreamReassembler = tcpStreamReassembler;
        _dnsResolverCache = dnsResolverCache;
        _geoIpService = geoIpService;
        _alertWebhookService = alertWebhookService;
        _configService = configService;
        CrafterVm = new PacketCrafterViewModel(
            craftingService ?? new PacketCraftingService(), captureService);
        _flushTimer.Tick += FlushPackets;
        _statsTimer.Tick += UpdateStats;

        if (detectionEngine != null)
        {
            AlertsVm = new AlertsViewModel(detectionEngine);
            AlertsVm.Subscribe(Application.Current.Dispatcher);
            detectionEngine.Start();

            // Wire webhook service to detection engine alerts
            if (_alertWebhookService != null)
            {
                _webhookSubscription = detectionEngine.AlertStream
                    .Subscribe(alert => _ = _alertWebhookService.SendAlertAsync(alert));
            }
        }

        // Load capture profiles from config
        if (_configService != null)
        {
            foreach (var profile in _configService.Config.Profiles)
                CaptureProfiles.Add(profile);
        }

        LoadDevices();
    }

    private void LoadDevices()
    {
        if (_captureService is null) return;
        AvailableDevices.Clear();
        try
        {
            foreach (var device in _captureService.GetAvailableDevices())
            {
                AvailableDevices.Add(device);
            }
            if (AvailableDevices.Count > 0)
            {
                SelectedDevice = AvailableDevices[0];
                StatusText = $"Ready — {AvailableDevices.Count} interface(s) found";
            }
            else
            {
                StatusText = "No capture interfaces found — is Npcap installed? (https://npcap.com)";
            }
        }
        catch (DllNotFoundException)
        {
            StatusText = "Npcap not installed — download from https://npcap.com to enable capture";
        }
        catch (Exception ex)
        {
            StatusText = $"Error loading devices: {ex.Message}";
        }
    }

    [RelayCommand]
    private void StartCapture()
    {
        if (_captureService is null) return;
        if (SelectedDevice is null)
        {
            StatusText = "No interface selected — install Npcap and click Refresh";
            return;
        }

        try
        {
            var filter = string.IsNullOrWhiteSpace(BpfFilter) ? null : BpfFilter;
            _captureService.StartCapture(SelectedDevice.Name, filter);

            _packetSubscription = _captureService.PacketStream
                .Subscribe(packet =>
                {
                    _packetChannel.Writer.TryWrite(packet);
                });

            IsCapturing = true;
            _captureStartTime = DateTime.UtcNow;
            StatusText = $"Capturing on {SelectedDevice.FriendlyName}...";
            CrafterVm.SetActiveDevice(SelectedDevice.Name);

            _flushTimer.Start();
            _statsTimer.Start();
        }
        catch (Exception ex)
        {
            StatusText = $"Capture error: {ex.Message}";
        }
    }

    [RelayCommand]
    private void StopCapture()
    {
        if (_captureService is null) return;

        _packetSubscription?.Dispose();
        _packetSubscription = null;
        _captureService.StopCapture();

        _flushTimer.Stop();
        _statsTimer.Stop();

        // Flush any remaining packets
        FlushPackets(null, EventArgs.Empty);

        IsCapturing = false;
        StatusText = $"Capture stopped — {PacketCount} packets ({DisplayedCount} displayed)";
    }

    [RelayCommand]
    private void ClearPackets()
    {
        Packets.Clear();
        _allPackets.Clear();
        PacketCount = 0;
        DisplayedCount = 0;
        _protocolStatistics?.Clear();
        _tcpStreamReassembler?.Clear();
        StreamCount = 0;
    }

    [RelayCommand]
    private void ApplyFilter()
    {
        if (string.IsNullOrWhiteSpace(FilterText))
        {
            _activeFilter = null;
            HasFilterError = false;
            FilterErrorMessage = string.Empty;
            RebuildFilteredView();
            return;
        }

        try
        {
            _activeFilter = FilterParser.Parse(FilterText);
            HasFilterError = false;
            FilterErrorMessage = string.Empty;
            RebuildFilteredView();
        }
        catch (FilterParseException ex)
        {
            HasFilterError = true;
            FilterErrorMessage = ex.Message;
        }
    }

    [RelayCommand]
    private void RefreshDevices()
    {
        LoadDevices();
    }

    [RelayCommand]
    private void CopySourceAddress()
    {
        if (SelectedPacket != null)
            Clipboard.SetText(SelectedPacket.SourceAddress);
    }

    [RelayCommand]
    private void CopyDestAddress()
    {
        if (SelectedPacket != null)
            Clipboard.SetText(SelectedPacket.DestinationAddress);
    }

    [RelayCommand]
    private void FilterBySource()
    {
        if (SelectedPacket != null)
        {
            FilterText = $"ip.src == {SelectedPacket.SourceAddress}";
            ApplyFilter();
        }
    }

    [RelayCommand]
    private void FilterByDest()
    {
        if (SelectedPacket != null)
        {
            FilterText = $"ip.dst == {SelectedPacket.DestinationAddress}";
            ApplyFilter();
        }
    }

    [RelayCommand]
    private void SendToCrafter()
    {
        if (SelectedPacket != null)
        {
            CrafterVm.LoadFromPacket(SelectedPacket);
            SelectedBottomTab = 4; // Switch to Crafter tab (shifted by new Statistics tab)
        }
    }

    [RelayCommand]
    private void ToggleBookmark()
    {
        if (SelectedPacket != null)
        {
            SelectedPacket.IsBookmarked = !SelectedPacket.IsBookmarked;
            OnPropertyChanged(nameof(SelectedPacket));
        }
    }

    [RelayCommand]
    private void FilterBookmarked()
    {
        ShowBookmarkedOnly = !ShowBookmarkedOnly;
        RebuildFilteredView();
    }

    [RelayCommand]
    private void SavePcap()
    {
        if (_pcapFileService is null || _allPackets.Count == 0)
        {
            StatusText = "No packets to save.";
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "PCAP files (*.pcap)|*.pcap|All files (*.*)|*.*",
            DefaultExt = ".pcap",
            FileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap",
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                _pcapFileService.SaveToPcap(dialog.FileName, _allPackets);
                StatusText = $"Saved {_allPackets.Count} packets to {System.IO.Path.GetFileName(dialog.FileName)}";
            }
            catch (Exception ex)
            {
                StatusText = $"Save error: {ex.Message}";
            }
        }
    }

    [RelayCommand]
    private void LoadPcap()
    {
        if (_pcapFileService is null) return;

        var dialog = new OpenFileDialog
        {
            Filter = "PCAP files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*",
            DefaultExt = ".pcap",
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var packets = _pcapFileService.LoadFromPcap(dialog.FileName);
                ClearPackets();

                foreach (var packet in packets)
                {
                    _allPackets.Add(packet);
                    if (PassesFilter(packet))
                        Packets.Add(packet);
                    _detectionEngine?.ProcessPacket(packet);
                    _protocolStatistics?.RecordPacket(packet.Protocol, packet.SourceAddress,
                        packet.DestinationAddress, packet.Length);
                    _tcpStreamReassembler?.ProcessPacket(packet);
                }

                PacketCount = _allPackets.Count;
                DisplayedCount = Packets.Count;
                StreamCount = _tcpStreamReassembler?.StreamCount ?? 0;
                StatusText = $"Loaded {packets.Count} packets from {System.IO.Path.GetFileName(dialog.FileName)}";
            }
            catch (Exception ex)
            {
                StatusText = $"Load error: {ex.Message}";
            }
        }
    }

    [RelayCommand]
    private void OpenInWireshark()
    {
        if (_pcapFileService is null || _allPackets.Count == 0)
        {
            StatusText = "No packets to open — capture or load a PCAP first.";
            return;
        }

        try
        {
            var tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                $"netspectre_{DateTime.Now:yyyyMMdd_HHmmss}.pcap");
            _pcapFileService.SaveToPcap(tempPath, _allPackets);

            var psi = new ProcessStartInfo
            {
                FileName = tempPath,
                UseShellExecute = true,
            };
            Process.Start(psi);
            StatusText = "Opening capture in Wireshark...";
        }
        catch (Exception ex)
        {
            StatusText = $"Could not open Wireshark: {ex.Message}";
        }
    }

    [RelayCommand]
    private void SaveProfile()
    {
        if (SelectedDevice is null) return;

        var profile = new CaptureProfile
        {
            Name = $"Profile {CaptureProfiles.Count + 1}",
            DeviceName = SelectedDevice.Name,
            BpfFilter = BpfFilter,
            DisplayFilter = FilterText,
        };

        CaptureProfiles.Add(profile);

        // Persist to config
        if (_configService != null)
        {
            _configService.Config.Profiles.Add(profile);
            _configService.Save();
        }

        StatusText = $"Saved capture profile: {profile.Name}";
    }

    partial void OnSelectedProfileChanged(CaptureProfile? value)
    {
        if (value is null) return;

        // Apply profile settings
        BpfFilter = value.BpfFilter;
        FilterText = value.DisplayFilter;

        // Try to select the matching device
        var device = AvailableDevices.FirstOrDefault(d => d.Name == value.DeviceName);
        if (device != null)
            SelectedDevice = device;

        if (!string.IsNullOrWhiteSpace(FilterText))
            ApplyFilter();

        StatusText = $"Applied profile: {value.Name}";
    }

    [RelayCommand]
    private void FollowStream()
    {
        if (SelectedPacket is null || _tcpStreamReassembler is null) return;

        var stream = _tcpStreamReassembler.GetStreamForPacket(SelectedPacket);
        if (stream is null)
        {
            StatusText = "No TCP stream found for this packet.";
            return;
        }

        // Filter to show only packets in this stream
        var packetNumbers = stream.Segments.Select(s => s.PacketNumber).ToHashSet();
        Packets.Clear();
        foreach (var p in _allPackets)
        {
            if (packetNumbers.Contains(p.Number))
                Packets.Add(p);
        }
        DisplayedCount = Packets.Count;
        StatusText = $"Following stream {stream.StreamId} — {stream.PacketCount} packets, {stream.Protocol}";
    }

    private void RebuildFilteredView()
    {
        Packets.Clear();
        foreach (var p in _allPackets)
        {
            if (ShowBookmarkedOnly && !p.IsBookmarked)
                continue;
            if (_activeFilter is null || _filterEvaluator.Evaluate(_activeFilter, p))
                Packets.Add(p);
        }
        DisplayedCount = Packets.Count;
    }

    private bool PassesFilter(PacketRecord packet)
    {
        if (ShowBookmarkedOnly && !packet.IsBookmarked) return false;
        if (_activeFilter is null) return true;
        return _filterEvaluator.Evaluate(_activeFilter, packet);
    }

    private void FlushPackets(object? sender, EventArgs e)
    {
        var flushed = 0;
        while (flushed < 500 && _packetChannel.Reader.TryRead(out var packet))
        {
            _allPackets.Add(packet);
            if (PassesFilter(packet))
                Packets.Add(packet);
            _detectionEngine?.ProcessPacket(packet);
            _protocolStatistics?.RecordPacket(packet.Protocol, packet.SourceAddress,
                packet.DestinationAddress, packet.Length);
            _tcpStreamReassembler?.ProcessPacket(packet);
            flushed++;
        }
        PacketCount = _allPackets.Count;
        DisplayedCount = Packets.Count;
        StreamCount = _tcpStreamReassembler?.StreamCount ?? 0;
    }

    private void UpdateStats(object? sender, EventArgs e)
    {
        if (_captureService is null) return;

        var stats = _captureService.Statistics;
        var elapsed = DateTime.UtcNow - _captureStartTime;
        CaptureElapsed = elapsed.ToString(@"hh\:mm\:ss");

        if (elapsed.TotalSeconds > 0)
            PacketsPerSecond = (int)(stats.TotalPackets / elapsed.TotalSeconds);
    }

    public void Cleanup()
    {
        _flushTimer.Stop();
        _statsTimer.Stop();
        _packetSubscription?.Dispose();
        _webhookSubscription?.Dispose();
        _captureService?.Dispose();
        _detectionEngine?.Dispose();
        _geoIpService?.Dispose();
        _alertWebhookService?.Dispose();
        AlertsVm.Cleanup();
    }
}
