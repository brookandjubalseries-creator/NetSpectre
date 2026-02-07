using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpectre.Core.Configuration;

namespace NetSpectre.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ConfigurationService _configService;

    // Capture
    [ObservableProperty] private int _bufferSize;
    [ObservableProperty] private int _batchIntervalMs;
    [ObservableProperty] private bool _promiscuousMode;
    [ObservableProperty] private int _maxFlushPerTick;

    // Port Scan
    [ObservableProperty] private bool _portScanEnabled;
    [ObservableProperty] private int _portScanWindowSeconds;
    [ObservableProperty] private int _portScanInfoThreshold;
    [ObservableProperty] private int _portScanWarningThreshold;
    [ObservableProperty] private int _portScanCriticalThreshold;

    // DNS Anomaly
    [ObservableProperty] private bool _dnsAnomalyEnabled;
    [ObservableProperty] private double _dnsSuspiciousEntropy;
    [ObservableProperty] private double _dnsHighEntropy;
    [ObservableProperty] private double _dnsCriticalEntropy;

    // C2 Beacon
    [ObservableProperty] private bool _c2BeaconEnabled;
    [ObservableProperty] private int _c2MinConnections;
    [ObservableProperty] private double _c2CriticalCvThreshold;
    [ObservableProperty] private double _c2WarningCvThreshold;
    [ObservableProperty] private double _c2DbscanClusterRatio;

    // Visualization
    [ObservableProperty] private int _maxNodes;
    [ObservableProperty] private int _targetFps;

    // UI
    [ObservableProperty] private bool _showHexView;
    [ObservableProperty] private int _maxDisplayedPackets;

    [ObservableProperty] private bool _hasChanges;

    public SettingsViewModel(ConfigurationService configService)
    {
        _configService = configService;
        LoadFromConfig();
    }

    private void LoadFromConfig()
    {
        var config = _configService.Config;

        BufferSize = config.Capture.BufferSize;
        BatchIntervalMs = config.Capture.BatchIntervalMs;
        PromiscuousMode = config.Capture.PromiscuousMode;
        MaxFlushPerTick = config.Capture.MaxFlushPerTick;

        PortScanEnabled = config.Detection.PortScan.Enabled;
        PortScanWindowSeconds = config.Detection.PortScan.WindowSeconds;
        PortScanInfoThreshold = config.Detection.PortScan.InfoThreshold;
        PortScanWarningThreshold = config.Detection.PortScan.WarningThreshold;
        PortScanCriticalThreshold = config.Detection.PortScan.CriticalThreshold;

        DnsAnomalyEnabled = config.Detection.DnsAnomaly.Enabled;
        DnsSuspiciousEntropy = config.Detection.DnsAnomaly.SuspiciousEntropy;
        DnsHighEntropy = config.Detection.DnsAnomaly.HighEntropy;
        DnsCriticalEntropy = config.Detection.DnsAnomaly.CriticalEntropy;

        C2BeaconEnabled = config.Detection.C2Beacon.Enabled;
        C2MinConnections = config.Detection.C2Beacon.MinConnections;
        C2CriticalCvThreshold = config.Detection.C2Beacon.CriticalCvThreshold;
        C2WarningCvThreshold = config.Detection.C2Beacon.WarningCvThreshold;
        C2DbscanClusterRatio = config.Detection.C2Beacon.DbscanClusterRatio;

        MaxNodes = config.Visualization.MaxNodes;
        TargetFps = config.Visualization.TargetFps;

        ShowHexView = config.Ui.ShowHexView;
        MaxDisplayedPackets = config.Ui.MaxDisplayedPackets;

        HasChanges = false;
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName != nameof(HasChanges))
            HasChanges = true;
    }

    [RelayCommand]
    private void Save()
    {
        var config = _configService.Config;

        config.Capture.BufferSize = BufferSize;
        config.Capture.BatchIntervalMs = BatchIntervalMs;
        config.Capture.PromiscuousMode = PromiscuousMode;
        config.Capture.MaxFlushPerTick = MaxFlushPerTick;

        config.Detection.PortScan.Enabled = PortScanEnabled;
        config.Detection.PortScan.WindowSeconds = PortScanWindowSeconds;
        config.Detection.PortScan.InfoThreshold = PortScanInfoThreshold;
        config.Detection.PortScan.WarningThreshold = PortScanWarningThreshold;
        config.Detection.PortScan.CriticalThreshold = PortScanCriticalThreshold;

        config.Detection.DnsAnomaly.Enabled = DnsAnomalyEnabled;
        config.Detection.DnsAnomaly.SuspiciousEntropy = DnsSuspiciousEntropy;
        config.Detection.DnsAnomaly.HighEntropy = DnsHighEntropy;
        config.Detection.DnsAnomaly.CriticalEntropy = DnsCriticalEntropy;

        config.Detection.C2Beacon.Enabled = C2BeaconEnabled;
        config.Detection.C2Beacon.MinConnections = C2MinConnections;
        config.Detection.C2Beacon.CriticalCvThreshold = C2CriticalCvThreshold;
        config.Detection.C2Beacon.WarningCvThreshold = C2WarningCvThreshold;
        config.Detection.C2Beacon.DbscanClusterRatio = C2DbscanClusterRatio;

        config.Visualization.MaxNodes = MaxNodes;
        config.Visualization.TargetFps = TargetFps;

        config.Ui.ShowHexView = ShowHexView;
        config.Ui.MaxDisplayedPackets = MaxDisplayedPackets;

        _configService.Save();
        HasChanges = false;
    }

    [RelayCommand]
    private void Cancel()
    {
        LoadFromConfig();
    }

    [RelayCommand]
    private void ResetDefaults()
    {
        _configService.Reset();
        LoadFromConfig();
    }
}
