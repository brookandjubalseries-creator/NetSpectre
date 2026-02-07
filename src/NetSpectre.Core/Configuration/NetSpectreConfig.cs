using NetSpectre.Core.Models;

namespace NetSpectre.Core.Configuration;

public sealed class NetSpectreConfig
{
    public CaptureConfig Capture { get; set; } = new();
    public DetectionConfig Detection { get; set; } = new();
    public VisualizationConfig Visualization { get; set; } = new();
    public UiConfig Ui { get; set; } = new();
    public List<CaptureProfile> Profiles { get; set; } = new();
    public WebhookConfig Webhook { get; set; } = new();
}

public sealed class WebhookConfig
{
    public bool Enabled { get; set; }
    public string Url { get; set; } = string.Empty;
    public bool OnCriticalOnly { get; set; } = true;
}

public sealed class CaptureConfig
{
    public int BufferSize { get; set; } = 50_000;
    public int BatchIntervalMs { get; set; } = 100;
    public bool PromiscuousMode { get; set; } = true;
    public int MaxFlushPerTick { get; set; } = 500;
}

public sealed class DetectionConfig
{
    public PortScanConfig PortScan { get; set; } = new();
    public DnsAnomalyConfig DnsAnomaly { get; set; } = new();
    public C2BeaconConfig C2Beacon { get; set; } = new();
}

public sealed class PortScanConfig
{
    public bool Enabled { get; set; } = true;
    public int WindowSeconds { get; set; } = 60;
    public int InfoThreshold { get; set; } = 10;
    public int WarningThreshold { get; set; } = 20;
    public int CriticalThreshold { get; set; } = 50;
}

public sealed class DnsAnomalyConfig
{
    public bool Enabled { get; set; } = true;
    public double SuspiciousEntropy { get; set; } = 3.1;
    public double HighEntropy { get; set; } = 4.0;
    public double CriticalEntropy { get; set; } = 4.5;
}

public sealed class C2BeaconConfig
{
    public bool Enabled { get; set; } = true;
    public int MinConnections { get; set; } = 10;
    public double CriticalCvThreshold { get; set; } = 0.10;
    public double WarningCvThreshold { get; set; } = 0.15;
    public double DbscanClusterRatio { get; set; } = 0.80;
}

public sealed class VisualizationConfig
{
    public float RepulsionForce { get; set; } = 5000f;
    public float AttractionForce { get; set; } = 0.01f;
    public float Damping { get; set; } = 0.85f;
    public int MaxNodes { get; set; } = 200;
    public int TargetFps { get; set; } = 30;
}

public sealed class UiConfig
{
    public bool ShowHexView { get; set; } = true;
    public string DefaultBpfFilter { get; set; } = string.Empty;
    public int MaxDisplayedPackets { get; set; } = 100_000;
}
