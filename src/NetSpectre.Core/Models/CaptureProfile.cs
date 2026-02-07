namespace NetSpectre.Core.Models;

public sealed class CaptureProfile
{
    public string Name { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string BpfFilter { get; set; } = string.Empty;
    public string DisplayFilter { get; set; } = string.Empty;
}
