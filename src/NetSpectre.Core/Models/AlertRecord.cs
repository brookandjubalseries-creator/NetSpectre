namespace NetSpectre.Core.Models;

public sealed class AlertRecord
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public AlertSeverity Severity { get; set; }
    public string DetectorName { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SourceAddress { get; set; } = string.Empty;
    public string DestinationAddress { get; set; } = string.Empty;
    public Dictionary<string, string> Metadata { get; set; } = new();
}
