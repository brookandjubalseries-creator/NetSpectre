namespace NetSpectre.Core.Models;

public sealed class ColoringRule
{
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public string Filter { get; set; } = string.Empty;  // e.g. "tcp", "ip.src == 192.168.1.1"
    public string ForegroundHex { get; set; } = "#CDD6F4";
    public string BackgroundHex { get; set; } = "#2D2D44";
    public int Priority { get; set; }

    public static List<ColoringRule> GetDefaults() => new()
    {
        new() { Name = "HTTP", Filter = "http", ForegroundHex = "#1E1E2E", BackgroundHex = "#A6E3A1", Priority = 10 },
        new() { Name = "HTTPS/TLS", Filter = "tls", ForegroundHex = "#1E1E2E", BackgroundHex = "#F9E2AF", Priority = 11 },
        new() { Name = "DNS", Filter = "dns", ForegroundHex = "#1E1E2E", BackgroundHex = "#CBA6F7", Priority = 20 },
        new() { Name = "TCP SYN", Filter = "tcp.syn", ForegroundHex = "#CDD6F4", BackgroundHex = "#45455E", Priority = 30 },
        new() { Name = "TCP RST", Filter = "tcp.rst", ForegroundHex = "#1E1E2E", BackgroundHex = "#F38BA8", Priority = 31 },
        new() { Name = "ICMP", Filter = "icmp", ForegroundHex = "#1E1E2E", BackgroundHex = "#F38BA8", Priority = 40 },
        new() { Name = "ARP", Filter = "arp", ForegroundHex = "#1E1E2E", BackgroundHex = "#94E2D5", Priority = 50 },
    };
}
