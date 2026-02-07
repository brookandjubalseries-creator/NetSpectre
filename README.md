# NetSpectre

A Wireshark-inspired network traffic analyzer, intrusion detection system, and packet crafter built with C#, WPF, and .NET 8.

![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)
![C#](https://img.shields.io/badge/C%23-12-239120?logo=csharp)
![WPF](https://img.shields.io/badge/WPF-Desktop-0078D4)
![Tests](https://img.shields.io/badge/Tests-192%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

## Features

### Packet Capture & Analysis
- **Live capture** via SharpPcap with per-interface selection and BPF filters
- **Protocol dissection** for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, and ARP
- **Display filter engine** with expression syntax (`ip.src == 192.168.1.1 && tcp.dstport == 443`)
- **PCAP export/import** — save captures and load `.pcap` files for offline analysis
- **Wireshark integration** — open current capture directly in Wireshark
- **TCP stream reassembly** — follow and reconstruct TCP conversations
- **Packet bookmarks** — star packets of interest and filter to bookmarked-only view

### Intrusion Detection (6 Modules)
| Module | What It Detects |
|---|---|
| **Port Scan Detector** | SYN/FIN/XMAS/NULL scans via unique dest port tracking in sliding windows |
| **DNS Anomaly Detector** | DGA domains, DNS tunneling, and high-entropy subdomain labels |
| **C2 Beacon Detector** | Periodic beaconing via coefficient of variation + DBSCAN clustering |
| **ARP Spoof Detector** | MAC-to-IP mapping changes with escalation on rapid MAC flapping |
| **Brute Force Detector** | Connection floods to SSH, RDP, SMB, MySQL, PostgreSQL, Telnet |
| **Payload Pattern Detector** | Signature-based matching for SQLi, command injection, directory traversal |

### Network Visualization
- **Force-directed graph** — live topology map with nodes sized by traffic volume
- **Protocol-colored edges** — TCP, UDP, DNS, HTTP each get distinct colors
- **Interactive** — drag nodes, scroll to zoom, click-and-drag to pan
- **GPU-accelerated** — SkiaSharp rendering at 30fps

### Statistics Dashboard
- **Protocol distribution** — real-time pie chart of traffic by protocol
- **Top talkers** — horizontal bar chart of highest-volume IP addresses
- **Bandwidth over time** — line chart with per-second throughput for the last 60 seconds

### Packet Crafting
- **Layer-by-layer builder** — Ethernet, IPv4, TCP/UDP/ICMP, and payload fields
- **5 built-in templates** — ARP Request, ICMP Echo, TCP SYN, DNS Query, HTTP GET
- **Capture-modify-replay** — right-click any captured packet, send to crafter, modify, and resend
- **Auto-checksums** — IP and TCP/UDP checksums computed automatically

### Additional Features
- **Alert webhooks** — POST alerts to Slack, Discord, or any webhook endpoint
- **TLS fingerprinting** — JA3 hash computation from ClientHello messages
- **DNS resolver cache** — async reverse DNS lookups with background resolution
- **GeoIP lookups** — country, city, and ISP via ip-api.com (rate-limited)
- **Capture profiles** — save and restore device + filter combinations
- **Dark/light themes** — toggle between Catppuccin Mocha dark and a clean light theme
- **Plugin system** — drop custom IDS module DLLs into `plugins/` for runtime loading
- **Configurable** — JSON settings for all detection thresholds, physics constants, and UI preferences

## Tech Stack

| Package | Version | Purpose |
|---|---|---|
| [SharpPcap](https://github.com/dotpcap/sharppcap) | 6.3.1 | Packet capture and injection |
| [PacketDotNet](https://github.com/dotpcap/packetnet) | 1.4.8 | Packet parsing and construction |
| [SkiaSharp](https://github.com/mono/SkiaSharp) | 2.88.9 | GPU-accelerated graph and chart rendering |
| [CommunityToolkit.Mvvm](https://github.com/CommunityToolkit/dotnet) | 8.4.0 | MVVM framework with source generators |
| [System.Reactive](https://github.com/dotnet/reactive) | 6.0.1 | Reactive packet pipeline |
| [Microsoft.Extensions.DependencyInjection](https://github.com/dotnet/runtime) | 8.0.1 | DI container |
| [xUnit](https://xunit.net/) | 2.9.2 | Test framework |
| [FluentAssertions](https://fluentassertions.com/) | 7.0.0 | Test assertions |

## Project Structure

```
NetSpectre/
├── src/
│   ├── NetSpectre/                  # WPF app — views, themes, viewmodels
│   ├── NetSpectre.Core/             # Models, interfaces, filtering, analysis services
│   ├── NetSpectre.Capture/          # SharpPcap capture service, packet dissectors
│   ├── NetSpectre.Detection/        # IDS engine + 6 detection modules
│   ├── NetSpectre.Crafting/         # Packet builder, templates, crafting service
│   └── NetSpectre.Visualization/    # SkiaSharp graph renderer, statistics charts
├── tests/
│   ├── NetSpectre.Core.Tests/       # 61 tests
│   ├── NetSpectre.Capture.Tests/    # 7 tests
│   ├── NetSpectre.Detection.Tests/  # 61 tests
│   ├── NetSpectre.Crafting.Tests/   # 37 tests
│   └── NetSpectre.Visualization.Tests/ # 26 tests
├── examples/
│   └── NetSpectre.Plugin.Example/   # Sample ICMP flood detection plugin
├── Directory.Build.props            # Shared build settings (net8.0-windows, nullable)
└── Directory.Packages.props         # Central package version management
```

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Npcap](https://npcap.com/) (required for live packet capture)
- Windows 10/11 (WPF)

## Build & Run

```bash
# Clone
git clone https://github.com/brookandjubalseries-creator/NetSpectre.git
cd NetSpectre

# Build
dotnet build

# Run tests (192 tests, 0 warnings)
dotnet test

# Launch
dotnet run --project src/NetSpectre
```

## Architecture

```
┌──────────────┐    IObservable<PacketRecord>    ┌──────────────────┐
│  SharpPcap    │ ─────────────────────────────> │  Detection Engine │
│  Capture      │           │                    │  (6 IDS modules)  │
└──────────────┘           │                    └──────────────────┘
                           │                              │
                    Channel<PacketRecord>          AlertStream
                           │                              │
                    ┌──────┴──────┐              ┌────────┴────────┐
                    │  MainVM     │              │  AlertsViewModel │
                    │  (batched   │              │  + Webhook POST  │
                    │   UI flush) │              └─────────────────┘
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴────┐ ┌────┴─────┐ ┌────┴──────┐
        │ DataGrid  │ │ SkiaSharp│ │ Statistics │
        │ (packets) │ │ (graph)  │ │ (charts)  │
        └──────────┘ └──────────┘ └───────────┘
```

- **Reactive pipeline** — capture emits `IObservable<PacketRecord>`, detection and UI subscribe independently
- **Batched UI updates** — packets buffer in a `Channel<PacketRecord>` and flush every 100ms to keep the UI responsive at 10k+ pps
- **Interface-based detection** — every detector implements `IDetectionModule`, enabling unit testing and runtime plugin loading
- **SkiaSharp rendering** — GPU-accelerated custom drawing for the network graph and statistics charts at 30fps

## Writing a Plugin

Create a .NET 8 class library referencing `NetSpectre.Core`, implement `IPlugin`:

```csharp
public class MyPlugin : IPlugin
{
    public string Name => "My Plugin";
    public string Version => "1.0.0";
    public string Author => "You";

    public void Initialize() { }

    public IEnumerable<IDetectionModule> GetDetectionModules()
    {
        yield return new MyCustomDetector();
    }
}
```

Build and drop the DLL into the `plugins/` folder. NetSpectre loads it on startup.

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `F5` | Start capture |
| `F6` | Stop capture |
| `Ctrl+K` | Clear packets |
| `Ctrl+F` | Focus filter |
| `Ctrl+S` | Save PCAP |
| `Ctrl+O` | Load PCAP |
| `Ctrl+B` | Toggle bookmark |

## Configuration

Settings are stored in `%APPDATA%/NetSpectre/settings.json` and editable via the Settings dialog:

- **Capture** — buffer size, batch interval, promiscuous mode
- **Detection** — per-module enable/disable and threshold tuning
- **Visualization** — physics constants, max nodes, target FPS
- **Webhooks** — URL, enable/disable, critical-only filtering
- **Profiles** — saved device + filter combinations

## License

MIT
