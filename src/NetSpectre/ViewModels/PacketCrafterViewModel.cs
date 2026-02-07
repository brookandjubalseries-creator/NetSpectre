using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpectre.Crafting;
using NetSpectre.Core.Interfaces;

namespace NetSpectre.ViewModels;

public partial class PacketCrafterViewModel : ObservableObject
{
    private readonly PacketCraftingService _craftingService;
    private readonly ICaptureService? _captureService;
    private byte[]? _builtPacket;

    [ObservableProperty]
    private ObservableCollection<string> _templateNames = new();

    [ObservableProperty]
    private string? _selectedTemplate;

    [ObservableProperty]
    private string _srcMac = "00-00-00-00-00-00";

    [ObservableProperty]
    private string _dstMac = "FF-FF-FF-FF-FF-FF";

    [ObservableProperty]
    private string _srcIp = "192.168.1.100";

    [ObservableProperty]
    private string _dstIp = "192.168.1.1";

    [ObservableProperty]
    private string _ttl = "64";

    [ObservableProperty]
    private ObservableCollection<string> _protocols = new() { "TCP", "UDP", "ICMP" };

    [ObservableProperty]
    private string _selectedProtocol = "TCP";

    [ObservableProperty]
    private string _srcPort = "12345";

    [ObservableProperty]
    private string _dstPort = "80";

    [ObservableProperty]
    private string _payloadText = string.Empty;

    [ObservableProperty]
    private string _statusMessage = "Select a template or configure fields manually.";

    private string? _activeDeviceName;

    public PacketCrafterViewModel()
    {
        _craftingService = new PacketCraftingService();
        LoadTemplates();
    }

    public PacketCrafterViewModel(PacketCraftingService craftingService, ICaptureService? captureService)
    {
        _craftingService = craftingService;
        _captureService = captureService;
        LoadTemplates();
    }

    public void SetActiveDevice(string? deviceName)
    {
        _activeDeviceName = deviceName;
    }

    private void LoadTemplates()
    {
        TemplateNames.Clear();
        foreach (var name in _craftingService.GetTemplateNames())
            TemplateNames.Add(name);
    }

    partial void OnSelectedTemplateChanged(string? value)
    {
        if (value == null) return;

        var template = _craftingService.GetTemplate(value);
        if (template == null) return;

        // Apply template defaults based on template name
        switch (value)
        {
            case "ARP Request":
                SelectedProtocol = "TCP"; // ARP doesn't use transport
                DstMac = "FF-FF-FF-FF-FF-FF";
                StatusMessage = $"Template: {value} — set target IP and click Build.";
                break;
            case "ICMP Echo":
                SelectedProtocol = "ICMP";
                StatusMessage = $"Template: {value} — set destination IP and click Build.";
                break;
            case "TCP SYN":
                SelectedProtocol = "TCP";
                DstPort = "80";
                StatusMessage = $"Template: {value} — set destination IP/port and click Build.";
                break;
            case "DNS Query":
                SelectedProtocol = "UDP";
                DstPort = "53";
                DstIp = "8.8.8.8";
                StatusMessage = $"Template: {value} — modify payload for query domain.";
                break;
            case "HTTP GET":
                SelectedProtocol = "TCP";
                DstPort = "80";
                PayloadText = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
                StatusMessage = $"Template: {value} — edit payload and click Build.";
                break;
            default:
                StatusMessage = $"Template: {value} loaded.";
                break;
        }
    }

    [RelayCommand]
    private void BuildPacket()
    {
        try
        {
            var builder = new PacketBuilder();

            builder.SetEthernet(SrcMac, DstMac);

            if (SelectedProtocol == "ICMP")
            {
                builder.SetIPv4(SrcIp, DstIp, byte.TryParse(Ttl, out var t) ? t : (byte)64);
                builder.SetIcmpEchoRequest();
                if (!string.IsNullOrEmpty(PayloadText))
                    builder.SetPayload(PayloadText);
            }
            else if (SelectedProtocol == "TCP")
            {
                builder.SetIPv4(SrcIp, DstIp, byte.TryParse(Ttl, out var t) ? t : (byte)64);
                var src = ushort.TryParse(SrcPort, out var sp) ? sp : (ushort)12345;
                var dst = ushort.TryParse(DstPort, out var dp) ? dp : (ushort)80;
                builder.SetTcp(src, dst, syn: true);
                if (!string.IsNullOrEmpty(PayloadText))
                    builder.SetPayload(PayloadText);
            }
            else // UDP
            {
                builder.SetIPv4(SrcIp, DstIp, byte.TryParse(Ttl, out var t) ? t : (byte)64);
                var src = ushort.TryParse(SrcPort, out var sp) ? sp : (ushort)12345;
                var dst = ushort.TryParse(DstPort, out var dp) ? dp : (ushort)53;
                builder.SetUdp(src, dst);
                if (!string.IsNullOrEmpty(PayloadText))
                    builder.SetPayload(PayloadText);
            }

            _builtPacket = builder.Build();
            StatusMessage = $"Packet built — {_builtPacket.Length} bytes. Ready to send.";
        }
        catch (Exception ex)
        {
            _builtPacket = null;
            StatusMessage = $"Build error: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task SendPacket()
    {
        if (_builtPacket == null)
        {
            StatusMessage = "No packet built — click Build first.";
            return;
        }

        if (string.IsNullOrEmpty(_activeDeviceName))
        {
            StatusMessage = "No capture interface selected — select an interface in the toolbar.";
            return;
        }

        try
        {
            StatusMessage = "Sending...";
            var success = await _craftingService.SendPacketAsync(_builtPacket, _activeDeviceName);
            StatusMessage = success
                ? $"Packet sent ({_builtPacket.Length} bytes) on {_activeDeviceName}."
                : "Send failed — check interface and permissions.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Send error: {ex.Message}";
        }
    }

    public void LoadFromPacket(Core.Models.PacketRecord packet)
    {
        SrcIp = packet.SourceAddress;
        DstIp = packet.DestinationAddress;

        // Set protocol from packet
        var proto = packet.Protocol.ToUpperInvariant();
        if (proto == "TCP" || proto == "UDP" || proto == "ICMP")
            SelectedProtocol = proto;

        StatusMessage = $"Loaded packet #{packet.Number} — modify fields and click Build.";
    }
}
