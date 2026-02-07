using System.Text;
using NetSpectre.Core.Models;

namespace NetSpectre.Core.Analysis;

public sealed class TcpStream
{
    public string StreamId { get; set; } = string.Empty;
    public string ClientAddress { get; set; } = string.Empty;
    public int ClientPort { get; set; }
    public string ServerAddress { get; set; } = string.Empty;
    public int ServerPort { get; set; }
    public List<TcpStreamSegment> Segments { get; set; } = new();
    public byte[] ReassembledData => Segments.SelectMany(s => s.Data).ToArray();
    public string Protocol { get; set; } = "TCP";
    public int PacketCount => Segments.Count;

    public string GetTextContent()
    {
        var data = ReassembledData;
        try { return Encoding.UTF8.GetString(data); }
        catch { return Encoding.ASCII.GetString(data); }
    }
}

public sealed class TcpStreamSegment
{
    public DateTime Timestamp { get; set; }
    public bool IsFromClient { get; set; }
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public int PacketNumber { get; set; }
}

public sealed class TcpStreamReassembler
{
    private readonly Dictionary<string, TcpStream> _streams = new();

    /// <summary>
    /// Get a unique stream ID for a packet's TCP connection (bidirectional).
    /// </summary>
    private static string GetStreamId(string srcIp, int srcPort, string dstIp, int dstPort)
    {
        // Normalize so both directions map to same stream
        var a = $"{srcIp}:{srcPort}";
        var b = $"{dstIp}:{dstPort}";
        return string.Compare(a, b, StringComparison.Ordinal) < 0 ? $"{a}<>{b}" : $"{b}<>{a}";
    }

    /// <summary>
    /// Process a packet and add it to the appropriate stream.
    /// </summary>
    public void ProcessPacket(PacketRecord packet)
    {
        if (packet.Protocol != "TCP" && packet.Protocol != "HTTP" && packet.Protocol != "TLS") return;
        if (packet.RawData.Length == 0) return;

        // Extract ports from packet layers
        int srcPort = 0, dstPort = 0;

        foreach (var layer in packet.Layers.LayerStack)
        {
            if (layer.Name.Contains("TCP", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var field in layer.Fields)
                {
                    if (field.Name == "Source Port" && int.TryParse(field.Value, out var sp)) srcPort = sp;
                    if (field.Name == "Destination Port" && int.TryParse(field.Value, out var dp)) dstPort = dp;
                }
            }
        }

        if (srcPort == 0 || dstPort == 0) return;

        var streamId = GetStreamId(packet.SourceAddress, srcPort, packet.DestinationAddress, dstPort);

        if (!_streams.TryGetValue(streamId, out var stream))
        {
            stream = new TcpStream
            {
                StreamId = streamId,
                ClientAddress = packet.SourceAddress,
                ClientPort = srcPort,
                ServerAddress = packet.DestinationAddress,
                ServerPort = dstPort,
            };

            // Determine protocol from port
            stream.Protocol = dstPort switch
            {
                80 => "HTTP",
                443 => "HTTPS/TLS",
                22 => "SSH",
                21 => "FTP",
                25 or 587 => "SMTP",
                _ => "TCP"
            };

            _streams[streamId] = stream;
        }

        // Determine direction
        bool isClient = packet.SourceAddress == stream.ClientAddress && srcPort == stream.ClientPort;

        // Extract TCP payload (simplified - use raw data minus headers)
        // The actual payload extraction would need TCP header offset
        // For display purposes, we note the packet in the stream
        stream.Segments.Add(new TcpStreamSegment
        {
            Timestamp = packet.Timestamp,
            IsFromClient = isClient,
            Data = packet.RawData, // Full packet data for reference
            PacketNumber = packet.Number,
        });
    }

    /// <summary>
    /// Get all streams.
    /// </summary>
    public IReadOnlyList<TcpStream> GetStreams() => _streams.Values.ToList().AsReadOnly();

    /// <summary>
    /// Get stream for a specific packet.
    /// </summary>
    public TcpStream? GetStreamForPacket(PacketRecord packet)
    {
        if (packet.Protocol != "TCP" && packet.Protocol != "HTTP" && packet.Protocol != "TLS") return null;

        // Find stream containing this packet number
        return _streams.Values.FirstOrDefault(s =>
            s.Segments.Any(seg => seg.PacketNumber == packet.Number));
    }

    /// <summary>
    /// Get stream by ID.
    /// </summary>
    public TcpStream? GetStream(string streamId)
    {
        return _streams.GetValueOrDefault(streamId);
    }

    public int StreamCount => _streams.Count;

    public void Clear()
    {
        _streams.Clear();
    }
}
