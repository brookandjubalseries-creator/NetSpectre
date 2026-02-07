using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using NetSpectre.Core.Models;
using NetSpectre.Capture.Dissectors;

namespace NetSpectre.Capture;

public sealed class PcapFileService
{
    private readonly PacketDissector _dissector = new();

    /// <summary>
    /// Save packets to a .pcap file.
    /// </summary>
    public void SaveToPcap(string filePath, IEnumerable<PacketRecord> packets)
    {
        using var writer = new CaptureFileWriterDevice(filePath);
        writer.Open(LinkLayers.Ethernet);

        foreach (var packet in packets)
        {
            if (packet.RawData.Length > 0)
            {
                var timeval = new PosixTimeval(packet.Timestamp.ToUniversalTime());
                var rawCapture = new RawCapture(LinkLayers.Ethernet, timeval, packet.RawData);
                writer.Write(rawCapture);
            }
        }
    }

    /// <summary>
    /// Load packets from a .pcap file.
    /// </summary>
    public List<PacketRecord> LoadFromPcap(string filePath)
    {
        var packets = new List<PacketRecord>();

        using var reader = new CaptureFileReaderDevice(filePath);
        reader.Open();

        int number = 1;
        while (reader.GetNextPacket(out var capture) == GetPacketStatus.PacketRead)
        {
            try
            {
                var rawCapture = capture.GetPacket();
                var record = _dissector.Dissect(rawCapture, number++);
                packets.Add(record);
            }
            catch
            {
                // Skip malformed packets
            }
        }

        return packets;
    }
}
