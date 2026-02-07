using System.Text;

namespace NetSpectre.Crafting.Templates;

public sealed class HttpGetTemplate : PacketTemplate
{
    public override string Name => "HTTP GET";
    public override string Description => "HTTP GET request over TCP port 80.";

    public string SourceIp { get; set; } = "192.168.1.1";
    public string DestinationIp { get; set; } = "192.168.1.2";
    public string Path { get; set; } = "/";
    public string Host { get; set; } = "example.com";

    public override PacketBuilder Apply(PacketBuilder builder)
    {
        var httpPayload = BuildHttpGetPayload();
        return builder
            .SetEthernet("00-11-22-33-44-55", "FF-FF-FF-FF-FF-FF")
            .SetIPv4(SourceIp, DestinationIp)
            .SetTcp(12345, 80, psh: true, ack: true)
            .SetPayload(httpPayload);
    }

    private byte[] BuildHttpGetPayload()
    {
        var request = $"GET {Path} HTTP/1.1\r\nHost: {Host}\r\nConnection: close\r\n\r\n";
        return Encoding.ASCII.GetBytes(request);
    }
}
