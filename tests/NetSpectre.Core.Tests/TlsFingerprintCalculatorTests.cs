using NetSpectre.Core.Analysis;
using Xunit;

namespace NetSpectre.Core.Tests;

public class TlsFingerprintCalculatorTests
{
    [Fact]
    public void ComputeJa3_EmptyData_ReturnsNull()
    {
        var result = TlsFingerprintCalculator.ComputeJa3(Array.Empty<byte>());
        Assert.Null(result);
    }

    [Fact]
    public void ComputeJa3_NonTlsData_ReturnsNull()
    {
        var data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        Assert.Null(TlsFingerprintCalculator.ComputeJa3(data));
    }

    [Fact]
    public void ComputeJa3_ValidClientHello_ReturnsHash()
    {
        // Construct a minimal TLS ClientHello
        // Record: 0x16 0x03 0x01 [length]
        // Handshake: 0x01 [3-byte length]
        // ClientHello: version(2) + random(32) + sessionId(1=0) + cipherSuites(4=2 suites) + compression(2)
        var hello = BuildMinimalClientHello(
            version: 0x0303,
            cipherSuites: new ushort[] { 0xc02c, 0xc02b },
            compressionMethods: new byte[] { 0x00 });

        var result = TlsFingerprintCalculator.ComputeJa3(hello);
        Assert.NotNull(result);
        Assert.Equal(32, result.Length); // MD5 hex = 32 chars
    }

    [Fact]
    public void ComputeJa3_SameInput_SameHash()
    {
        var hello = BuildMinimalClientHello(0x0303, new ushort[] { 0xc02c }, new byte[] { 0x00 });
        var hash1 = TlsFingerprintCalculator.ComputeJa3(hello);
        var hash2 = TlsFingerprintCalculator.ComputeJa3(hello);
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeJa3_DifferentCiphers_DifferentHash()
    {
        var hello1 = BuildMinimalClientHello(0x0303, new ushort[] { 0xc02c }, new byte[] { 0x00 });
        var hello2 = BuildMinimalClientHello(0x0303, new ushort[] { 0xc030 }, new byte[] { 0x00 });
        var hash1 = TlsFingerprintCalculator.ComputeJa3(hello1);
        var hash2 = TlsFingerprintCalculator.ComputeJa3(hello2);
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void GetKnownClient_UnknownHash_ReturnsNull()
    {
        Assert.Null(TlsFingerprintCalculator.GetKnownClient("0000000000000000"));
    }

    private static byte[] BuildMinimalClientHello(ushort version, ushort[] cipherSuites, byte[] compressionMethods)
    {
        var ms = new System.IO.MemoryStream();
        var w = new System.IO.BinaryWriter(ms);

        // ClientHello body
        var body = new System.IO.MemoryStream();
        var bw = new System.IO.BinaryWriter(body);

        // Version
        bw.Write((byte)(version >> 8));
        bw.Write((byte)(version & 0xFF));
        // Random (32 bytes)
        bw.Write(new byte[32]);
        // Session ID length = 0
        bw.Write((byte)0);
        // Cipher suites
        bw.Write((byte)((cipherSuites.Length * 2) >> 8));
        bw.Write((byte)((cipherSuites.Length * 2) & 0xFF));
        foreach (var cs in cipherSuites)
        {
            bw.Write((byte)(cs >> 8));
            bw.Write((byte)(cs & 0xFF));
        }
        // Compression methods
        bw.Write((byte)compressionMethods.Length);
        bw.Write(compressionMethods);
        // No extensions
        bw.Flush();
        var bodyBytes = body.ToArray();

        // Handshake header
        var handshake = new System.IO.MemoryStream();
        var hw = new System.IO.BinaryWriter(handshake);
        hw.Write((byte)0x01); // ClientHello
        hw.Write((byte)(bodyBytes.Length >> 16));
        hw.Write((byte)((bodyBytes.Length >> 8) & 0xFF));
        hw.Write((byte)(bodyBytes.Length & 0xFF));
        hw.Write(bodyBytes);
        hw.Flush();
        var handshakeBytes = handshake.ToArray();

        // TLS Record
        w.Write((byte)0x16); // Handshake
        w.Write((byte)0x03);
        w.Write((byte)0x01); // TLS 1.0 record version
        w.Write((byte)(handshakeBytes.Length >> 8));
        w.Write((byte)(handshakeBytes.Length & 0xFF));
        w.Write(handshakeBytes);
        w.Flush();

        return ms.ToArray();
    }
}
