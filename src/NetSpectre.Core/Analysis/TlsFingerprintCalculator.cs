using System.Security.Cryptography;
using System.Text;

namespace NetSpectre.Core.Analysis;

public static class TlsFingerprintCalculator
{
    /// <summary>
    /// Attempts to compute a JA3 hash from raw TLS ClientHello data.
    /// Returns null if the data is not a valid ClientHello.
    /// </summary>
    public static string? ComputeJa3(byte[] rawData)
    {
        // TLS record: ContentType(1) + Version(2) + Length(2) + Handshake
        // Handshake: Type(1, must be 0x01 for ClientHello) + Length(3) + ClientHello
        // ClientHello: Version(2) + Random(32) + SessionID(var) + CipherSuites(var) + Compression(var) + Extensions(var)
        //
        // JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        // Each field is a dash-separated list of decimal values
        // Final result is MD5 hash of the comma-separated string

        try
        {
            int offset = 0;

            // Find TLS record - scan for handshake content type (0x16)
            // In a captured packet, the TLS data may start after TCP payload offset
            int tlsStart = FindTlsRecord(rawData);
            if (tlsStart < 0) return null;
            offset = tlsStart;

            if (rawData.Length < offset + 5) return null;
            byte contentType = rawData[offset];
            if (contentType != 0x16) return null; // Not handshake

            // Skip record header
            offset += 5;

            if (rawData.Length < offset + 4) return null;
            byte handshakeType = rawData[offset];
            if (handshakeType != 0x01) return null; // Not ClientHello

            // Skip handshake header (type + 3-byte length)
            offset += 4;

            if (rawData.Length < offset + 2) return null;
            ushort clientVersion = (ushort)((rawData[offset] << 8) | rawData[offset + 1]);
            offset += 2;

            // Skip Random (32 bytes)
            offset += 32;
            if (rawData.Length < offset + 1) return null;

            // Skip Session ID
            byte sessionIdLen = rawData[offset];
            offset += 1 + sessionIdLen;
            if (rawData.Length < offset + 2) return null;

            // Cipher Suites
            ushort cipherSuitesLen = (ushort)((rawData[offset] << 8) | rawData[offset + 1]);
            offset += 2;
            var ciphers = new List<ushort>();
            int cipherEnd = offset + cipherSuitesLen;
            if (rawData.Length < cipherEnd) return null;
            while (offset < cipherEnd)
            {
                ushort cs = (ushort)((rawData[offset] << 8) | rawData[offset + 1]);
                // Skip GREASE values (0x0a0a, 0x1a1a, 0x2a2a, etc.)
                if ((cs & 0x0f0f) != 0x0a0a)
                    ciphers.Add(cs);
                offset += 2;
            }

            // Compression methods
            if (rawData.Length < offset + 1) return null;
            byte compLen = rawData[offset];
            offset += 1 + compLen;

            // Extensions
            var extensions = new List<ushort>();
            var ellipticCurves = new List<ushort>();
            var ecPointFormats = new List<byte>();

            if (rawData.Length >= offset + 2)
            {
                ushort extLen = (ushort)((rawData[offset] << 8) | rawData[offset + 1]);
                offset += 2;
                int extEnd = offset + extLen;

                while (offset + 4 <= extEnd && offset + 4 <= rawData.Length)
                {
                    ushort extType = (ushort)((rawData[offset] << 8) | rawData[offset + 1]);
                    ushort extDataLen = (ushort)((rawData[offset + 2] << 8) | rawData[offset + 3]);
                    offset += 4;

                    // Skip GREASE
                    if ((extType & 0x0f0f) != 0x0a0a)
                        extensions.Add(extType);

                    if (extType == 0x000a && offset + 2 <= rawData.Length) // supported_groups
                    {
                        ushort groupsLen = (ushort)((rawData[offset] << 8) | rawData[offset + 1]);
                        int gOffset = offset + 2;
                        int gEnd = gOffset + groupsLen;
                        while (gOffset + 2 <= gEnd && gOffset + 2 <= rawData.Length)
                        {
                            ushort group = (ushort)((rawData[gOffset] << 8) | rawData[gOffset + 1]);
                            if ((group & 0x0f0f) != 0x0a0a)
                                ellipticCurves.Add(group);
                            gOffset += 2;
                        }
                    }
                    else if (extType == 0x000b && offset + 1 <= rawData.Length) // ec_point_formats
                    {
                        byte fmtLen = rawData[offset];
                        for (int i = 0; i < fmtLen && offset + 1 + i < rawData.Length; i++)
                            ecPointFormats.Add(rawData[offset + 1 + i]);
                    }

                    offset += extDataLen;
                }
            }

            // Build JA3 string
            var ja3Raw = string.Join(",",
                clientVersion.ToString(),
                string.Join("-", ciphers),
                string.Join("-", extensions),
                string.Join("-", ellipticCurves),
                string.Join("-", ecPointFormats));

            // MD5 hash
            var hash = MD5.HashData(Encoding.ASCII.GetBytes(ja3Raw));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static int FindTlsRecord(byte[] data)
    {
        // Look for TLS handshake record (0x16) followed by valid version (0x0301-0x0304)
        for (int i = 0; i < data.Length - 5; i++)
        {
            if (data[i] == 0x16 && data[i + 1] == 0x03 && data[i + 2] >= 0x00 && data[i + 2] <= 0x04)
                return i;
        }
        return -1;
    }

    /// <summary>
    /// Get a human-readable description for known JA3 hashes.
    /// </summary>
    public static string? GetKnownClient(string ja3Hash)
    {
        return KnownJa3Hashes.GetValueOrDefault(ja3Hash);
    }

    private static readonly Dictionary<string, string> KnownJa3Hashes = new()
    {
        // Common browser/tool JA3 hashes (these are examples)
        ["e7d705a3286e19ea42f587b344ee6865"] = "Firefox",
        ["b32309a26951912be7dba376398abc3b"] = "Chrome",
        ["3b5074b1b5d032e5620f69f9f700ff0e"] = "curl",
        ["07e3d985f07f34e0a7b2b2e75a3e6105"] = "Python requests",
    };
}
