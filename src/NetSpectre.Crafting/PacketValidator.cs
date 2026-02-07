using System.Net;

namespace NetSpectre.Crafting;

public sealed class PacketValidator
{
    private readonly List<string> _errors = new();

    public IReadOnlyList<string> Errors => _errors.AsReadOnly();
    public bool IsValid => _errors.Count == 0;

    public PacketValidator ValidateIpAddress(string? address, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            _errors.Add($"{fieldName} is required.");
            return this;
        }
        if (!IPAddress.TryParse(address, out _))
            _errors.Add($"{fieldName} is not a valid IP address: {address}");
        return this;
    }

    public PacketValidator ValidateMacAddress(string? address, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            _errors.Add($"{fieldName} is required.");
            return this;
        }
        var normalized = address.Replace(':', '-').Replace('.', '-').ToUpperInvariant();
        var parts = normalized.Split('-');
        if (parts.Length != 6 || !parts.All(p => p.Length == 2 && p.All(IsHexChar)))
            _errors.Add($"{fieldName} is not a valid MAC address: {address}");
        return this;
    }

    public PacketValidator ValidatePort(int port, string fieldName)
    {
        if (port < 0 || port > 65535)
            _errors.Add($"{fieldName} must be between 0 and 65535. Got: {port}");
        return this;
    }

    public PacketValidator ValidateTtl(int ttl)
    {
        if (ttl < 1 || ttl > 255)
            _errors.Add($"TTL must be between 1 and 255. Got: {ttl}");
        return this;
    }

    public PacketValidator ValidatePayloadSize(byte[]? payload, int maxSize = 65507)
    {
        if (payload != null && payload.Length > maxSize)
            _errors.Add($"Payload size ({payload.Length} bytes) exceeds maximum ({maxSize} bytes).");
        return this;
    }

    public PacketValidator Clear()
    {
        _errors.Clear();
        return this;
    }

    private static bool IsHexChar(char c) =>
        c is (>= '0' and <= '9') or (>= 'A' and <= 'F') or (>= 'a' and <= 'f');
}
