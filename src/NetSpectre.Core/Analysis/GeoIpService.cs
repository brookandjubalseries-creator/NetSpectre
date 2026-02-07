using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace NetSpectre.Core.Analysis;

public sealed class GeoIpLocation
{
    public string Country { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string Isp { get; set; } = string.Empty;
    public double Latitude { get; set; }
    public double Longitude { get; set; }
}

public sealed class GeoIpService : IDisposable
{
    private readonly HttpClient _httpClient = new();
    private readonly ConcurrentDictionary<string, GeoIpLocation?> _cache = new();
    private readonly ConcurrentDictionary<string, byte> _pending = new();
    private readonly SemaphoreSlim _rateLimiter = new(1, 1);
    private DateTime _lastRequest = DateTime.MinValue;

    /// <summary>
    /// Try to get location for an IP. Returns null if not yet resolved.
    /// Triggers async lookup if not cached.
    /// </summary>
    public GeoIpLocation? TryGetLocation(string ipAddress)
    {
        if (_cache.TryGetValue(ipAddress, out var location))
            return location;

        if (!IPAddress.TryParse(ipAddress, out var ip))
            return null;

        // Skip private/local IPs
        if (IsPrivateIp(ip))
            return null;

        if (_pending.TryAdd(ipAddress, 0))
            _ = LookupAsync(ipAddress);

        return null;
    }

    public GeoIpLocation? GetCached(string ipAddress)
    {
        _cache.TryGetValue(ipAddress, out var location);
        return location;
    }

    public int CacheSize => _cache.Count;

    private async Task LookupAsync(string ipAddress)
    {
        try
        {
            // Rate limit: max ~40 req/min to stay under ip-api.com limit
            await _rateLimiter.WaitAsync();
            try
            {
                var elapsed = DateTime.UtcNow - _lastRequest;
                if (elapsed.TotalMilliseconds < 1500)
                    await Task.Delay(1500 - (int)elapsed.TotalMilliseconds);
                _lastRequest = DateTime.UtcNow;
            }
            finally
            {
                _rateLimiter.Release();
            }

            var response = await _httpClient.GetStringAsync($"http://ip-api.com/json/{ipAddress}?fields=status,country,countryCode,regionName,city,lat,lon,isp");
            var json = JsonDocument.Parse(response);
            var root = json.RootElement;

            if (root.GetProperty("status").GetString() == "success")
            {
                _cache[ipAddress] = new GeoIpLocation
                {
                    Country = root.GetProperty("country").GetString() ?? "",
                    CountryCode = root.GetProperty("countryCode").GetString() ?? "",
                    City = root.GetProperty("city").GetString() ?? "",
                    Region = root.GetProperty("regionName").GetString() ?? "",
                    Isp = root.GetProperty("isp").GetString() ?? "",
                    Latitude = root.GetProperty("lat").GetDouble(),
                    Longitude = root.GetProperty("lon").GetDouble(),
                };
            }
            else
            {
                _cache[ipAddress] = null;
            }
        }
        catch
        {
            _cache[ipAddress] = null;
        }
        finally
        {
            _pending.TryRemove(ipAddress, out _);
        }
    }

    private static bool IsPrivateIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return true; // Skip IPv6 for now
        return bytes[0] switch
        {
            10 => true,
            172 => bytes[1] >= 16 && bytes[1] <= 31,
            192 => bytes[1] == 168,
            169 => bytes[1] == 254,
            _ => false,
        };
    }

    public void Clear() => _cache.Clear();

    public void Dispose()
    {
        _httpClient.Dispose();
        _rateLimiter.Dispose();
    }
}
