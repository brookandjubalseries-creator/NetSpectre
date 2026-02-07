using System.Collections.Concurrent;
using System.Net;

namespace NetSpectre.Core.Analysis;

public sealed class DnsResolverCache
{
    private readonly ConcurrentDictionary<string, string?> _cache = new();
    private readonly ConcurrentDictionary<string, byte> _pending = new();

    /// <summary>
    /// Try to get a hostname for an IP. Returns null if not resolved yet.
    /// Triggers async resolution if not in cache.
    /// </summary>
    public string? TryResolve(string ipAddress)
    {
        if (_cache.TryGetValue(ipAddress, out var hostname))
            return hostname;

        // Don't resolve private IPs or already-a-hostname
        if (!IPAddress.TryParse(ipAddress, out _))
            return null;

        // Start async resolution (fire and forget, result cached for next lookup)
        if (_pending.TryAdd(ipAddress, 0))
        {
            _ = ResolveAsync(ipAddress);
        }

        return null;
    }

    /// <summary>
    /// Get cached hostname or return the IP as-is.
    /// </summary>
    public string GetDisplayName(string ipAddress)
    {
        var hostname = TryResolve(ipAddress);
        return hostname ?? ipAddress;
    }

    public int CacheSize => _cache.Count;

    public void Clear()
    {
        _cache.Clear();
        _pending.Clear();
    }

    private async Task ResolveAsync(string ipAddress)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ipAddress);
            _cache[ipAddress] = entry.HostName != ipAddress ? entry.HostName : null;
        }
        catch
        {
            _cache[ipAddress] = null; // Cache the failure too
        }
        finally
        {
            _pending.TryRemove(ipAddress, out _);
        }
    }
}
