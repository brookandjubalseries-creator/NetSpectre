using NetSpectre.Core.Analysis;
using Xunit;

namespace NetSpectre.Core.Tests;

public class DnsResolverCacheTests
{
    [Fact]
    public void TryResolve_FirstCall_ReturnsNull()
    {
        var cache = new DnsResolverCache();
        // First call triggers async resolution; result is not yet available
        var result = cache.TryResolve("8.8.8.8");
        Assert.Null(result);
    }

    [Fact]
    public void GetDisplayName_NotYetResolved_ReturnsIp()
    {
        var cache = new DnsResolverCache();
        var displayName = cache.GetDisplayName("192.168.1.1");
        Assert.Equal("192.168.1.1", displayName);
    }

    [Fact]
    public void Clear_EmptiesCache()
    {
        var cache = new DnsResolverCache();
        // Trigger a resolution to populate pending/cache
        cache.TryResolve("127.0.0.1");
        cache.Clear();
        Assert.Equal(0, cache.CacheSize);
    }

    [Fact]
    public void TryResolve_NonIpInput_ReturnsNull()
    {
        var cache = new DnsResolverCache();
        // A hostname string (not an IP) should return null without triggering resolution
        var result = cache.TryResolve("not-an-ip-address");
        Assert.Null(result);
    }

    [Fact]
    public void CacheSize_InitiallyZero()
    {
        var cache = new DnsResolverCache();
        Assert.Equal(0, cache.CacheSize);
    }
}
