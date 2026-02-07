using NetSpectre.Core.Models;

namespace NetSpectre.Detection.Utilities;

public sealed class AlertDeduplicator
{
    private readonly Dictionary<string, DateTime> _recentAlerts = new();
    private readonly TimeSpan _window;

    public AlertDeduplicator(TimeSpan? window = null)
    {
        _window = window ?? TimeSpan.FromMinutes(5);
    }

    public bool IsDuplicate(AlertRecord alert)
    {
        var key = $"{alert.DetectorName}:{alert.Title}:{alert.SourceAddress}";
        CleanupExpired();

        if (_recentAlerts.TryGetValue(key, out var lastSeen))
        {
            if (DateTime.UtcNow - lastSeen < _window)
                return true;
        }

        _recentAlerts[key] = DateTime.UtcNow;
        return false;
    }

    public void Clear() => _recentAlerts.Clear();

    private void CleanupExpired()
    {
        var cutoff = DateTime.UtcNow - _window;
        var expired = _recentAlerts.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
        foreach (var key in expired)
            _recentAlerts.Remove(key);
    }
}
