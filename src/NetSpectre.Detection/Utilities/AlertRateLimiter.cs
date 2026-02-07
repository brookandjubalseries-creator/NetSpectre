namespace NetSpectre.Detection.Utilities;

public sealed class AlertRateLimiter
{
    private readonly Dictionary<string, SlidingWindow<bool>> _buckets = new();
    private readonly int _maxPerMinute;

    public AlertRateLimiter(int maxPerMinute = 10)
    {
        _maxPerMinute = maxPerMinute;
    }

    public bool IsAllowed(string detectorName)
    {
        if (!_buckets.TryGetValue(detectorName, out var window))
        {
            window = new SlidingWindow<bool>(TimeSpan.FromMinutes(1));
            _buckets[detectorName] = window;
        }

        if (window.Count >= _maxPerMinute)
            return false;

        window.Add(true);
        return true;
    }

    public void Clear() => _buckets.Clear();
}
