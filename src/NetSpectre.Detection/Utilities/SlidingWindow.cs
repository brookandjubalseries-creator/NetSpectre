namespace NetSpectre.Detection.Utilities;

public sealed class SlidingWindow<T>
{
    private readonly List<(DateTime Timestamp, T Value)> _items = new();
    private readonly TimeSpan _windowSize;

    public SlidingWindow(TimeSpan windowSize)
    {
        _windowSize = windowSize;
    }

    public int Count
    {
        get
        {
            Cleanup();
            return _items.Count;
        }
    }

    public void Add(T value, DateTime? timestamp = null)
    {
        var ts = timestamp ?? DateTime.UtcNow;
        _items.Add((ts, value));
        Cleanup();
    }

    public IReadOnlyList<T> GetValues()
    {
        Cleanup();
        return _items.Select(i => i.Value).ToList();
    }

    public IReadOnlyList<(DateTime Timestamp, T Value)> GetEntries()
    {
        Cleanup();
        return _items.ToList();
    }

    public void Clear() => _items.Clear();

    private void Cleanup()
    {
        var cutoff = DateTime.UtcNow - _windowSize;
        _items.RemoveAll(i => i.Timestamp < cutoff);
    }
}
