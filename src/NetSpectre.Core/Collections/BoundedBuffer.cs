using System.Collections;

namespace NetSpectre.Core.Collections;

public sealed class BoundedBuffer<T> : IReadOnlyList<T>
{
    private readonly T[] _buffer;
    private readonly object _lock = new();
    private int _head;
    private int _count;

    public BoundedBuffer(int capacity = 50_000)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _buffer = new T[capacity];
    }

    public int Capacity => _buffer.Length;
    public int Count { get { lock (_lock) return _count; } }

    public void Add(T item)
    {
        lock (_lock)
        {
            _buffer[_head] = item;
            _head = (_head + 1) % _buffer.Length;
            if (_count < _buffer.Length) _count++;
        }
    }

    public T this[int index]
    {
        get
        {
            lock (_lock)
            {
                if (index < 0 || index >= _count)
                    throw new ArgumentOutOfRangeException(nameof(index));
                int start = _count < _buffer.Length ? 0 : _head;
                int actual = (start + index) % _buffer.Length;
                return _buffer[actual];
            }
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            Array.Clear(_buffer, 0, _buffer.Length);
            _head = 0;
            _count = 0;
        }
    }

    public List<T> ToList()
    {
        lock (_lock)
        {
            var list = new List<T>(_count);
            for (int i = 0; i < _count; i++)
                list.Add(this[i]);
            return list;
        }
    }

    public IEnumerator<T> GetEnumerator()
    {
        var snapshot = ToList();
        return snapshot.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
