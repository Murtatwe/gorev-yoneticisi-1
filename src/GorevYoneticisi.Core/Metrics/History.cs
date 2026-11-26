namespace GorevYoneticisi.Core.Metrics;

/// <summary>Fixed-size ring buffer of recent values, for live graphs.</summary>
public sealed class History
{
    private readonly double[] _buffer;
    private int _start;

    public History(int capacity)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _buffer = new double[capacity];
    }

    public int Capacity => _buffer.Length;
    public int Count { get; private set; }

    public double Latest => Count == 0 ? 0 : _buffer[(_start + Count - 1) % _buffer.Length];

    public void Add(double value)
    {
        if (Count < _buffer.Length)
        {
            _buffer[(_start + Count) % _buffer.Length] = value;
            Count++;
        }
        else
        {
            _buffer[_start] = value;
            _start = (_start + 1) % _buffer.Length;
        }
    }

    /// <summary>Values from oldest to newest.</summary>
    public double[] ToArray()
    {
        var result = new double[Count];
        for (int i = 0; i < Count; i++) result[i] = _buffer[(_start + i) % _buffer.Length];
        return result;
    }
}
