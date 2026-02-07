using NetSpectre.Core.Collections;
using Xunit;

namespace NetSpectre.Core.Tests;

public class BoundedBufferTests
{
    [Fact]
    public void Add_WithinCapacity_IncrementsCount()
    {
        var buffer = new BoundedBuffer<int>(10);
        buffer.Add(1);
        buffer.Add(2);
        Assert.Equal(2, buffer.Count);
    }

    [Fact]
    public void Add_ExceedsCapacity_OverwritesOldest()
    {
        var buffer = new BoundedBuffer<int>(3);
        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);
        buffer.Add(4);
        Assert.Equal(3, buffer.Count);
        Assert.Equal(2, buffer[0]);
        Assert.Equal(3, buffer[1]);
        Assert.Equal(4, buffer[2]);
    }

    [Fact]
    public void Clear_ResetsBuffer()
    {
        var buffer = new BoundedBuffer<int>(10);
        buffer.Add(1);
        buffer.Add(2);
        buffer.Clear();
        Assert.Empty(buffer);
    }

    [Fact]
    public void Indexer_OutOfRange_Throws()
    {
        var buffer = new BoundedBuffer<int>(10);
        buffer.Add(1);
        Assert.Throws<ArgumentOutOfRangeException>(() => buffer[5]);
    }

    [Fact]
    public void Constructor_ZeroCapacity_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedBuffer<int>(0));
    }

    [Fact]
    public void ToList_ReturnsCorrectOrder()
    {
        var buffer = new BoundedBuffer<int>(3);
        buffer.Add(10);
        buffer.Add(20);
        buffer.Add(30);
        buffer.Add(40);
        var list = buffer.ToList();
        Assert.Equal(new[] { 20, 30, 40 }, list);
    }
}
