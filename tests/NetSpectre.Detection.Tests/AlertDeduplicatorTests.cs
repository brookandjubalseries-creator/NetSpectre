using NetSpectre.Core.Models;
using NetSpectre.Detection.Utilities;
using Xunit;

namespace NetSpectre.Detection.Tests;

public class AlertDeduplicatorTests
{
    [Fact]
    public void IsDuplicate_FirstAlert_ReturnsFalse()
    {
        var dedup = new AlertDeduplicator();
        var alert = new AlertRecord
        {
            DetectorName = "TestDetector",
            Title = "Test Alert",
            SourceAddress = "192.168.1.1"
        };
        Assert.False(dedup.IsDuplicate(alert));
    }

    [Fact]
    public void IsDuplicate_SameAlertTwice_ReturnsTrueForSecond()
    {
        var dedup = new AlertDeduplicator();
        var alert = new AlertRecord
        {
            DetectorName = "TestDetector",
            Title = "Test Alert",
            SourceAddress = "192.168.1.1"
        };
        dedup.IsDuplicate(alert);
        Assert.True(dedup.IsDuplicate(alert));
    }

    [Fact]
    public void IsDuplicate_DifferentSource_ReturnsFalse()
    {
        var dedup = new AlertDeduplicator();
        var alert1 = new AlertRecord
        {
            DetectorName = "TestDetector",
            Title = "Test Alert",
            SourceAddress = "192.168.1.1"
        };
        var alert2 = new AlertRecord
        {
            DetectorName = "TestDetector",
            Title = "Test Alert",
            SourceAddress = "192.168.1.2"
        };
        dedup.IsDuplicate(alert1);
        Assert.False(dedup.IsDuplicate(alert2));
    }

    [Fact]
    public void Clear_AllowsSameAlertAgain()
    {
        var dedup = new AlertDeduplicator();
        var alert = new AlertRecord
        {
            DetectorName = "TestDetector",
            Title = "Test Alert",
            SourceAddress = "192.168.1.1"
        };
        dedup.IsDuplicate(alert);
        dedup.Clear();
        Assert.False(dedup.IsDuplicate(alert));
    }
}

public class SlidingWindowTests
{
    [Fact]
    public void Count_ReturnsItemsWithinWindow()
    {
        var window = new SlidingWindow<int>(TimeSpan.FromMinutes(5));
        window.Add(1);
        window.Add(2);
        window.Add(3);
        Assert.Equal(3, window.Count);
    }

    [Fact]
    public void GetValues_ReturnsCorrectValues()
    {
        var window = new SlidingWindow<string>(TimeSpan.FromMinutes(5));
        window.Add("a");
        window.Add("b");
        var values = window.GetValues();
        Assert.Equal(2, values.Count);
        Assert.Contains("a", values);
        Assert.Contains("b", values);
    }

    [Fact]
    public void Clear_RemovesAll()
    {
        var window = new SlidingWindow<int>(TimeSpan.FromMinutes(5));
        window.Add(1);
        window.Add(2);
        window.Clear();
        Assert.Equal(0, window.Count);
    }
}
