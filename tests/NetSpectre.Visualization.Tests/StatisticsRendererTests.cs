using SkiaSharp;
using Xunit;

namespace NetSpectre.Visualization.Tests;

public class StatisticsRendererTests
{
    [Fact]
    public void RenderPieChart_EmptyData_DoesNotCrash()
    {
        var renderer = new StatisticsRenderer();
        using var bitmap = new SKBitmap(800, 400);
        using var canvas = new SKCanvas(bitmap);

        var ex = Record.Exception(() =>
            renderer.RenderPieChart(canvas, 800, 400, new Dictionary<string, long>(), "Empty Pie"));

        Assert.Null(ex);
    }

    [Fact]
    public void RenderPieChart_WithData_Renders()
    {
        var renderer = new StatisticsRenderer();
        using var bitmap = new SKBitmap(800, 400);
        using var canvas = new SKCanvas(bitmap);

        var data = new Dictionary<string, long>
        {
            ["TCP"] = 5000,
            ["UDP"] = 3000,
            ["ICMP"] = 1000,
            ["DNS"] = 500,
        };

        var ex = Record.Exception(() =>
            renderer.RenderPieChart(canvas, 800, 400, data, "Protocol Distribution"));

        Assert.Null(ex);
    }

    [Fact]
    public void RenderBarChart_EmptyData_DoesNotCrash()
    {
        var renderer = new StatisticsRenderer();
        using var bitmap = new SKBitmap(800, 400);
        using var canvas = new SKCanvas(bitmap);

        var ex = Record.Exception(() =>
            renderer.RenderBarChart(canvas, 800, 400, new List<KeyValuePair<string, long>>(), "Empty Bar"));

        Assert.Null(ex);
    }

    [Fact]
    public void RenderBarChart_WithData_Renders()
    {
        var renderer = new StatisticsRenderer();
        using var bitmap = new SKBitmap(800, 400);
        using var canvas = new SKCanvas(bitmap);

        var data = new List<KeyValuePair<string, long>>
        {
            new("192.168.1.1", 15000),
            new("10.0.0.5", 12000),
            new("172.16.0.1", 8000),
            new("192.168.1.100", 5000),
        };

        var ex = Record.Exception(() =>
            renderer.RenderBarChart(canvas, 800, 400, data, "Top Talkers"));

        Assert.Null(ex);
    }

    [Fact]
    public void RenderBandwidthChart_InsufficientData_ShowsMessage()
    {
        var renderer = new StatisticsRenderer();
        using var bitmap = new SKBitmap(800, 400);
        using var canvas = new SKCanvas(bitmap);

        // Only one data point - insufficient for a line chart
        var data = new List<(DateTime Time, double BytesPerSecond)>
        {
            (DateTime.UtcNow, 1000.0),
        };

        var ex = Record.Exception(() =>
            renderer.RenderBandwidthChart(canvas, 800, 400, data, "Bandwidth"));

        Assert.Null(ex);
    }

    [Fact]
    public void RenderBandwidthChart_WithData_Renders()
    {
        var renderer = new StatisticsRenderer();
        using var bitmap = new SKBitmap(800, 400);
        using var canvas = new SKCanvas(bitmap);

        var now = DateTime.UtcNow;
        var data = new List<(DateTime Time, double BytesPerSecond)>
        {
            (now.AddSeconds(-10), 1000.0),
            (now.AddSeconds(-9), 1500.0),
            (now.AddSeconds(-8), 2200.0),
            (now.AddSeconds(-7), 1800.0),
            (now.AddSeconds(-6), 3000.0),
            (now.AddSeconds(-5), 2500.0),
        };

        var ex = Record.Exception(() =>
            renderer.RenderBandwidthChart(canvas, 800, 400, data, "Bandwidth Over Time"));

        Assert.Null(ex);
    }
}
