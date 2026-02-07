using SkiaSharp;

namespace NetSpectre.Visualization;

public sealed class StatisticsRenderer
{
    private static readonly SKColor[] ChartColors = new[]
    {
        new SKColor(0x89, 0xB4, 0xFA), // Blue
        new SKColor(0xA6, 0xE3, 0xA1), // Green
        new SKColor(0xCB, 0xA6, 0xF7), // Purple
        new SKColor(0xF9, 0xE2, 0xAF), // Yellow
        new SKColor(0xF3, 0x8B, 0xA8), // Red
        new SKColor(0x94, 0xE2, 0xD5), // Teal
        new SKColor(0xFA, 0xB3, 0x87), // Orange
        new SKColor(0xF5, 0xC2, 0xE7), // Pink
    };

    private static readonly SKColor BackgroundColor = new(0x1E, 0x1E, 0x2E);
    private static readonly SKColor TextColor = new(0xCD, 0xD6, 0xF4);
    private static readonly SKColor DimTextColor = new(0x6C, 0x70, 0x86);

    /// <summary>
    /// Render a pie chart showing protocol distribution.
    /// </summary>
    public void RenderPieChart(SKCanvas canvas, int width, int height, Dictionary<string, long> data, string title)
    {
        canvas.Clear(BackgroundColor);

        if (data.Count == 0)
        {
            using var emptyPaint = new SKPaint { Color = DimTextColor, TextSize = 14, IsAntialias = true };
            canvas.DrawText("No data yet — start capturing", width / 2f - 100, height / 2f, emptyPaint);
            return;
        }

        // Title
        using var titlePaint = new SKPaint { Color = TextColor, TextSize = 16, IsAntialias = true, FakeBoldText = true };
        canvas.DrawText(title, 12, 24, titlePaint);

        var total = data.Values.Sum();
        if (total == 0) return;

        // Pie chart
        float centerX = width * 0.35f;
        float centerY = height * 0.55f;
        float radius = Math.Min(width * 0.25f, height * 0.35f);
        var rect = new SKRect(centerX - radius, centerY - radius, centerX + radius, centerY + radius);

        float startAngle = -90;
        int colorIdx = 0;
        var sorted = data.OrderByDescending(kv => kv.Value).ToList();

        foreach (var kv in sorted)
        {
            float sweepAngle = (float)kv.Value / total * 360f;
            var color = ChartColors[colorIdx % ChartColors.Length];
            using var paint = new SKPaint { Color = color, IsAntialias = true, Style = SKPaintStyle.Fill };
            canvas.DrawArc(rect, startAngle, sweepAngle, true, paint);
            startAngle += sweepAngle;
            colorIdx++;
        }

        // Legend
        float legendX = width * 0.65f;
        float legendY = 50;
        colorIdx = 0;
        using var legendPaint = new SKPaint { Color = TextColor, TextSize = 12, IsAntialias = true };

        foreach (var kv in sorted.Take(8))
        {
            var color = ChartColors[colorIdx % ChartColors.Length];
            using var dotPaint = new SKPaint { Color = color, IsAntialias = true };
            canvas.DrawCircle(legendX, legendY - 4, 5, dotPaint);

            var pct = (double)kv.Value / total * 100;
            canvas.DrawText($"{kv.Key}: {pct:F1}%", legendX + 14, legendY, legendPaint);
            legendY += 20;
            colorIdx++;
        }
    }

    /// <summary>
    /// Render a horizontal bar chart showing top talkers.
    /// </summary>
    public void RenderBarChart(SKCanvas canvas, int width, int height, List<KeyValuePair<string, long>> data, string title)
    {
        canvas.Clear(BackgroundColor);

        using var titlePaint = new SKPaint { Color = TextColor, TextSize = 16, IsAntialias = true, FakeBoldText = true };
        canvas.DrawText(title, 12, 24, titlePaint);

        if (data.Count == 0)
        {
            using var emptyPaint = new SKPaint { Color = DimTextColor, TextSize = 14, IsAntialias = true };
            canvas.DrawText("No data yet", width / 2f - 40, height / 2f, emptyPaint);
            return;
        }

        var maxVal = data.Max(kv => kv.Value);
        if (maxVal == 0) return;

        float barAreaX = 160;
        float barAreaWidth = width - barAreaX - 20;
        float barHeight = Math.Min(24, (height - 50) / (float)data.Count - 4);
        float y = 50;

        using var labelPaint = new SKPaint { Color = TextColor, TextSize = 11, IsAntialias = true };
        using var valuePaint = new SKPaint { Color = DimTextColor, TextSize = 11, IsAntialias = true };
        int colorIdx = 0;

        foreach (var kv in data.Take(10))
        {
            // Label
            var label = kv.Key.Length > 20 ? kv.Key[..17] + "..." : kv.Key;
            canvas.DrawText(label, 8, y + barHeight * 0.7f, labelPaint);

            // Bar
            float barWidth = (float)kv.Value / maxVal * barAreaWidth;
            var color = ChartColors[colorIdx % ChartColors.Length];
            using var barPaint = new SKPaint { Color = color.WithAlpha(200), IsAntialias = true };
            canvas.DrawRoundRect(barAreaX, y, barWidth, barHeight, 3, 3, barPaint);

            // Value
            var valueStr = FormatBytes(kv.Value);
            canvas.DrawText(valueStr, barAreaX + barWidth + 6, y + barHeight * 0.7f, valuePaint);

            y += barHeight + 4;
            colorIdx++;
        }
    }

    /// <summary>
    /// Render a bandwidth-over-time line chart.
    /// </summary>
    public void RenderBandwidthChart(SKCanvas canvas, int width, int height, List<(DateTime Time, double BytesPerSecond)> data, string title)
    {
        canvas.Clear(BackgroundColor);

        using var titlePaint = new SKPaint { Color = TextColor, TextSize = 16, IsAntialias = true, FakeBoldText = true };
        canvas.DrawText(title, 12, 24, titlePaint);

        if (data.Count < 2)
        {
            using var emptyPaint = new SKPaint { Color = DimTextColor, TextSize = 14, IsAntialias = true };
            canvas.DrawText("Collecting data...", width / 2f - 60, height / 2f, emptyPaint);
            return;
        }

        float chartLeft = 70, chartTop = 44, chartRight = width - 20, chartBottom = height - 30;
        float chartWidth = chartRight - chartLeft;
        float chartHeight = chartBottom - chartTop;

        // Axes
        using var axisPaint = new SKPaint { Color = DimTextColor, StrokeWidth = 1, IsAntialias = true };
        canvas.DrawLine(chartLeft, chartBottom, chartRight, chartBottom, axisPaint);
        canvas.DrawLine(chartLeft, chartTop, chartLeft, chartBottom, axisPaint);

        var maxBps = data.Max(d => d.BytesPerSecond);
        if (maxBps == 0) maxBps = 1;

        // Grid lines
        using var gridPaint = new SKPaint { Color = DimTextColor.WithAlpha(40), StrokeWidth = 1 };
        using var gridLabelPaint = new SKPaint { Color = DimTextColor, TextSize = 10, IsAntialias = true };
        for (int i = 1; i <= 4; i++)
        {
            float gy = chartBottom - (chartHeight * i / 4f);
            canvas.DrawLine(chartLeft, gy, chartRight, gy, gridPaint);
            canvas.DrawText(FormatBytes((long)(maxBps * i / 4)) + "/s", 2, gy + 4, gridLabelPaint);
        }

        // Line
        using var linePaint = new SKPaint
        {
            Color = ChartColors[0],
            StrokeWidth = 2,
            IsAntialias = true,
            Style = SKPaintStyle.Stroke,
        };

        var path = new SKPath();
        var minTime = data.Min(d => d.Time);
        var maxTime = data.Max(d => d.Time);
        var timeRange = (maxTime - minTime).TotalSeconds;
        if (timeRange < 1) timeRange = 1;

        for (int i = 0; i < data.Count; i++)
        {
            float x = chartLeft + (float)((data[i].Time - minTime).TotalSeconds / timeRange) * chartWidth;
            float y = chartBottom - (float)(data[i].BytesPerSecond / maxBps) * chartHeight;
            if (i == 0) path.MoveTo(x, y);
            else path.LineTo(x, y);
        }
        canvas.DrawPath(path, linePaint);

        // Fill under line
        using var fillPaint = new SKPaint
        {
            Color = ChartColors[0].WithAlpha(40),
            IsAntialias = true,
            Style = SKPaintStyle.Fill,
        };
        var fillPath = new SKPath(path);
        fillPath.LineTo(chartRight, chartBottom);
        fillPath.LineTo(chartLeft, chartBottom);
        fillPath.Close();
        canvas.DrawPath(fillPath, fillPaint);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1_000_000_000) return $"{bytes / 1_000_000_000.0:F1} GB";
        if (bytes >= 1_000_000) return $"{bytes / 1_000_000.0:F1} MB";
        if (bytes >= 1_000) return $"{bytes / 1_000.0:F1} KB";
        return $"{bytes} B";
    }
}
