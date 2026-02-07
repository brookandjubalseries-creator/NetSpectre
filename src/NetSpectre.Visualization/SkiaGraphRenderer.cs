using NetSpectre.Core.Models;
using SkiaSharp;

namespace NetSpectre.Visualization;

public sealed class SkiaGraphRenderer
{
    private static readonly Dictionary<string, SKColor> ProtocolColors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["TCP"] = new SKColor(0x89, 0xB4, 0xFA),
        ["UDP"] = new SKColor(0xA6, 0xE3, 0xA1),
        ["DNS"] = new SKColor(0xCB, 0xA6, 0xF7),
        ["HTTP"] = new SKColor(0xF9, 0xE2, 0xAF),
        ["HTTPS"] = new SKColor(0xFA, 0xB3, 0x87),
        ["ICMP"] = new SKColor(0xF3, 0x8B, 0xA8),
        ["ARP"] = new SKColor(0x94, 0xE2, 0xD5),
    };

    private static readonly SKColor DefaultEdgeColor = new(0xA6, 0xAD, 0xC8);
    private static readonly SKColor NodeColor = new(0x89, 0xB4, 0xFA);
    private static readonly SKColor FlaggedNodeColor = new(0xF3, 0x8B, 0xA8);
    private static readonly SKColor BackgroundColor = new(0x1E, 0x1E, 0x2E);
    private static readonly SKColor TextColor = new(0xCD, 0xD6, 0xF4);

    public float OffsetX { get; set; }
    public float OffsetY { get; set; }
    public float Zoom { get; set; } = 1f;

    public void Render(SKCanvas canvas, int width, int height,
        IReadOnlyList<NetworkNode> nodes, IReadOnlyList<NetworkEdge> edges,
        Dictionary<string, NetworkNode> nodeLookup)
    {
        canvas.Clear(BackgroundColor);
        canvas.Save();
        canvas.Translate(width / 2f + OffsetX, height / 2f + OffsetY);
        canvas.Scale(Zoom);

        foreach (var edge in edges)
        {
            if (!nodeLookup.TryGetValue(edge.SourceAddress, out var src)) continue;
            if (!nodeLookup.TryGetValue(edge.DestinationAddress, out var dst)) continue;

            var color = ProtocolColors.GetValueOrDefault(edge.Protocol, DefaultEdgeColor);
            using var paint = new SKPaint
            {
                Color = color.WithAlpha(120),
                StrokeWidth = edge.Thickness,
                IsAntialias = true,
                Style = SKPaintStyle.Stroke,
            };
            canvas.DrawLine(src.X, src.Y, dst.X, dst.Y, paint);
        }

        foreach (var node in nodes)
        {
            var radius = Math.Max(8f, node.Radius);

            if (node.IsFlagged)
            {
                using var glowPaint = new SKPaint
                {
                    Color = FlaggedNodeColor.WithAlpha(60),
                    IsAntialias = true,
                    Style = SKPaintStyle.Fill,
                    MaskFilter = SKMaskFilter.CreateBlur(SKBlurStyle.Normal, 8f),
                };
                canvas.DrawCircle(node.X, node.Y, radius + 6, glowPaint);
            }

            var nodeColor = node.IsFlagged ? FlaggedNodeColor : NodeColor;
            using var fillPaint = new SKPaint
            {
                Color = nodeColor,
                IsAntialias = true,
                Style = SKPaintStyle.Fill,
            };
            canvas.DrawCircle(node.X, node.Y, radius, fillPaint);

            using var borderPaint = new SKPaint
            {
                Color = nodeColor.WithAlpha(200),
                IsAntialias = true,
                Style = SKPaintStyle.Stroke,
                StrokeWidth = 1.5f,
            };
            canvas.DrawCircle(node.X, node.Y, radius, borderPaint);

            var label = node.Label ?? node.Address;
            using var textPaint = new SKPaint
            {
                Color = TextColor,
                IsAntialias = true,
                TextSize = 11,
            };
            var textWidth = textPaint.MeasureText(label);
            canvas.DrawText(label, node.X - textWidth / 2, node.Y + radius + 14, textPaint);
        }

        canvas.Restore();
    }
}
