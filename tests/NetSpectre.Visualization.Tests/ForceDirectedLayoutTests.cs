using NetSpectre.Core.Models;
using Xunit;

namespace NetSpectre.Visualization.Tests;

public class ForceDirectedLayoutTests
{
    [Fact]
    public void AddNode_NewNode_AddsToCollection()
    {
        var layout = new ForceDirectedLayout();
        var node = new NetworkNode { Address = "192.168.1.1" };

        layout.AddNode(node);

        Assert.Single(layout.Nodes);
        Assert.Equal("192.168.1.1", layout.Nodes[0].Address);
    }

    [Fact]
    public void AddNode_DuplicateAddress_IgnoresDuplicate()
    {
        var layout = new ForceDirectedLayout();
        layout.AddNode(new NetworkNode { Address = "10.0.0.1" });
        layout.AddNode(new NetworkNode { Address = "10.0.0.1" });

        Assert.Single(layout.Nodes);
    }

    [Fact]
    public void AddNode_ZeroPosition_RandomizesPosition()
    {
        var layout = new ForceDirectedLayout();
        var node = new NetworkNode { Address = "10.0.0.1", X = 0, Y = 0 };

        layout.AddNode(node);

        Assert.True(node.X != 0 || node.Y != 0);
    }

    [Fact]
    public void AddEdge_NewEdge_AddsToCollection()
    {
        var layout = new ForceDirectedLayout();
        var edge = new NetworkEdge
        {
            SourceAddress = "10.0.0.1",
            DestinationAddress = "10.0.0.2",
            Protocol = "TCP"
        };

        layout.AddEdge(edge);

        Assert.Single(layout.Edges);
    }

    [Fact]
    public void AddEdge_DuplicateEdge_AggregatesTraffic()
    {
        var layout = new ForceDirectedLayout();
        layout.AddEdge(new NetworkEdge
        {
            SourceAddress = "10.0.0.1",
            DestinationAddress = "10.0.0.2",
            TotalBytes = 100,
            PacketCount = 1
        });
        layout.AddEdge(new NetworkEdge
        {
            SourceAddress = "10.0.0.1",
            DestinationAddress = "10.0.0.2",
            TotalBytes = 200,
            PacketCount = 2
        });

        Assert.Single(layout.Edges);
        Assert.Equal(300, layout.Edges[0].TotalBytes);
        Assert.Equal(3, layout.Edges[0].PacketCount);
    }

    [Fact]
    public void RemoveNode_ExistingNode_RemovesNodeAndEdges()
    {
        var layout = new ForceDirectedLayout();
        layout.AddNode(new NetworkNode { Address = "10.0.0.1" });
        layout.AddNode(new NetworkNode { Address = "10.0.0.2" });
        layout.AddEdge(new NetworkEdge
        {
            SourceAddress = "10.0.0.1",
            DestinationAddress = "10.0.0.2"
        });

        layout.RemoveNode("10.0.0.1");

        Assert.Single(layout.Nodes);
        Assert.Empty(layout.Edges);
    }

    [Fact]
    public void RemoveNode_NonExistent_NoEffect()
    {
        var layout = new ForceDirectedLayout();
        layout.AddNode(new NetworkNode { Address = "10.0.0.1" });

        layout.RemoveNode("10.0.0.99");

        Assert.Single(layout.Nodes);
    }

    [Fact]
    public void Step_TwoNodes_RepelsApart()
    {
        var layout = new ForceDirectedLayout();
        var a = new NetworkNode { Address = "A", X = -5, Y = 1 };
        var b = new NetworkNode { Address = "B", X = 10, Y = 1 };
        layout.AddNode(a);
        layout.AddNode(b);

        var initialAx = a.X;
        var initialBx = b.X;
        layout.Step(0.016f);

        Assert.True(a.X < initialAx, "Node A should be pushed left");
        Assert.True(b.X > initialBx, "Node B should be pushed right");
    }

    [Fact]
    public void Step_ConnectedNodes_AttractsToRest()
    {
        var layout = new ForceDirectedLayout();
        var a = new NetworkNode { Address = "A", X = -300, Y = 0 };
        var b = new NetworkNode { Address = "B", X = 300, Y = 0 };
        layout.AddNode(a);
        layout.AddNode(b);
        layout.AddEdge(new NetworkEdge { SourceAddress = "A", DestinationAddress = "B" });

        // Run many steps so attraction overcomes repulsion at large distance
        for (int i = 0; i < 100; i++)
            layout.Step(0.016f);

        var distance = MathF.Sqrt((a.X - b.X) * (a.X - b.X) + (a.Y - b.Y) * (a.Y - b.Y));
        Assert.True(distance < 600, "Connected nodes should attract towards each other");
    }

    [Fact]
    public void Step_PinnedNode_DoesNotMove()
    {
        var layout = new ForceDirectedLayout();
        var pinned = new NetworkNode { Address = "A", X = 100, Y = 100, IsPinned = true };
        var other = new NetworkNode { Address = "B", X = 150, Y = 100 };
        layout.AddNode(pinned);
        layout.AddNode(other);

        layout.Step(0.016f);

        Assert.Equal(100f, pinned.X);
        Assert.Equal(100f, pinned.Y);
    }

    [Fact]
    public void Step_EmptyLayout_NoException()
    {
        var layout = new ForceDirectedLayout();
        var ex = Record.Exception(() => layout.Step(0.016f));
        Assert.Null(ex);
    }

    [Fact]
    public void Clear_RemovesAll()
    {
        var layout = new ForceDirectedLayout();
        layout.AddNode(new NetworkNode { Address = "A" });
        layout.AddNode(new NetworkNode { Address = "B" });
        layout.AddEdge(new NetworkEdge { SourceAddress = "A", DestinationAddress = "B" });

        layout.Clear();

        Assert.Empty(layout.Nodes);
        Assert.Empty(layout.Edges);
    }

    [Fact]
    public void GetNodeAt_HitInRadius_ReturnsNode()
    {
        var layout = new ForceDirectedLayout();
        var node = new NetworkNode { Address = "A", X = 100, Y = 100, Radius = 20 };
        layout.AddNode(node);

        var result = layout.GetNodeAt(105, 105);

        Assert.NotNull(result);
        Assert.Equal("A", result.Address);
    }

    [Fact]
    public void GetNodeAt_MissOutsideRadius_ReturnsNull()
    {
        var layout = new ForceDirectedLayout();
        var node = new NetworkNode { Address = "A", X = 100, Y = 100, Radius = 20 };
        layout.AddNode(node);

        var result = layout.GetNodeAt(200, 200);

        Assert.Null(result);
    }

    [Fact]
    public void Step_VelocityClamped_NeverExceedsMax()
    {
        var layout = new ForceDirectedLayout();
        // Place two nodes very close to create extreme repulsion
        var a = new NetworkNode { Address = "A", X = 0, Y = 0 };
        var b = new NetworkNode { Address = "B", X = 1, Y = 0 };
        layout.AddNode(a);
        layout.AddNode(b);

        layout.Step(0.05f);

        var speedA = MathF.Sqrt(a.VelocityX * a.VelocityX + a.VelocityY * a.VelocityY);
        var speedB = MathF.Sqrt(b.VelocityX * b.VelocityX + b.VelocityY * b.VelocityY);
        Assert.True(speedA <= 50f, $"Speed {speedA} exceeds max velocity");
        Assert.True(speedB <= 50f, $"Speed {speedB} exceeds max velocity");
    }
}

public class GraphInteractionHandlerTests
{
    [Fact]
    public void OnScroll_PositiveDelta_ZoomsIn()
    {
        var layout = new ForceDirectedLayout();
        var renderer = new SkiaGraphRenderer();
        var handler = new GraphInteractionHandler(layout, renderer);

        handler.OnScroll(120);

        Assert.True(renderer.Zoom > 1f);
    }

    [Fact]
    public void OnScroll_NegativeDelta_ZoomsOut()
    {
        var layout = new ForceDirectedLayout();
        var renderer = new SkiaGraphRenderer();
        var handler = new GraphInteractionHandler(layout, renderer);

        handler.OnScroll(-120);

        Assert.True(renderer.Zoom < 1f);
    }

    [Fact]
    public void OnScroll_ZoomClamped_MinMax()
    {
        var layout = new ForceDirectedLayout();
        var renderer = new SkiaGraphRenderer();
        var handler = new GraphInteractionHandler(layout, renderer);

        // Zoom out many times
        for (int i = 0; i < 100; i++)
            handler.OnScroll(-120);

        Assert.True(renderer.Zoom >= 0.1f);

        // Zoom in many times
        for (int i = 0; i < 200; i++)
            handler.OnScroll(120);

        Assert.True(renderer.Zoom <= 5f);
    }

    [Fact]
    public void OnMouseDown_RightButton_StartsPanning()
    {
        var layout = new ForceDirectedLayout();
        var renderer = new SkiaGraphRenderer();
        var handler = new GraphInteractionHandler(layout, renderer);

        handler.OnMouseDown(100, 100, 800, 600, rightButton: true);
        handler.OnMouseMove(150, 120, 800, 600);
        handler.OnMouseUp();

        Assert.True(renderer.OffsetX != 0 || renderer.OffsetY != 0);
    }

    [Fact]
    public void OnMouseDown_LeftOnNode_PinsAndDrags()
    {
        var layout = new ForceDirectedLayout();
        var renderer = new SkiaGraphRenderer();
        var handler = new GraphInteractionHandler(layout, renderer);

        // Use non-zero position to avoid AddNode randomization
        var node = new NetworkNode { Address = "A", X = 50, Y = 50, Radius = 50 };
        layout.AddNode(node);

        // Screen center (400,300) maps to world (0,0). Node is at (50,50) with radius 50.
        // Click at screen position that maps to world (50,50) = screen (450, 350) with no offset/zoom.
        handler.OnMouseDown(450, 350, 800, 600);

        Assert.True(node.IsPinned);

        handler.OnMouseUp();
        Assert.False(node.IsPinned);
    }
}
