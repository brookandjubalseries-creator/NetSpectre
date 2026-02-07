using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;

namespace NetSpectre.Visualization;

public sealed class ForceDirectedLayout : IGraphLayoutEngine
{
    private readonly List<NetworkNode> _nodes = new();
    private readonly List<NetworkEdge> _edges = new();
    private readonly Dictionary<string, NetworkNode> _nodeLookup = new();
    private readonly Random _random = new(42);

    private const float RepulsionForce = 5000f;
    private const float AttractionForce = 0.01f;
    private const float RestLength = 150f;
    private const float Damping = 0.85f;
    private const float MaxVelocity = 50f;

    public IReadOnlyList<NetworkNode> Nodes => _nodes.AsReadOnly();
    public IReadOnlyList<NetworkEdge> Edges => _edges.AsReadOnly();

    public void AddNode(NetworkNode node)
    {
        if (_nodeLookup.ContainsKey(node.Address)) return;
        if (node.X == 0 && node.Y == 0)
        {
            node.X = (float)(_random.NextDouble() * 800 - 400);
            node.Y = (float)(_random.NextDouble() * 600 - 300);
        }
        _nodes.Add(node);
        _nodeLookup[node.Address] = node;
    }

    public void AddEdge(NetworkEdge edge)
    {
        var existing = _edges.FirstOrDefault(e =>
            e.SourceAddress == edge.SourceAddress && e.DestinationAddress == edge.DestinationAddress);
        if (existing != null)
        {
            existing.TotalBytes += edge.TotalBytes;
            existing.PacketCount += edge.PacketCount;
            return;
        }
        _edges.Add(edge);
    }

    public void RemoveNode(string address)
    {
        if (_nodeLookup.TryGetValue(address, out var node))
        {
            _nodes.Remove(node);
            _nodeLookup.Remove(address);
            _edges.RemoveAll(e => e.SourceAddress == address || e.DestinationAddress == address);
        }
    }

    public void Step(float deltaTime)
    {
        if (_nodes.Count == 0) return;
        deltaTime = Math.Min(deltaTime, 0.05f);

        for (int i = 0; i < _nodes.Count; i++)
        {
            for (int j = i + 1; j < _nodes.Count; j++)
            {
                var a = _nodes[i];
                var b = _nodes[j];
                var dx = a.X - b.X;
                var dy = a.Y - b.Y;
                var dist = MathF.Sqrt(dx * dx + dy * dy);
                if (dist < 1f) dist = 1f;

                var force = RepulsionForce / (dist * dist);
                var fx = (dx / dist) * force;
                var fy = (dy / dist) * force;

                if (!a.IsPinned) { a.VelocityX += fx * deltaTime; a.VelocityY += fy * deltaTime; }
                if (!b.IsPinned) { b.VelocityX -= fx * deltaTime; b.VelocityY -= fy * deltaTime; }
            }
        }

        foreach (var edge in _edges)
        {
            if (!_nodeLookup.TryGetValue(edge.SourceAddress, out var src)) continue;
            if (!_nodeLookup.TryGetValue(edge.DestinationAddress, out var dst)) continue;

            var dx = dst.X - src.X;
            var dy = dst.Y - src.Y;
            var dist = MathF.Sqrt(dx * dx + dy * dy);
            if (dist < 1f) dist = 1f;

            var force = AttractionForce * (dist - RestLength);
            var fx = (dx / dist) * force;
            var fy = (dy / dist) * force;

            if (!src.IsPinned) { src.VelocityX += fx * deltaTime; src.VelocityY += fy * deltaTime; }
            if (!dst.IsPinned) { dst.VelocityX -= fx * deltaTime; dst.VelocityY -= fy * deltaTime; }
        }

        foreach (var node in _nodes)
        {
            if (node.IsPinned) continue;

            node.VelocityX *= Damping;
            node.VelocityY *= Damping;

            var speed = MathF.Sqrt(node.VelocityX * node.VelocityX + node.VelocityY * node.VelocityY);
            if (speed > MaxVelocity)
            {
                node.VelocityX = (node.VelocityX / speed) * MaxVelocity;
                node.VelocityY = (node.VelocityY / speed) * MaxVelocity;
            }

            node.X += node.VelocityX;
            node.Y += node.VelocityY;
        }
    }

    public void Clear()
    {
        _nodes.Clear();
        _edges.Clear();
        _nodeLookup.Clear();
    }

    public NetworkNode? GetNodeAt(float x, float y)
    {
        foreach (var node in _nodes)
        {
            var dx = node.X - x;
            var dy = node.Y - y;
            if (dx * dx + dy * dy <= node.Radius * node.Radius)
                return node;
        }
        return null;
    }
}
