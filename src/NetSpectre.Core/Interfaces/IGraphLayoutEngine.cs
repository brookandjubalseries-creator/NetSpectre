using NetSpectre.Core.Models;

namespace NetSpectre.Core.Interfaces;

public interface IGraphLayoutEngine
{
    void AddNode(NetworkNode node);
    void AddEdge(NetworkEdge edge);
    void RemoveNode(string address);
    void Step(float deltaTime);
    IReadOnlyList<NetworkNode> Nodes { get; }
    IReadOnlyList<NetworkEdge> Edges { get; }
    void Clear();
}
