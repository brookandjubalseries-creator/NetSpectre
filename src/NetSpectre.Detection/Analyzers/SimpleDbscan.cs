namespace NetSpectre.Detection.Analyzers;

public static class SimpleDbscan
{
    public static List<List<double>> Cluster(IReadOnlyList<double> points, double epsilon, int minPoints)
    {
        var clusters = new List<List<double>>();
        var visited = new HashSet<int>();
        var noise = new HashSet<int>();

        for (int i = 0; i < points.Count; i++)
        {
            if (visited.Contains(i)) continue;
            visited.Add(i);

            var neighbors = GetNeighbors(points, i, epsilon);
            if (neighbors.Count < minPoints)
            {
                noise.Add(i);
                continue;
            }

            var cluster = new List<double> { points[i] };
            clusters.Add(cluster);

            var queue = new Queue<int>(neighbors);
            while (queue.Count > 0)
            {
                var idx = queue.Dequeue();
                if (noise.Contains(idx))
                {
                    noise.Remove(idx);
                    cluster.Add(points[idx]);
                }
                if (visited.Contains(idx)) continue;
                visited.Add(idx);
                cluster.Add(points[idx]);

                var nextNeighbors = GetNeighbors(points, idx, epsilon);
                if (nextNeighbors.Count >= minPoints)
                {
                    foreach (var n in nextNeighbors)
                        queue.Enqueue(n);
                }
            }
        }

        return clusters;
    }

    public static double? GetDominantClusterRatio(IReadOnlyList<double> points, double epsilon, int minPoints)
    {
        if (points.Count == 0) return null;

        var clusters = Cluster(points, epsilon, minPoints);
        if (clusters.Count == 0) return null;

        var largest = clusters.Max(c => c.Count);
        return (double)largest / points.Count;
    }

    private static List<int> GetNeighbors(IReadOnlyList<double> points, int index, double epsilon)
    {
        var neighbors = new List<int>();
        var point = points[index];
        for (int i = 0; i < points.Count; i++)
        {
            if (Math.Abs(points[i] - point) <= epsilon)
                neighbors.Add(i);
        }
        return neighbors;
    }
}
