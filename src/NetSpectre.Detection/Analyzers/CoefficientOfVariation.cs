namespace NetSpectre.Detection.Analyzers;

public static class CoefficientOfVariation
{
    public static double Calculate(IReadOnlyList<double> values)
    {
        if (values.Count < 2) return double.MaxValue;

        var mean = values.Average();
        if (Math.Abs(mean) < 1e-10) return double.MaxValue;

        var variance = values.Sum(v => (v - mean) * (v - mean)) / (values.Count - 1);
        var stdDev = Math.Sqrt(variance);

        return stdDev / mean;
    }

    public static IReadOnlyList<double> ComputeInterArrivalTimes(IReadOnlyList<DateTime> timestamps)
    {
        if (timestamps.Count < 2) return Array.Empty<double>();

        var sorted = timestamps.OrderBy(t => t).ToList();
        var intervals = new List<double>(sorted.Count - 1);
        for (int i = 1; i < sorted.Count; i++)
        {
            intervals.Add((sorted[i] - sorted[i - 1]).TotalSeconds);
        }
        return intervals;
    }
}
