namespace NetSpectre.Detection.Analyzers;

public static class ShannonEntropy
{
    public static double Calculate(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;

        var freq = new Dictionary<char, int>();
        foreach (var c in input)
        {
            freq.TryGetValue(c, out var count);
            freq[c] = count + 1;
        }

        double entropy = 0;
        var len = (double)input.Length;
        foreach (var count in freq.Values)
        {
            var p = count / len;
            if (p > 0)
                entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
