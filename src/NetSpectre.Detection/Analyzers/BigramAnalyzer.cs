namespace NetSpectre.Detection.Analyzers;

public static class BigramAnalyzer
{
    private static readonly HashSet<string> CommonBigrams = new(StringComparer.OrdinalIgnoreCase)
    {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
        "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
        "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    };

    public static double GetUncommonBigramRatio(string input)
    {
        if (string.IsNullOrEmpty(input) || input.Length < 2) return 0;

        var total = 0;
        var uncommon = 0;
        for (int i = 0; i < input.Length - 1; i++)
        {
            if (!char.IsLetter(input[i]) || !char.IsLetter(input[i + 1]))
                continue;
            total++;
            var bigram = input.Substring(i, 2);
            if (!CommonBigrams.Contains(bigram))
                uncommon++;
        }

        return total == 0 ? 0 : (double)uncommon / total;
    }
}
