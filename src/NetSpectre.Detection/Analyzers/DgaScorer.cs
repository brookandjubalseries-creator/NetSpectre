namespace NetSpectre.Detection.Analyzers;

public static class DgaScorer
{
    public static double Score(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return 0;

        // Extract the main label (second-level domain)
        var parts = domain.Split('.');
        var label = parts.Length >= 2 ? parts[^2] : parts[0];
        if (label.Length < 3) return 0;

        var entropy = ShannonEntropy.Calculate(label);
        var cvRatio = GetConsonantVowelRatio(label);
        var bigramScore = BigramAnalyzer.GetUncommonBigramRatio(label);
        var digitRatio = GetDigitRatio(label);

        // Weighted score: higher = more likely DGA
        return (entropy * 0.35) + (cvRatio * 0.25) + (bigramScore * 0.25) + (digitRatio * 0.15);
    }

    public static double GetConsonantVowelRatio(string input)
    {
        var vowels = "aeiouAEIOU";
        int consonants = 0, vowelCount = 0;
        foreach (var c in input)
        {
            if (!char.IsLetter(c)) continue;
            if (vowels.Contains(c))
                vowelCount++;
            else
                consonants++;
        }
        var total = consonants + vowelCount;
        return total == 0 ? 0 : (double)consonants / total;
    }

    private static double GetDigitRatio(string input)
    {
        if (input.Length == 0) return 0;
        int digits = input.Count(char.IsDigit);
        return (double)digits / input.Length;
    }
}
