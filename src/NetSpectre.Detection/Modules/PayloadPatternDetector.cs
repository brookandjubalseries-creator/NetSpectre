using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Text;
using System.Text.RegularExpressions;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;

namespace NetSpectre.Detection.Modules;

public sealed class PayloadPatternDetector : IDetectionModule
{
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly List<SignatureRule> _rules;

    public string Name => "Payload Pattern Detector";
    public string Description => "Detects malicious payload patterns using signature-based matching";
    public bool IsEnabled { get; set; } = true;
    public IObservable<AlertRecord> AlertStream => _alertSubject.AsObservable();

    public PayloadPatternDetector(IEnumerable<SignatureRule>? customRules = null)
    {
        _rules = new List<SignatureRule>(GetDefaultRules());
        if (customRules is not null)
        {
            _rules.AddRange(customRules);
        }
    }

    public void ProcessPacket(PacketRecord packet)
    {
        if (!IsEnabled) return;

        if (packet.RawData is null || packet.RawData.Length == 0) return;

        string payload;
        try
        {
            payload = Encoding.UTF8.GetString(packet.RawData);
        }
        catch
        {
            return;
        }

        if (string.IsNullOrEmpty(payload)) return;

        foreach (var rule in _rules)
        {
            try
            {
                var match = Regex.Match(payload, rule.Pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
                if (match.Success)
                {
                    var matchedContent = match.Value;
                    if (matchedContent.Length > 100)
                        matchedContent = matchedContent[..100];

                    _alertSubject.OnNext(new AlertRecord
                    {
                        Timestamp = DateTime.UtcNow,
                        Severity = rule.Severity,
                        DetectorName = Name,
                        Title = rule.Name,
                        Description = $"{rule.Description}. Matched content: {matchedContent}",
                        SourceAddress = packet.SourceAddress,
                        DestinationAddress = packet.DestinationAddress,
                        Metadata = new Dictionary<string, string>
                        {
                            ["RuleName"] = rule.Name,
                            ["MatchedContent"] = matchedContent,
                            ["Pattern"] = rule.Pattern,
                        }
                    });
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Skip rules that time out
            }
        }
    }

    public void AddRule(SignatureRule rule)
    {
        _rules.Add(rule);
    }

    public void RemoveRule(string ruleName)
    {
        _rules.RemoveAll(r => r.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase));
    }

    public void Reset()
    {
        _rules.Clear();
        _rules.AddRange(GetDefaultRules());
    }

    private static IEnumerable<SignatureRule> GetDefaultRules()
    {
        yield return new SignatureRule(
            "SQL Injection Attempt",
            @"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*delete)",
            AlertSeverity.Warning,
            "Potential SQL injection attack detected in payload");

        yield return new SignatureRule(
            "Shell Command Injection",
            @"(?i)(\||\;|\$\(|`).*(cat|ls|whoami|passwd|etc/shadow)",
            AlertSeverity.Critical,
            "Potential shell command injection detected in payload");

        yield return new SignatureRule(
            "Directory Traversal",
            @"\.\./\.\./",
            AlertSeverity.Warning,
            "Potential directory traversal attack detected in payload");

        yield return new SignatureRule(
            "Base64 Encoded Payload",
            @"[A-Za-z0-9+/]{50,}={0,2}",
            AlertSeverity.Info,
            "Suspiciously long Base64-encoded content detected in payload");
    }
}

public sealed record SignatureRule(
    string Name,
    string Pattern,
    AlertSeverity Severity,
    string Description);
