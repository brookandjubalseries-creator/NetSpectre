using System.Net.Http;
using System.Text;
using System.Text.Json;
using NetSpectre.Core.Models;

namespace NetSpectre.Core.Services;

public sealed class AlertWebhookService : IDisposable
{
    private readonly HttpClient _httpClient = new();
    private string _webhookUrl = string.Empty;
    private bool _enabled;
    private bool _criticalOnly = true;

    public void Configure(string url, bool enabled, bool criticalOnly = true)
    {
        _webhookUrl = url;
        _enabled = enabled;
        _criticalOnly = criticalOnly;
    }

    public async Task SendAlertAsync(AlertRecord alert)
    {
        if (!_enabled || string.IsNullOrEmpty(_webhookUrl)) return;
        if (_criticalOnly && alert.Severity != AlertSeverity.Critical) return;

        try
        {
            // Format that works with Slack, Discord, and generic webhooks
            var payload = new
            {
                text = $"[NetSpectre Alert] {alert.Severity}: {alert.Title}",
                content = $"**{alert.Severity}** — {alert.Title}\n{alert.Description}\nSource: {alert.SourceAddress}\nDetector: {alert.DetectorName}\nTime: {alert.Timestamp:yyyy-MM-dd HH:mm:ss UTC}",
                embeds = new[]
                {
                    new
                    {
                        title = $"{alert.Severity}: {alert.Title}",
                        description = alert.Description,
                        color = alert.Severity switch
                        {
                            AlertSeverity.Critical => 0xF38BA8,
                            AlertSeverity.Warning => 0xF9E2AF,
                            _ => 0x89B4FA
                        },
                        fields = new[]
                        {
                            new { name = "Source", value = alert.SourceAddress, inline = true },
                            new { name = "Detector", value = alert.DetectorName, inline = true },
                            new { name = "Time", value = alert.Timestamp.ToString("HH:mm:ss UTC"), inline = true },
                        }
                    }
                }
            };

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            await _httpClient.PostAsync(_webhookUrl, content);
        }
        catch
        {
            // Silently ignore webhook failures
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }
}
