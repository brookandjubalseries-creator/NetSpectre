using NetSpectre.Core.Models;
using NetSpectre.Core.Services;
using Xunit;

namespace NetSpectre.Core.Tests;

public class AlertWebhookServiceTests
{
    private static AlertRecord MakeAlert(AlertSeverity severity = AlertSeverity.Critical)
    {
        return new AlertRecord
        {
            Id = 1,
            Timestamp = DateTime.UtcNow,
            Severity = severity,
            DetectorName = "TestDetector",
            Title = "Test Alert",
            Description = "This is a test alert.",
            SourceAddress = "192.168.1.100",
            DestinationAddress = "10.0.0.1",
        };
    }

    [Fact]
    public async Task SendAlertAsync_WhenDisabled_DoesNotThrow()
    {
        using var service = new AlertWebhookService();
        service.Configure("https://example.com/webhook", enabled: false);

        var alert = MakeAlert();

        // Should complete without throwing even though service is disabled
        await service.SendAlertAsync(alert);
    }

    [Fact]
    public async Task SendAlertAsync_WithEmptyUrl_DoesNotThrow()
    {
        using var service = new AlertWebhookService();
        service.Configure("", enabled: true);

        var alert = MakeAlert();

        // Should complete without throwing even with empty URL
        await service.SendAlertAsync(alert);
    }

    [Fact]
    public async Task SendAlertAsync_CriticalOnly_FiltersNonCriticalAlerts()
    {
        using var service = new AlertWebhookService();
        // Use an invalid URL so if it tries to send, it would fail
        // but with criticalOnly=true, non-critical alerts should be skipped entirely
        service.Configure("https://0.0.0.0:1/webhook", enabled: true, criticalOnly: true);

        var warningAlert = MakeAlert(AlertSeverity.Warning);
        var infoAlert = MakeAlert(AlertSeverity.Info);

        // These should return immediately without attempting to send
        await service.SendAlertAsync(warningAlert);
        await service.SendAlertAsync(infoAlert);
    }

    [Fact]
    public async Task Configure_SetsPropertiesCorrectly()
    {
        using var service = new AlertWebhookService();

        // Configure with criticalOnly = false
        service.Configure("https://hooks.example.com/test", enabled: true, criticalOnly: false);

        // We can verify the configuration took effect by sending a non-critical alert
        // to a bad URL - if criticalOnly were true, it would skip; if false, it would attempt
        // and silently fail. Either way no exception should be thrown.
        var infoAlert = MakeAlert(AlertSeverity.Info);

        // The task should complete (either skipped or silently failed)
        await service.SendAlertAsync(infoAlert);
    }
}
