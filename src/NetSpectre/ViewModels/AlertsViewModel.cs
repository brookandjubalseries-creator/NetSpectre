using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;

namespace NetSpectre.ViewModels;

public partial class AlertsViewModel : ObservableObject
{
    private readonly IDetectionEngine? _detectionEngine;
    private IDisposable? _alertSubscription;

    [ObservableProperty]
    private ObservableCollection<AlertRecord> _alerts = new();

    [ObservableProperty]
    private AlertRecord? _selectedAlert;

    [ObservableProperty]
    private int _alertCount;

    [ObservableProperty]
    private int _criticalCount;

    [ObservableProperty]
    private int _warningCount;

    public AlertsViewModel()
    {
        // Design-time
    }

    public AlertsViewModel(IDetectionEngine detectionEngine)
    {
        _detectionEngine = detectionEngine;
    }

    public void Subscribe(System.Windows.Threading.Dispatcher dispatcher)
    {
        if (_detectionEngine is null) return;

        _alertSubscription = _detectionEngine.AlertStream
            .Subscribe(alert =>
            {
                dispatcher.BeginInvoke(() =>
                {
                    Alerts.Insert(0, alert);
                    AlertCount = Alerts.Count;
                    if (alert.Severity == AlertSeverity.Critical)
                        CriticalCount++;
                    else if (alert.Severity == AlertSeverity.Warning)
                        WarningCount++;
                });
            });
    }

    [RelayCommand]
    private void ClearAlerts()
    {
        Alerts.Clear();
        AlertCount = 0;
        CriticalCount = 0;
        WarningCount = 0;
    }

    [RelayCommand]
    private void ExportCsv()
    {
        if (Alerts.Count == 0) return;

        var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv",
            DefaultExt = ".csv",
            FileName = $"netspectre_alerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
        };

        if (dialog.ShowDialog() == true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Timestamp,Severity,Detector,Title,SourceAddress,DestinationAddress,Description");
            foreach (var alert in Alerts)
            {
                sb.AppendLine($"{alert.Id},{alert.Timestamp:O},{alert.Severity},{Escape(alert.DetectorName)},{Escape(alert.Title)},{alert.SourceAddress},{alert.DestinationAddress},{Escape(alert.Description)}");
            }
            File.WriteAllText(dialog.FileName, sb.ToString());
        }
    }

    private static string Escape(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }

    public void Cleanup()
    {
        _alertSubscription?.Dispose();
    }
}
