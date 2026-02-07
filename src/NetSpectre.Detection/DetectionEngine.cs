using System.Reactive.Linq;
using System.Reactive.Subjects;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Models;
using NetSpectre.Detection.Utilities;

namespace NetSpectre.Detection;

public sealed class DetectionEngine : IDetectionEngine
{
    private readonly List<IDetectionModule> _modules = new();
    private readonly Subject<AlertRecord> _alertSubject = new();
    private readonly AlertDeduplicator _deduplicator = new();
    private readonly AlertRateLimiter _rateLimiter = new();
    private readonly List<IDisposable> _subscriptions = new();
    private int _alertIdCounter;
    private bool _isRunning;

    public IObservable<AlertRecord> AlertStream => _alertSubject.AsObservable();
    public IReadOnlyList<IDetectionModule> Modules => _modules.AsReadOnly();

    public void RegisterModule(IDetectionModule module)
    {
        _modules.Add(module);
        var sub = module.AlertStream.Subscribe(OnModuleAlert);
        _subscriptions.Add(sub);
    }

    public void ProcessPacket(PacketRecord packet)
    {
        if (!_isRunning) return;
        foreach (var module in _modules)
        {
            if (module.IsEnabled)
            {
                module.ProcessPacket(packet);
            }
        }
    }

    public void Start() => _isRunning = true;
    public void Stop() => _isRunning = false;

    private void OnModuleAlert(AlertRecord alert)
    {
        if (_deduplicator.IsDuplicate(alert)) return;
        if (!_rateLimiter.IsAllowed(alert.DetectorName)) return;

        alert.Id = Interlocked.Increment(ref _alertIdCounter);
        _alertSubject.OnNext(alert);
    }

    public void Dispose()
    {
        foreach (var sub in _subscriptions)
            sub.Dispose();
        _subscriptions.Clear();
        _alertSubject.Dispose();
    }
}
