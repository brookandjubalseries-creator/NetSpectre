using NetSpectre.Core.Interfaces;

namespace NetSpectre.Plugin.Example;

public sealed class ExamplePlugin : IPlugin
{
    public string Name => "ICMP Flood Detection Plugin";
    public string Version => "1.0.0";
    public string Author => "NetSpectre Examples";

    private IcmpFloodDetector? _detector;

    public void Initialize()
    {
        _detector = new IcmpFloodDetector();
    }

    public IReadOnlyList<IDetectionModule> GetDetectionModules()
    {
        if (_detector == null)
            return Array.Empty<IDetectionModule>();
        return new IDetectionModule[] { _detector };
    }
}
