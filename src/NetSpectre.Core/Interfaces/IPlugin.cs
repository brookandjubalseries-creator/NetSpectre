namespace NetSpectre.Core.Interfaces;

public interface IPlugin
{
    string Name { get; }
    string Version { get; }
    string Author { get; }
    void Initialize();
    IReadOnlyList<IDetectionModule> GetDetectionModules();
}
