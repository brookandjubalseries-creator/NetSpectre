using System.Reflection;
using NetSpectre.Core.Interfaces;

namespace NetSpectre.Core.Plugins;

public sealed class PluginLoader
{
    private readonly List<LoadedPlugin> _loadedPlugins = new();

    public IReadOnlyList<LoadedPlugin> LoadedPlugins => _loadedPlugins.AsReadOnly();

    public void LoadFromDirectory(string pluginsDirectory)
    {
        if (!Directory.Exists(pluginsDirectory))
            return;

        var dllFiles = Directory.GetFiles(pluginsDirectory, "*.dll", SearchOption.AllDirectories);
        foreach (var dllPath in dllFiles)
        {
            TryLoadPlugin(dllPath);
        }
    }

    public void LoadFromPath(string dllPath)
    {
        TryLoadPlugin(dllPath);
    }

    private void TryLoadPlugin(string dllPath)
    {
        try
        {
            var loadContext = new PluginLoadContext(dllPath);
            var assembly = loadContext.LoadFromAssemblyPath(dllPath);

            var pluginTypes = assembly.GetTypes()
                .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);

            foreach (var pluginType in pluginTypes)
            {
                if (Activator.CreateInstance(pluginType) is IPlugin plugin)
                {
                    plugin.Initialize();
                    _loadedPlugins.Add(new LoadedPlugin(plugin, dllPath, loadContext));
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to load plugin from {dllPath}: {ex.Message}");
        }
    }

    public IReadOnlyList<IDetectionModule> GetAllDetectionModules()
    {
        return _loadedPlugins
            .Where(p => p.IsEnabled)
            .SelectMany(p => p.Plugin.GetDetectionModules())
            .ToList()
            .AsReadOnly();
    }

    public void UnloadAll()
    {
        foreach (var loaded in _loadedPlugins)
        {
            loaded.LoadContext.Unload();
        }
        _loadedPlugins.Clear();
    }
}

public sealed class LoadedPlugin
{
    public IPlugin Plugin { get; }
    public string FilePath { get; }
    internal PluginLoadContext LoadContext { get; }
    public bool IsEnabled { get; set; } = true;

    public LoadedPlugin(IPlugin plugin, string filePath, PluginLoadContext loadContext)
    {
        Plugin = plugin;
        FilePath = filePath;
        LoadContext = loadContext;
    }
}
