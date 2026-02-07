using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSpectre.Core.Configuration;

public sealed class ConfigurationService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly string _configPath;

    public NetSpectreConfig Config { get; private set; } = new();

    public ConfigurationService()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var configDir = Path.Combine(appData, "NetSpectre");
        _configPath = Path.Combine(configDir, "settings.json");
    }

    public ConfigurationService(string configPath)
    {
        _configPath = configPath;
    }

    public void Load()
    {
        if (!File.Exists(_configPath))
        {
            Config = new NetSpectreConfig();
            return;
        }

        try
        {
            var json = File.ReadAllText(_configPath);
            Config = JsonSerializer.Deserialize<NetSpectreConfig>(json, JsonOptions) ?? new NetSpectreConfig();
        }
        catch
        {
            Config = new NetSpectreConfig();
        }
    }

    public void Save()
    {
        var directory = Path.GetDirectoryName(_configPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(Config, JsonOptions);
        File.WriteAllText(_configPath, json);
    }

    public void Reset()
    {
        Config = new NetSpectreConfig();
        Save();
    }
}
