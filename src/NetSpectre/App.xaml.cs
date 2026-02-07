using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using NetSpectre.Capture;
using NetSpectre.Core.Analysis;
using NetSpectre.Core.Configuration;
using NetSpectre.Core.Interfaces;
using NetSpectre.Core.Plugins;
using NetSpectre.Core.Services;
using NetSpectre.Crafting;
using NetSpectre.Detection;
using NetSpectre.Detection.Modules;
using NetSpectre.Services;
using NetSpectre.ViewModels;

namespace NetSpectre;

public partial class App : Application
{
    private ServiceProvider? _serviceProvider;

    public IServiceProvider? Services => _serviceProvider;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        // Configure webhook service from config
        var config = _serviceProvider.GetRequiredService<ConfigurationService>().Config;
        var webhook = _serviceProvider.GetRequiredService<AlertWebhookService>();
        webhook.Configure(config.Webhook.Url, config.Webhook.Enabled, config.Webhook.OnCriticalOnly);

        var mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Configuration
        services.AddSingleton<ConfigurationService>(sp =>
        {
            var configService = new ConfigurationService();
            configService.Load();
            return configService;
        });

        // Plugin Loader
        services.AddSingleton<PluginLoader>(sp =>
        {
            var loader = new PluginLoader();
            var pluginsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "plugins");
            loader.LoadFromDirectory(pluginsDir);
            return loader;
        });

        // Services
        services.AddSingleton<ThemeService>();
        services.AddSingleton<PacketCraftingService>();
        services.AddSingleton<PcapFileService>();
        services.AddSingleton<ProtocolStatistics>();
        services.AddSingleton<TcpStreamReassembler>();
        services.AddSingleton<DnsResolverCache>();
        services.AddSingleton<GeoIpService>();
        services.AddSingleton<AlertWebhookService>();
        services.AddSingleton<ICaptureService, SharpPcapCaptureService>();
        services.AddSingleton<IDetectionEngine>(sp =>
        {
            var config = sp.GetRequiredService<ConfigurationService>().Config;
            var engine = new DetectionEngine();

            if (config.Detection.PortScan.Enabled)
            {
                engine.RegisterModule(new PortScanDetector(
                    windowSize: TimeSpan.FromSeconds(config.Detection.PortScan.WindowSeconds),
                    infoThreshold: config.Detection.PortScan.InfoThreshold,
                    warningThreshold: config.Detection.PortScan.WarningThreshold,
                    criticalThreshold: config.Detection.PortScan.CriticalThreshold));
            }

            if (config.Detection.DnsAnomaly.Enabled)
            {
                engine.RegisterModule(new DnsAnomalyDetector(
                    suspiciousEntropy: config.Detection.DnsAnomaly.SuspiciousEntropy,
                    highEntropy: config.Detection.DnsAnomaly.HighEntropy,
                    criticalEntropy: config.Detection.DnsAnomaly.CriticalEntropy));
            }

            if (config.Detection.C2Beacon.Enabled)
            {
                engine.RegisterModule(new C2BeaconDetector(
                    minConnections: config.Detection.C2Beacon.MinConnections,
                    criticalCvThreshold: config.Detection.C2Beacon.CriticalCvThreshold,
                    warningCvThreshold: config.Detection.C2Beacon.WarningCvThreshold,
                    dbscanClusterRatio: config.Detection.C2Beacon.DbscanClusterRatio));
            }

            // New detectors: ARP Spoof, Brute Force, Payload Pattern
            engine.RegisterModule(new ArpSpoofDetector());
            engine.RegisterModule(new BruteForceDetector());
            engine.RegisterModule(new PayloadPatternDetector());

            // Register plugin detection modules
            var pluginLoader = sp.GetRequiredService<PluginLoader>();
            foreach (var module in pluginLoader.GetAllDetectionModules())
            {
                engine.RegisterModule(module);
            }

            return engine;
        });

        // ViewModels
        services.AddSingleton<MainViewModel>(sp =>
            new MainViewModel(
                sp.GetRequiredService<ICaptureService>(),
                sp.GetRequiredService<IDetectionEngine>(),
                sp.GetRequiredService<PacketCraftingService>(),
                sp.GetRequiredService<PcapFileService>(),
                sp.GetRequiredService<ProtocolStatistics>(),
                sp.GetRequiredService<TcpStreamReassembler>(),
                sp.GetRequiredService<DnsResolverCache>(),
                sp.GetRequiredService<GeoIpService>(),
                sp.GetRequiredService<AlertWebhookService>(),
                sp.GetRequiredService<ConfigurationService>()));
        services.AddTransient<SettingsViewModel>(sp =>
            new SettingsViewModel(sp.GetRequiredService<ConfigurationService>()));

        // Views
        services.AddSingleton<MainWindow>();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serviceProvider?.Dispose();
        base.OnExit(e);
    }
}
