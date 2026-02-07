using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using NetSpectre.Core.Models;
using NetSpectre.Services;
using NetSpectre.ViewModels;
using NetSpectre.Visualization;
using SkiaSharp;
using SkiaSharp.Views.Desktop;

namespace NetSpectre;

public partial class MainWindow : Window
{
    private readonly ForceDirectedLayout _graphLayout = new();
    private readonly SkiaGraphRenderer _graphRenderer = new();
    private readonly StatisticsRenderer _statsRenderer = new();
    private readonly GraphInteractionHandler _graphInteraction;
    private readonly DispatcherTimer _graphTimer;
    private readonly Dictionary<string, NetworkNode> _nodeLookup = new();

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;

        _graphInteraction = new GraphInteractionHandler(_graphLayout, _graphRenderer);

        _graphTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(33), // ~30fps
        };
        _graphTimer.Tick += GraphTimer_Tick;
        _graphTimer.Start();

        // Subscribe to packets for graph updates
        viewModel.Packets.CollectionChanged += (_, args) =>
        {
            if (args.NewItems == null) return;
            foreach (PacketRecord packet in args.NewItems)
                AddPacketToGraph(packet);
        };
    }

    private void AddPacketToGraph(PacketRecord packet)
    {
        var src = packet.SourceAddress;
        var dst = packet.DestinationAddress;
        if (string.IsNullOrEmpty(src) || string.IsNullOrEmpty(dst)) return;

        if (!_nodeLookup.ContainsKey(src))
        {
            var node = new NetworkNode { Address = src };
            _graphLayout.AddNode(node);
            _nodeLookup[src] = node;
        }

        if (!_nodeLookup.ContainsKey(dst))
        {
            var node = new NetworkNode { Address = dst };
            _graphLayout.AddNode(node);
            _nodeLookup[dst] = node;
        }

        // Update node traffic
        _nodeLookup[src].TotalBytes += packet.Length;
        _nodeLookup[dst].TotalBytes += packet.Length;
        _nodeLookup[src].ConnectionCount++;
        _nodeLookup[dst].ConnectionCount++;

        // Scale radius by traffic
        _nodeLookup[src].Radius = Math.Clamp(8f + (float)Math.Log10(Math.Max(1, _nodeLookup[src].TotalBytes)) * 3f, 8f, 40f);
        _nodeLookup[dst].Radius = Math.Clamp(8f + (float)Math.Log10(Math.Max(1, _nodeLookup[dst].TotalBytes)) * 3f, 8f, 40f);

        _graphLayout.AddEdge(new NetworkEdge
        {
            SourceAddress = src,
            DestinationAddress = dst,
            Protocol = packet.Protocol,
            TotalBytes = packet.Length,
            PacketCount = 1,
        });
    }

    private void GraphTimer_Tick(object? sender, EventArgs e)
    {
        _graphLayout.Step(0.016f);
        GraphCanvas.InvalidateVisual();

        // Also refresh statistics charts if stats tab is visible
        if (DataContext is MainViewModel vm && vm.SelectedBottomTab == 3)
        {
            StatsPieCanvas.InvalidateVisual();
            StatsBarCanvas.InvalidateVisual();
            StatsBandwidthCanvas.InvalidateVisual();
        }
    }

    private void GraphCanvas_PaintSurface(object? sender, SKPaintSurfaceEventArgs e)
    {
        _graphRenderer.Render(
            e.Surface.Canvas,
            e.Info.Width,
            e.Info.Height,
            _graphLayout.Nodes,
            _graphLayout.Edges,
            _nodeLookup);
    }

    private void GraphCanvas_MouseDown(object sender, MouseButtonEventArgs e)
    {
        var pos = e.GetPosition(GraphCanvas);
        var w = (int)GraphCanvas.ActualWidth;
        var h = (int)GraphCanvas.ActualHeight;
        _graphInteraction.OnMouseDown((float)pos.X, (float)pos.Y, w, h, e.RightButton == MouseButtonState.Pressed);
        GraphCanvas.CaptureMouse();
    }

    private void GraphCanvas_MouseMove(object sender, MouseEventArgs e)
    {
        var pos = e.GetPosition(GraphCanvas);
        var w = (int)GraphCanvas.ActualWidth;
        var h = (int)GraphCanvas.ActualHeight;
        _graphInteraction.OnMouseMove((float)pos.X, (float)pos.Y, w, h);
    }

    private void GraphCanvas_MouseUp(object sender, MouseButtonEventArgs e)
    {
        _graphInteraction.OnMouseUp();
        GraphCanvas.ReleaseMouseCapture();
    }

    private void GraphCanvas_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        _graphInteraction.OnScroll(e.Delta);
    }

    // Statistics chart paint handlers
    private void StatsPieCanvas_PaintSurface(object? sender, SKPaintSurfaceEventArgs e)
    {
        if (DataContext is MainViewModel vm && vm.ProtocolStats != null)
        {
            var data = vm.ProtocolStats.GetProtocolByteBreakdown();
            _statsRenderer.RenderPieChart(e.Surface.Canvas, e.Info.Width, e.Info.Height,
                data, "Protocol Distribution");
        }
        else
        {
            e.Surface.Canvas.Clear(new SKColor(0x1E, 0x1E, 0x2E));
        }
    }

    private void StatsBarCanvas_PaintSurface(object? sender, SKPaintSurfaceEventArgs e)
    {
        if (DataContext is MainViewModel vm && vm.ProtocolStats != null)
        {
            var data = vm.ProtocolStats.GetTopTalkers(10);
            _statsRenderer.RenderBarChart(e.Surface.Canvas, e.Info.Width, e.Info.Height,
                data, "Top Talkers");
        }
        else
        {
            e.Surface.Canvas.Clear(new SKColor(0x1E, 0x1E, 0x2E));
        }
    }

    private void StatsBandwidthCanvas_PaintSurface(object? sender, SKPaintSurfaceEventArgs e)
    {
        if (DataContext is MainViewModel vm && vm.ProtocolStats != null)
        {
            var data = vm.ProtocolStats.GetBandwidthPerSecond(60);
            _statsRenderer.RenderBandwidthChart(e.Surface.Canvas, e.Info.Width, e.Info.Height,
                data, "Bandwidth (Last 60s)");
        }
        else
        {
            e.Surface.Canvas.Clear(new SKColor(0x1E, 0x1E, 0x2E));
        }
    }

    private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        _graphTimer.Stop();
        if (DataContext is MainViewModel vm)
        {
            vm.Cleanup();
        }
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        var app = (App)Application.Current;
        var serviceProvider = app.Services;
        if (serviceProvider == null) return;

        var settingsVm = serviceProvider.GetRequiredService<SettingsViewModel>();
        var settingsWindow = new SettingsWindow(settingsVm)
        {
            Owner = this,
        };
        settingsWindow.ShowDialog();
    }

    private void ToggleTheme_Click(object sender, RoutedEventArgs e)
    {
        var app = (App)Application.Current;
        var themeService = app.Services?.GetService<ThemeService>();
        if (themeService == null) return;

        themeService.ToggleTheme();
        ThemeIcon.Text = themeService.CurrentTheme == AppTheme.Dark ? "\u2600" : "\u263D";
    }
}
