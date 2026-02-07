using System.Windows;

namespace NetSpectre.Services;

public enum AppTheme { Dark, Light }

public sealed class ThemeService
{
    private AppTheme _currentTheme = AppTheme.Dark;

    public AppTheme CurrentTheme => _currentTheme;

    public void ApplyTheme(AppTheme theme)
    {
        _currentTheme = theme;
        var app = Application.Current;
        if (app == null) return;

        var themeUri = theme switch
        {
            AppTheme.Light => new Uri("Themes/LightTheme.xaml", UriKind.Relative),
            _ => new Uri("Themes/DarkTheme.xaml", UriKind.Relative),
        };

        var newTheme = new ResourceDictionary { Source = themeUri };

        // Replace the first merged dictionary (theme) while keeping converters
        var merged = app.Resources.MergedDictionaries;
        if (merged.Count > 0)
            merged[0] = newTheme;
        else
            merged.Insert(0, newTheme);
    }

    public void ToggleTheme()
    {
        ApplyTheme(_currentTheme == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark);
    }
}
