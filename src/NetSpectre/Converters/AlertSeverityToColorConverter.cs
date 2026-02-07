using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using NetSpectre.Core.Models;

namespace NetSpectre.Converters;

public sealed class AlertSeverityToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is AlertSeverity severity)
        {
            return severity switch
            {
                AlertSeverity.Critical => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#20F38BA8")),
                AlertSeverity.Warning => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#20F9E2AF")),
                AlertSeverity.Info => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2089B4FA")),
                _ => Brushes.Transparent
            };
        }
        return Brushes.Transparent;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class AlertSeverityToTextColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is AlertSeverity severity)
        {
            return severity switch
            {
                AlertSeverity.Critical => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8")),
                AlertSeverity.Warning => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F9E2AF")),
                AlertSeverity.Info => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#89B4FA")),
                _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CDD6F4"))
            };
        }
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CDD6F4"));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
