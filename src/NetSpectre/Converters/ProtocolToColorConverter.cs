using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace NetSpectre.Converters;

public sealed class ProtocolToColorConverter : IValueConverter
{
    private static readonly Dictionary<string, string> ProtocolColors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["TCP"] = "#89B4FA",
        ["UDP"] = "#A6E3A1",
        ["DNS"] = "#CBA6F7",
        ["HTTP"] = "#F9E2AF",
        ["HTTPS"] = "#FAB387",
        ["TLS"] = "#FAB387",
        ["ICMP"] = "#F38BA8",
        ["ICMPv6"] = "#F38BA8",
        ["ARP"] = "#94E2D5",
        ["IPv4"] = "#89B4FA",
        ["IPv6"] = "#89B4FA",
    };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string protocol && ProtocolColors.TryGetValue(protocol, out var hex))
        {
            var color = (Color)ColorConverter.ConvertFromString(hex);
            return new SolidColorBrush(color);
        }
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A6ADC8"));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
