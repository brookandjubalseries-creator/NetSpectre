using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace NetSpectre.Converters;

public sealed class ProtocolToRowColorConverter : IValueConverter
{
    private static readonly Dictionary<string, string> ProtocolRowColors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["TCP"] = "#1589B4FA",
        ["UDP"] = "#15A6E3A1",
        ["DNS"] = "#15CBA6F7",
        ["HTTP"] = "#15F9E2AF",
        ["HTTPS"] = "#15FAB387",
        ["TLS"] = "#15FAB387",
        ["ICMP"] = "#15F38BA8",
        ["ICMPv6"] = "#15F38BA8",
        ["ARP"] = "#1594E2D5",
    };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string protocol && ProtocolRowColors.TryGetValue(protocol, out var hex))
        {
            var color = (Color)ColorConverter.ConvertFromString(hex);
            return new SolidColorBrush(color);
        }
        return Brushes.Transparent;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
