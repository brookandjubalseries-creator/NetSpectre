using System.Globalization;
using NetSpectre.Core.Models;

namespace NetSpectre.Core.Filtering;

public sealed class FilterEvaluator
{
    private readonly FilterFieldRegistry _registry;

    private static readonly HashSet<string> ProtocolNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "tcp", "udp", "dns", "http", "https", "tls", "icmp", "icmpv6", "arp", "ipv4", "ipv6", "ip", "eth", "ethernet"
    };

    public FilterEvaluator(FilterFieldRegistry? registry = null)
    {
        _registry = registry ?? new FilterFieldRegistry();
    }

    public bool Evaluate(FilterExpression expression, PacketRecord packet)
    {
        return expression switch
        {
            ProtocolExpression proto => EvaluateProtocol(proto, packet),
            ComparisonExpression comp => EvaluateComparison(comp, packet),
            BinaryLogicExpression logic => EvaluateLogic(logic, packet),
            NotExpression not => !Evaluate(not.Operand, packet),
            _ => false
        };
    }

    private bool EvaluateProtocol(ProtocolExpression expr, PacketRecord packet)
    {
        var name = expr.ProtocolName;

        // Known protocol — match against packet protocol
        if (ProtocolNames.Contains(name))
        {
            // Special handling: "ip" matches both IPv4 and IPv6
            if (name.Equals("ip", StringComparison.OrdinalIgnoreCase))
                return packet.Protocol.Equals("IPv4", StringComparison.OrdinalIgnoreCase) ||
                       packet.Protocol.Equals("IPv6", StringComparison.OrdinalIgnoreCase) ||
                       packet.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) ||
                       packet.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ||
                       packet.Protocol.Equals("ICMP", StringComparison.OrdinalIgnoreCase) ||
                       packet.Protocol.Equals("DNS", StringComparison.OrdinalIgnoreCase) ||
                       packet.Protocol.Equals("HTTP", StringComparison.OrdinalIgnoreCase);

            if (name.Equals("eth", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ethernet", StringComparison.OrdinalIgnoreCase))
                return true; // everything has Ethernet layer

            return packet.Protocol.Equals(name, StringComparison.OrdinalIgnoreCase);
        }

        // If it's a registered field name, treat as a presence check
        if (_registry.HasField(name))
        {
            var val = _registry.GetFieldValue(packet, name);
            return val != null;
        }

        return false;
    }

    private bool EvaluateComparison(ComparisonExpression expr, PacketRecord packet)
    {
        // Special handling for tcp.port and udp.port — match either src or dst
        if (expr.FieldName.Equals("tcp.port", StringComparison.OrdinalIgnoreCase))
        {
            var src = _registry.GetFieldValue(packet, "tcp.srcport");
            var dst = _registry.GetFieldValue(packet, "tcp.dstport");
            return CompareValue(src, expr.Operator, expr.Value) ||
                   CompareValue(dst, expr.Operator, expr.Value);
        }

        if (expr.FieldName.Equals("udp.port", StringComparison.OrdinalIgnoreCase))
        {
            var src = _registry.GetFieldValue(packet, "udp.srcport");
            var dst = _registry.GetFieldValue(packet, "udp.dstport");
            return CompareValue(src, expr.Operator, expr.Value) ||
                   CompareValue(dst, expr.Operator, expr.Value);
        }

        if (expr.FieldName.Equals("ip.addr", StringComparison.OrdinalIgnoreCase))
        {
            return CompareValue(packet.SourceAddress, expr.Operator, expr.Value) ||
                   CompareValue(packet.DestinationAddress, expr.Operator, expr.Value);
        }

        var fieldValue = _registry.GetFieldValue(packet, expr.FieldName);
        return CompareValue(fieldValue, expr.Operator, expr.Value);
    }

    private static bool CompareValue(string? fieldValue, FilterTokenType op, string compareValue)
    {
        if (fieldValue == null) return false;

        return op switch
        {
            FilterTokenType.Equals => fieldValue.Equals(compareValue, StringComparison.OrdinalIgnoreCase),
            FilterTokenType.NotEquals => !fieldValue.Equals(compareValue, StringComparison.OrdinalIgnoreCase),
            FilterTokenType.Contains => fieldValue.Contains(compareValue, StringComparison.OrdinalIgnoreCase),
            FilterTokenType.GreaterThan => CompareNumeric(fieldValue, compareValue) > 0,
            FilterTokenType.LessThan => CompareNumeric(fieldValue, compareValue) < 0,
            FilterTokenType.GreaterOrEqual => CompareNumeric(fieldValue, compareValue) >= 0,
            FilterTokenType.LessOrEqual => CompareNumeric(fieldValue, compareValue) <= 0,
            _ => false
        };
    }

    private static int CompareNumeric(string a, string b)
    {
        if (double.TryParse(a, NumberStyles.Any, CultureInfo.InvariantCulture, out var numA) &&
            double.TryParse(b, NumberStyles.Any, CultureInfo.InvariantCulture, out var numB))
        {
            return numA.CompareTo(numB);
        }
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private bool EvaluateLogic(BinaryLogicExpression expr, PacketRecord packet)
    {
        return expr.Operator switch
        {
            FilterTokenType.And => Evaluate(expr.Left, packet) && Evaluate(expr.Right, packet),
            FilterTokenType.Or => Evaluate(expr.Left, packet) || Evaluate(expr.Right, packet),
            _ => false
        };
    }
}
