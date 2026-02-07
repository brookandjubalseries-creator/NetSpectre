namespace NetSpectre.Core.Filtering;

public abstract class FilterExpression { }

public sealed class ComparisonExpression : FilterExpression
{
    public string FieldName { get; }
    public FilterTokenType Operator { get; }
    public string Value { get; }

    public ComparisonExpression(string fieldName, FilterTokenType op, string value)
    {
        FieldName = fieldName;
        Operator = op;
        Value = value;
    }
}

public sealed class ProtocolExpression : FilterExpression
{
    public string ProtocolName { get; }

    public ProtocolExpression(string protocolName)
    {
        ProtocolName = protocolName;
    }
}

public sealed class BinaryLogicExpression : FilterExpression
{
    public FilterExpression Left { get; }
    public FilterTokenType Operator { get; }
    public FilterExpression Right { get; }

    public BinaryLogicExpression(FilterExpression left, FilterTokenType op, FilterExpression right)
    {
        Left = left;
        Operator = op;
        Right = right;
    }
}

public sealed class NotExpression : FilterExpression
{
    public FilterExpression Operand { get; }

    public NotExpression(FilterExpression operand)
    {
        Operand = operand;
    }
}
