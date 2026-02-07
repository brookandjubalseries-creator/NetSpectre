namespace NetSpectre.Core.Filtering;

public sealed class FilterParser
{
    private readonly List<FilterToken> _tokens;
    private int _pos;

    private static readonly HashSet<string> KnownProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
        "tcp", "udp", "dns", "http", "https", "tls", "icmp", "icmpv6", "arp", "ipv4", "ipv6", "ip", "eth", "ethernet"
    };

    public FilterParser(List<FilterToken> tokens)
    {
        _tokens = tokens;
        _pos = 0;
    }

    public static FilterExpression Parse(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new FilterParseException("Empty filter expression");

        var lexer = new FilterLexer(input);
        var tokens = lexer.Tokenize();
        var parser = new FilterParser(tokens);
        var expr = parser.ParseOrExpression();

        if (parser.Current.Type != FilterTokenType.EndOfInput)
            throw new FilterParseException($"Unexpected token '{parser.Current.Value}' at position {parser.Current.Position}");

        return expr;
    }

    private FilterToken Current => _tokens[_pos];

    private FilterToken Advance()
    {
        var token = _tokens[_pos];
        if (_pos < _tokens.Count - 1) _pos++;
        return token;
    }

    private FilterExpression ParseOrExpression()
    {
        var left = ParseAndExpression();
        while (Current.Type == FilterTokenType.Or)
        {
            Advance();
            var right = ParseAndExpression();
            left = new BinaryLogicExpression(left, FilterTokenType.Or, right);
        }
        return left;
    }

    private FilterExpression ParseAndExpression()
    {
        var left = ParseUnaryExpression();
        while (Current.Type == FilterTokenType.And)
        {
            Advance();
            var right = ParseUnaryExpression();
            left = new BinaryLogicExpression(left, FilterTokenType.And, right);
        }
        return left;
    }

    private FilterExpression ParseUnaryExpression()
    {
        if (Current.Type == FilterTokenType.Not)
        {
            Advance();
            var operand = ParseUnaryExpression();
            return new NotExpression(operand);
        }
        return ParsePrimary();
    }

    private FilterExpression ParsePrimary()
    {
        if (Current.Type == FilterTokenType.LeftParen)
        {
            Advance();
            var expr = ParseOrExpression();
            if (Current.Type != FilterTokenType.RightParen)
                throw new FilterParseException($"Expected ')' at position {Current.Position}");
            Advance();
            return expr;
        }

        if (Current.Type == FilterTokenType.Identifier)
        {
            var identifier = Advance();

            // Check if it's a bare protocol name (no comparison operator follows)
            if (IsComparisonOperator(Current.Type))
            {
                var op = Advance();
                var value = ParseValue();
                return new ComparisonExpression(identifier.Value, op.Type, value);
            }

            // Bare protocol or field name
            if (KnownProtocols.Contains(identifier.Value))
                return new ProtocolExpression(identifier.Value);

            // Could be a field that acts as a boolean (just checks presence)
            return new ProtocolExpression(identifier.Value);
        }

        throw new FilterParseException($"Unexpected token '{Current.Value}' at position {Current.Position}");
    }

    private string ParseValue()
    {
        var token = Current;
        if (token.Type == FilterTokenType.StringLiteral ||
            token.Type == FilterTokenType.NumberLiteral ||
            token.Type == FilterTokenType.Identifier)
        {
            Advance();
            return token.Value;
        }
        throw new FilterParseException($"Expected value at position {token.Position}, got '{token.Value}'");
    }

    private static bool IsComparisonOperator(FilterTokenType type)
    {
        return type is FilterTokenType.Equals or FilterTokenType.NotEquals
            or FilterTokenType.GreaterThan or FilterTokenType.LessThan
            or FilterTokenType.GreaterOrEqual or FilterTokenType.LessOrEqual
            or FilterTokenType.Contains;
    }
}
