namespace NetSpectre.Core.Filtering;

public enum FilterTokenType
{
    Identifier,     // field name like ip.src, tcp.port, or bare protocol
    StringLiteral,  // quoted string "hello"
    NumberLiteral,  // 443, 192.168.1.1 (IP addresses treated as strings)
    Equals,         // ==
    NotEquals,      // !=
    GreaterThan,    // >
    LessThan,       // <
    GreaterOrEqual, // >=
    LessOrEqual,    // <=
    Contains,       // contains
    And,            // &&
    Or,             // ||
    Not,            // !
    LeftParen,      // (
    RightParen,     // )
    EndOfInput,
}

public sealed class FilterToken
{
    public FilterTokenType Type { get; }
    public string Value { get; }
    public int Position { get; }

    public FilterToken(FilterTokenType type, string value, int position)
    {
        Type = type;
        Value = value;
        Position = position;
    }
}
