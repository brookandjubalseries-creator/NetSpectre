namespace NetSpectre.Core.Filtering;

public sealed class FilterLexer
{
    private readonly string _input;
    private int _pos;

    public FilterLexer(string input)
    {
        _input = input ?? throw new ArgumentNullException(nameof(input));
        _pos = 0;
    }

    public List<FilterToken> Tokenize()
    {
        var tokens = new List<FilterToken>();
        while (_pos < _input.Length)
        {
            SkipWhitespace();
            if (_pos >= _input.Length) break;

            var c = _input[_pos];
            var startPos = _pos;

            if (c == '(')
            {
                tokens.Add(new FilterToken(FilterTokenType.LeftParen, "(", startPos));
                _pos++;
            }
            else if (c == ')')
            {
                tokens.Add(new FilterToken(FilterTokenType.RightParen, ")", startPos));
                _pos++;
            }
            else if (c == '!' && Peek(1) == '=')
            {
                tokens.Add(new FilterToken(FilterTokenType.NotEquals, "!=", startPos));
                _pos += 2;
            }
            else if (c == '!')
            {
                tokens.Add(new FilterToken(FilterTokenType.Not, "!", startPos));
                _pos++;
            }
            else if (c == '=' && Peek(1) == '=')
            {
                tokens.Add(new FilterToken(FilterTokenType.Equals, "==", startPos));
                _pos += 2;
            }
            else if (c == '>' && Peek(1) == '=')
            {
                tokens.Add(new FilterToken(FilterTokenType.GreaterOrEqual, ">=", startPos));
                _pos += 2;
            }
            else if (c == '<' && Peek(1) == '=')
            {
                tokens.Add(new FilterToken(FilterTokenType.LessOrEqual, "<=", startPos));
                _pos += 2;
            }
            else if (c == '>')
            {
                tokens.Add(new FilterToken(FilterTokenType.GreaterThan, ">", startPos));
                _pos++;
            }
            else if (c == '<')
            {
                tokens.Add(new FilterToken(FilterTokenType.LessThan, "<", startPos));
                _pos++;
            }
            else if (c == '&' && Peek(1) == '&')
            {
                tokens.Add(new FilterToken(FilterTokenType.And, "&&", startPos));
                _pos += 2;
            }
            else if (c == '|' && Peek(1) == '|')
            {
                tokens.Add(new FilterToken(FilterTokenType.Or, "||", startPos));
                _pos += 2;
            }
            else if (c == '"')
            {
                tokens.Add(ReadString(startPos));
            }
            else if (char.IsLetterOrDigit(c) || c == '.' || c == ':' || c == '_')
            {
                tokens.Add(ReadIdentifierOrNumber(startPos));
            }
            else
            {
                throw new FilterParseException($"Unexpected character '{c}' at position {startPos}");
            }
        }

        tokens.Add(new FilterToken(FilterTokenType.EndOfInput, "", _pos));
        return tokens;
    }

    private void SkipWhitespace()
    {
        while (_pos < _input.Length && char.IsWhiteSpace(_input[_pos]))
            _pos++;
    }

    private char Peek(int offset)
    {
        var idx = _pos + offset;
        return idx < _input.Length ? _input[idx] : '\0';
    }

    private FilterToken ReadString(int startPos)
    {
        _pos++; // skip opening quote
        var start = _pos;
        while (_pos < _input.Length && _input[_pos] != '"')
            _pos++;
        if (_pos >= _input.Length)
            throw new FilterParseException($"Unterminated string starting at position {startPos}");
        var value = _input[start.._pos];
        _pos++; // skip closing quote
        return new FilterToken(FilterTokenType.StringLiteral, value, startPos);
    }

    private FilterToken ReadIdentifierOrNumber(int startPos)
    {
        var start = _pos;
        while (_pos < _input.Length && (char.IsLetterOrDigit(_input[_pos]) || _input[_pos] == '.' || _input[_pos] == ':' || _input[_pos] == '_' || _input[_pos] == '-' || _input[_pos] == '/'))
            _pos++;
        var value = _input[start.._pos];

        // Check for keywords
        if (value.Equals("contains", StringComparison.OrdinalIgnoreCase))
            return new FilterToken(FilterTokenType.Contains, value, startPos);
        if (value.Equals("and", StringComparison.OrdinalIgnoreCase))
            return new FilterToken(FilterTokenType.And, value, startPos);
        if (value.Equals("or", StringComparison.OrdinalIgnoreCase))
            return new FilterToken(FilterTokenType.Or, value, startPos);
        if (value.Equals("not", StringComparison.OrdinalIgnoreCase))
            return new FilterToken(FilterTokenType.Not, value, startPos);

        // Determine if it looks like a number or IP (starts with a digit)
        if (char.IsDigit(value[0]))
            return new FilterToken(FilterTokenType.NumberLiteral, value, startPos);

        return new FilterToken(FilterTokenType.Identifier, value, startPos);
    }
}
