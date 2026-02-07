using NetSpectre.Core.Filtering;
using NetSpectre.Core.Models;
using Xunit;

namespace NetSpectre.Core.Tests;

public class FilterLexerTests
{
    [Fact]
    public void Tokenize_SimpleComparison_ReturnsCorrectTokens()
    {
        var lexer = new FilterLexer("ip.src == 192.168.1.1");
        var tokens = lexer.Tokenize();

        Assert.Equal(FilterTokenType.Identifier, tokens[0].Type);
        Assert.Equal("ip.src", tokens[0].Value);
        Assert.Equal(FilterTokenType.Equals, tokens[1].Type);
        Assert.Equal(FilterTokenType.NumberLiteral, tokens[2].Type);
        Assert.Equal("192.168.1.1", tokens[2].Value);
        Assert.Equal(FilterTokenType.EndOfInput, tokens[3].Type);
    }

    [Fact]
    public void Tokenize_BooleanExpression_ReturnsCorrectTokens()
    {
        var lexer = new FilterLexer("tcp && udp");
        var tokens = lexer.Tokenize();

        Assert.Equal(FilterTokenType.Identifier, tokens[0].Type);
        Assert.Equal(FilterTokenType.And, tokens[1].Type);
        Assert.Equal(FilterTokenType.Identifier, tokens[2].Type);
    }

    [Fact]
    public void Tokenize_ContainsKeyword_ReturnsContainsToken()
    {
        var lexer = new FilterLexer("dns.qname contains \"example\"");
        var tokens = lexer.Tokenize();

        Assert.Equal(FilterTokenType.Identifier, tokens[0].Type);
        Assert.Equal(FilterTokenType.Contains, tokens[1].Type);
        Assert.Equal(FilterTokenType.StringLiteral, tokens[2].Type);
        Assert.Equal("example", tokens[2].Value);
    }

    [Fact]
    public void Tokenize_AllOperators_Works()
    {
        var lexer = new FilterLexer("== != > < >= <= !");
        var tokens = lexer.Tokenize();

        Assert.Equal(FilterTokenType.Equals, tokens[0].Type);
        Assert.Equal(FilterTokenType.NotEquals, tokens[1].Type);
        Assert.Equal(FilterTokenType.GreaterThan, tokens[2].Type);
        Assert.Equal(FilterTokenType.LessThan, tokens[3].Type);
        Assert.Equal(FilterTokenType.GreaterOrEqual, tokens[4].Type);
        Assert.Equal(FilterTokenType.LessOrEqual, tokens[5].Type);
        Assert.Equal(FilterTokenType.Not, tokens[6].Type);
    }

    [Fact]
    public void Tokenize_UnterminatedString_Throws()
    {
        var lexer = new FilterLexer("dns.qname == \"hello");
        Assert.Throws<FilterParseException>(() => lexer.Tokenize());
    }
}

public class FilterParserTests
{
    [Fact]
    public void Parse_BareProtocol_ReturnsProtocolExpression()
    {
        var expr = FilterParser.Parse("tcp");
        Assert.IsType<ProtocolExpression>(expr);
        Assert.Equal("tcp", ((ProtocolExpression)expr).ProtocolName);
    }

    [Fact]
    public void Parse_Comparison_ReturnsComparisonExpression()
    {
        var expr = FilterParser.Parse("ip.src == 192.168.1.1");
        var comp = Assert.IsType<ComparisonExpression>(expr);
        Assert.Equal("ip.src", comp.FieldName);
        Assert.Equal(FilterTokenType.Equals, comp.Operator);
        Assert.Equal("192.168.1.1", comp.Value);
    }

    [Fact]
    public void Parse_And_ReturnsBinaryLogicExpression()
    {
        var expr = FilterParser.Parse("tcp && udp");
        var logic = Assert.IsType<BinaryLogicExpression>(expr);
        Assert.Equal(FilterTokenType.And, logic.Operator);
    }

    [Fact]
    public void Parse_Or_ReturnsBinaryLogicExpression()
    {
        var expr = FilterParser.Parse("tcp || udp");
        var logic = Assert.IsType<BinaryLogicExpression>(expr);
        Assert.Equal(FilterTokenType.Or, logic.Operator);
    }

    [Fact]
    public void Parse_Not_ReturnsNotExpression()
    {
        var expr = FilterParser.Parse("!tcp");
        var not = Assert.IsType<NotExpression>(expr);
        Assert.IsType<ProtocolExpression>(not.Operand);
    }

    [Fact]
    public void Parse_Parenthesized_RespectsGrouping()
    {
        var expr = FilterParser.Parse("(tcp || udp) && ip.src == 10.0.0.1");
        var logic = Assert.IsType<BinaryLogicExpression>(expr);
        Assert.Equal(FilterTokenType.And, logic.Operator);
        Assert.IsType<BinaryLogicExpression>(logic.Left); // the OR
        Assert.IsType<ComparisonExpression>(logic.Right);
    }

    [Fact]
    public void Parse_ComplexExpression_Works()
    {
        var expr = FilterParser.Parse("ip.src == 192.168.1.1 && tcp.dstport == 443");
        var logic = Assert.IsType<BinaryLogicExpression>(expr);
        Assert.IsType<ComparisonExpression>(logic.Left);
        Assert.IsType<ComparisonExpression>(logic.Right);
    }

    [Fact]
    public void Parse_EmptyString_Throws()
    {
        Assert.Throws<FilterParseException>(() => FilterParser.Parse(""));
    }
}

public class FilterEvaluatorTests
{
    private readonly FilterEvaluator _evaluator = new();

    private static PacketRecord MakeTcpPacket(
        string src = "192.168.1.1",
        string dst = "10.0.0.1",
        string srcPort = "12345",
        string dstPort = "443")
    {
        var layers = new PacketLayers();
        var tcpLayer = new ProtocolLayer { Name = "Transmission Control Protocol" };
        tcpLayer.AddField("Source Port", srcPort);
        tcpLayer.AddField("Destination Port", dstPort);
        tcpLayer.AddField("Flags", "SYN");
        layers.AddLayer(tcpLayer);

        return new PacketRecord
        {
            Number = 1,
            Protocol = "TCP",
            SourceAddress = src,
            DestinationAddress = dst,
            Length = 64,
            Layers = layers,
        };
    }

    private static PacketRecord MakeUdpDnsPacket(string queryName = "example.com")
    {
        var layers = new PacketLayers();
        var dnsLayer = new ProtocolLayer { Name = "Domain Name System" };
        dnsLayer.AddField("Query Name", queryName);
        dnsLayer.AddField("Transaction ID", "0x1234");
        layers.AddLayer(dnsLayer);

        return new PacketRecord
        {
            Number = 2,
            Protocol = "DNS",
            SourceAddress = "192.168.1.1",
            DestinationAddress = "8.8.8.8",
            Length = 72,
            Layers = layers,
        };
    }

    [Fact]
    public void Evaluate_BareProtocol_MatchesTcp()
    {
        var expr = FilterParser.Parse("tcp");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_BareProtocol_DoesNotMatchWrongProtocol()
    {
        var expr = FilterParser.Parse("udp");
        Assert.False(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_IpSrcEquals_Matches()
    {
        var expr = FilterParser.Parse("ip.src == 192.168.1.1");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_IpSrcEquals_DoesNotMatch()
    {
        var expr = FilterParser.Parse("ip.src == 10.0.0.99");
        Assert.False(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_TcpDstport_Matches()
    {
        var expr = FilterParser.Parse("tcp.dstport == 443");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_TcpPort_MatchesEitherSrcOrDst()
    {
        var expr = FilterParser.Parse("tcp.port == 443");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));

        var expr2 = FilterParser.Parse("tcp.port == 12345");
        Assert.True(_evaluator.Evaluate(expr2, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_And_BothMustMatch()
    {
        var expr = FilterParser.Parse("tcp && ip.src == 192.168.1.1");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));

        var expr2 = FilterParser.Parse("tcp && ip.src == 10.0.0.99");
        Assert.False(_evaluator.Evaluate(expr2, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_Or_EitherMatches()
    {
        var expr = FilterParser.Parse("tcp || udp");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_Not_InvertsResult()
    {
        var expr = FilterParser.Parse("!udp");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));

        var expr2 = FilterParser.Parse("!tcp");
        Assert.False(_evaluator.Evaluate(expr2, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_DnsQnameContains_Matches()
    {
        var expr = FilterParser.Parse("dns.qname contains \"example\"");
        Assert.True(_evaluator.Evaluate(expr, MakeUdpDnsPacket("example.com")));
    }

    [Fact]
    public void Evaluate_DnsQnameContains_DoesNotMatch()
    {
        var expr = FilterParser.Parse("dns.qname contains \"google\"");
        Assert.False(_evaluator.Evaluate(expr, MakeUdpDnsPacket("example.com")));
    }

    [Fact]
    public void Evaluate_ComplexExpression_Works()
    {
        var expr = FilterParser.Parse("ip.src == 192.168.1.1 && tcp.dstport == 443");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_NotEquals_Works()
    {
        var expr = FilterParser.Parse("ip.src != 10.0.0.99");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));
    }

    [Fact]
    public void Evaluate_FrameLen_NumericComparison()
    {
        var expr = FilterParser.Parse("frame.len > 50");
        Assert.True(_evaluator.Evaluate(expr, MakeTcpPacket()));

        var expr2 = FilterParser.Parse("frame.len < 50");
        Assert.False(_evaluator.Evaluate(expr2, MakeTcpPacket()));
    }
}
