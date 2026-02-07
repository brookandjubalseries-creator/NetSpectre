using Xunit;

namespace NetSpectre.Crafting.Tests;

public class PacketValidatorTests
{
    [Fact]
    public void ValidateIpAddress_ValidIp_NoErrors()
    {
        var v = new PacketValidator().ValidateIpAddress("192.168.1.1", "Source IP");
        Assert.True(v.IsValid);
    }

    [Fact]
    public void ValidateIpAddress_InvalidIp_HasError()
    {
        var v = new PacketValidator().ValidateIpAddress("not.an.ip", "Source IP");
        Assert.False(v.IsValid);
        Assert.Contains(v.Errors, e => e.Contains("Source IP"));
    }

    [Fact]
    public void ValidateIpAddress_Null_HasError()
    {
        var v = new PacketValidator().ValidateIpAddress(null, "Source IP");
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ValidateMacAddress_ValidMac_NoErrors()
    {
        var v = new PacketValidator().ValidateMacAddress("00-11-22-33-44-55", "Source MAC");
        Assert.True(v.IsValid);
    }

    [Fact]
    public void ValidateMacAddress_ColonFormat_NoErrors()
    {
        var v = new PacketValidator().ValidateMacAddress("00:11:22:33:44:55", "Source MAC");
        Assert.True(v.IsValid);
    }

    [Fact]
    public void ValidateMacAddress_InvalidMac_HasError()
    {
        var v = new PacketValidator().ValidateMacAddress("ZZ-ZZ-ZZ-ZZ-ZZ-ZZ", "Source MAC");
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ValidatePort_ValidPort_NoErrors()
    {
        var v = new PacketValidator().ValidatePort(443, "Dest Port");
        Assert.True(v.IsValid);
    }

    [Fact]
    public void ValidatePort_NegativePort_HasError()
    {
        var v = new PacketValidator().ValidatePort(-1, "Port");
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ValidatePort_TooLargePort_HasError()
    {
        var v = new PacketValidator().ValidatePort(70000, "Port");
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ValidateTtl_Valid_NoErrors()
    {
        var v = new PacketValidator().ValidateTtl(64);
        Assert.True(v.IsValid);
    }

    [Fact]
    public void ValidateTtl_Zero_HasError()
    {
        var v = new PacketValidator().ValidateTtl(0);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ValidateTtl_Over255_HasError()
    {
        var v = new PacketValidator().ValidateTtl(256);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ValidatePayloadSize_WithinLimit_NoErrors()
    {
        var v = new PacketValidator().ValidatePayloadSize(new byte[100]);
        Assert.True(v.IsValid);
    }

    [Fact]
    public void ValidatePayloadSize_ExceedsLimit_HasError()
    {
        var v = new PacketValidator().ValidatePayloadSize(new byte[100], maxSize: 50);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ValidatePayloadSize_Null_NoErrors()
    {
        var v = new PacketValidator().ValidatePayloadSize(null);
        Assert.True(v.IsValid);
    }

    [Fact]
    public void Clear_RemovesAllErrors()
    {
        var v = new PacketValidator()
            .ValidateIpAddress("bad", "IP")
            .ValidatePort(-1, "Port");
        Assert.False(v.IsValid);

        v.Clear();
        Assert.True(v.IsValid);
    }

    [Fact]
    public void ChainedValidations_AccumulateErrors()
    {
        var v = new PacketValidator()
            .ValidateIpAddress("bad", "Source IP")
            .ValidatePort(-1, "Source Port")
            .ValidateTtl(0);

        Assert.Equal(3, v.Errors.Count);
    }
}
