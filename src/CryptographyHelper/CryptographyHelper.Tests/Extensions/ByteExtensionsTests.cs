using Xunit;

namespace CryptographyHelper.Tests.Extensions;

public class ByteExtensionsTests
{
    [Fact]
    public void FixedTimeEquals_ComparesContentsOfDistinctArrays()
    {
        byte[] first = { 1, 2, 3 };
        byte[] second = { 1, 2, 3 };

        Assert.NotSame(first, second);
        Assert.True(first.FixedTimeEquals(second));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void FixedTimeEquals_RejectsDifferenceAtAnyPosition(int index)
    {
        byte[] first = { 1, 2, 3 };
        byte[] second = { 1, 2, 3 };
        second[index] ^= 1;

        Assert.False(first.FixedTimeEquals(second));
        Assert.False(second.FixedTimeEquals(first));
    }

    [Fact]
    public void FixedTimeEquals_RejectsDifferentLengths()
    {
        byte[] first = { 1, 2 };
        byte[] second = { 1, 2, 3 };

        Assert.False(first.FixedTimeEquals(second));
        Assert.False(second.FixedTimeEquals(first));
    }

    [Fact]
    public void FixedTimeEquals_AcceptsEmptyArraysAndSameReference()
    {
        byte[] value = { 1, 2, 3 };

        Assert.True(new byte[0].FixedTimeEquals(new byte[0]));
        Assert.True(value.FixedTimeEquals(value));
    }

    [Fact]
    public void FixedTimeEquals_PreservesNullSemantics()
    {
        byte[] missing = null;
        byte[] empty = new byte[0];
        byte[] value = { 1 };

        Assert.True(missing.FixedTimeEquals(null));
        Assert.False(missing.FixedTimeEquals(empty));
        Assert.False(empty.FixedTimeEquals(missing));
        Assert.False(missing.FixedTimeEquals(value));
        Assert.False(value.FixedTimeEquals(missing));
    }

    [Fact]
    public void LegacyStaticEquals_PreservesContentComparison()
    {
#pragma warning disable CS0618 // Verify compatibility for existing explicit static callers.
        Assert.True(ByteExtensions.Equals(new byte[] { 1, 2 }, new byte[] { 1, 2 }));
        Assert.False(ByteExtensions.Equals(new byte[] { 1, 2 }, new byte[] { 1, 3 }));
        Assert.True(ByteExtensions.Equals(null, null));
        Assert.False(ByteExtensions.Equals(null, new byte[0]));
#pragma warning restore CS0618
    }
}
