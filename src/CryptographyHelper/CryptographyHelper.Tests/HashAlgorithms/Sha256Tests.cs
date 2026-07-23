using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Sha256Tests
{
    [Theory]
    [InlineData("Original Message to hash", "DC1D33325F502D18D02F21B7F8AA721EF485A92C4E0F6A8D34378025E5DF078E")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseSha256().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "DC1D33325F502D18D02F21B7F8AA721EF485A92C4E0F6A8D34378025E5DF078E")]
    public void HashBytes(string originalMessage, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();

        // Act
        var hashed = originalBytes.UseSha256().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "91EC99381BAD80B8F96CCB2B9E292E806DB439C298230594650C07CAC1621148")]
    public void HashStringWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalMessage.UseSha256().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "91EC99381BAD80B8F96CCB2B9E292E806DB439C298230594650C07CAC1621148")]
    public void HashBytesWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalBytes.UseSha256().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }
}
