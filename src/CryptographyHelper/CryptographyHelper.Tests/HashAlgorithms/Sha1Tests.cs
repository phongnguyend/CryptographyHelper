using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Sha1Tests
{
    [Theory]
    [InlineData("Original Message to hash", "3882994BFCD293B6070D78A9DB0690E3BD18364F")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseSha1().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "3882994BFCD293B6070D78A9DB0690E3BD18364F")]
    public void HashBytes(string originalMessage, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();

        // Act
        var hashed = originalBytes.UseSha1().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "75E1EF7CF7645DA619BF6A2594B64843DE6690BD")]
    public void HashStringWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalMessage.UseSha1().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "75E1EF7CF7645DA619BF6A2594B64843DE6690BD")]
    public void HashBytesWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalBytes.UseSha1().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }
}
