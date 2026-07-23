using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Sha384Tests
{
    [Theory]
    [InlineData("Original Message to hash", "F6CAF4688471120BFF98F0F53D9F5A403C9991F9F196F93713C4D6262A6787F890DFB300807354A199715E1CA4A43EA5")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseSha384().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "F6CAF4688471120BFF98F0F53D9F5A403C9991F9F196F93713C4D6262A6787F890DFB300807354A199715E1CA4A43EA5")]
    public void HashBytes(string originalMessage, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();

        // Act
        var hashed = originalBytes.UseSha384().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "0803D90E53B514DC34B8EFD4D7076E75C11B164120895697E5EA5C1DE0E12BEAB4FC5C85548D6D12FF8E9FD648121F1E")]
    public void HashStringWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalMessage.UseSha384().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "0803D90E53B514DC34B8EFD4D7076E75C11B164120895697E5EA5C1DE0E12BEAB4FC5C85548D6D12FF8E9FD648121F1E")]
    public void HashBytesWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalBytes.UseSha384().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }
}
