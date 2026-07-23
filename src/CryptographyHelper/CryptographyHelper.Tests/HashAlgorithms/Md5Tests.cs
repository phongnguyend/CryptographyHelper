using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Md5Tests
{
    [Theory]
    [InlineData("Original Message to hash", "B4DE75BC83002A2705C1CB5BC41727C5")]
    [InlineData("Original Message to hash 2", "E0A22BEC1F00C38C49C07E5247F66039")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseMd5().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "B4DE75BC83002A2705C1CB5BC41727C5")]
    [InlineData("Original Message to hash 2", "E0A22BEC1F00C38C49C07E5247F66039")]
    public void HashBytes(string originalMessage, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();

        // Act
        var hashed = originalBytes.UseMd5().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "0A1820C7393A3FE90F8726E7FB8D303D")]
    [InlineData("Original Message to hash 2", "myscretekey", "87F4D0F1F769A272F688CD3FC96A8AC3")]
    [InlineData("Original Message to hash", "myscretekey2", "B39B5F858942F23CBA84ED02D4D9BF8D")]
    [InlineData("Original Message to hash 2", "myscretekey2", "D07EC7E45572093FD7121F1A27A96D2E")]
    public void HashStringWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalMessage.UseMd5().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "0A1820C7393A3FE90F8726E7FB8D303D")]
    [InlineData("Original Message to hash 2", "myscretekey", "87F4D0F1F769A272F688CD3FC96A8AC3")]
    [InlineData("Original Message to hash", "myscretekey2", "B39B5F858942F23CBA84ED02D4D9BF8D")]
    [InlineData("Original Message to hash 2", "myscretekey2", "D07EC7E45572093FD7121F1A27A96D2E")]
    public void HashBytesWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalBytes.UseMd5().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }
}
