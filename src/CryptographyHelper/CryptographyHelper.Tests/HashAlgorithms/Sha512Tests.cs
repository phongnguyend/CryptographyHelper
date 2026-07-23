using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Sha512Tests
{
    [Theory]
    [InlineData("Original Message to hash", "4BC7C892C45B94157C58D07F40B52CC2325505A560C7EB30472B43A15717E32307BF1B7A2CAD08446A9EF220F5255A9763FACA8632CFBC35D2C1E3131A250986")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseSha512().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "4BC7C892C45B94157C58D07F40B52CC2325505A560C7EB30472B43A15717E32307BF1B7A2CAD08446A9EF220F5255A9763FACA8632CFBC35D2C1E3131A250986")]
    public void HashBytes(string originalMessage, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();

        // Act
        var hashed = originalBytes.UseSha512().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "E6F4B40BA23A614DF9CE20B0CE3C2212BDAE3D003E72306140130F711163CB1A211AAC51D45991132D7996E585C8E21D5F54755B1D810D8A0069E78E7D22763D")]
    public void HashStringWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalMessage.UseSha512().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "myscretekey", "E6F4B40BA23A614DF9CE20B0CE3C2212BDAE3D003E72306140130F711163CB1A211AAC51D45991132D7996E585C8E21D5F54755B1D810D8A0069E78E7D22763D")]
    public void HashBytesWithKey(string originalMessage, string keyValue, string expected)
    {
        // Arrange
        var originalBytes = originalMessage.GetBytes();
        var key = keyValue.GetBytes();

        // Act
        var hashed = originalBytes.UseSha512().WithKey(key).ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }
}
