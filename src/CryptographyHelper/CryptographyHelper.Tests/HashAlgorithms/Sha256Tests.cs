using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Sha256Tests
{
    [Theory]
    [InlineData("Original Message to hash", "DC1D33325F502D18D02F21B7F8AA721EF485A92C4E0F6A8D34378025E5DF078E")]
    [InlineData("Original Message to hash 2", "3C7F846976B9C8912CFD2E4B2A9DDE52159B4A87621DE2E7DC90A9A6F6BDC71C")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseSha256().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "DC1D33325F502D18D02F21B7F8AA721EF485A92C4E0F6A8D34378025E5DF078E")]
    [InlineData("Original Message to hash 2", "3C7F846976B9C8912CFD2E4B2A9DDE52159B4A87621DE2E7DC90A9A6F6BDC71C")]
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
    [InlineData("Original Message to hash 2", "myscretekey", "89F6D64695E8A5CAFFBAE69C9351ABFCB1F3D63AB770E16064E3F63D461BE273")]
    [InlineData("Original Message to hash", "myscretekey2", "3BDE8FB9CAE62385E85CE2EC3C598483A4AD3170102D8AC71CFA476C2AA3E5D9")]
    [InlineData("Original Message to hash 2", "myscretekey2", "04D9C70ABC7FD19FC5231B78B09D82CF72505414171FFA56A2A66D409824CA5F")]
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
    [InlineData("Original Message to hash 2", "myscretekey", "89F6D64695E8A5CAFFBAE69C9351ABFCB1F3D63AB770E16064E3F63D461BE273")]
    [InlineData("Original Message to hash", "myscretekey2", "3BDE8FB9CAE62385E85CE2EC3C598483A4AD3170102D8AC71CFA476C2AA3E5D9")]
    [InlineData("Original Message to hash 2", "myscretekey2", "04D9C70ABC7FD19FC5231B78B09D82CF72505414171FFA56A2A66D409824CA5F")]
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
