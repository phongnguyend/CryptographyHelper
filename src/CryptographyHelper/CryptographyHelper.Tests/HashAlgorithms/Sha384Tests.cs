using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Sha384Tests
{
    [Theory]
    [InlineData("Original Message to hash", "F6CAF4688471120BFF98F0F53D9F5A403C9991F9F196F93713C4D6262A6787F890DFB300807354A199715E1CA4A43EA5")]
    [InlineData("Original Message to hash 2", "5F495CFE9F2089A4983D7E233C66ED44A684CC3DA6176334145F2A8646A1AF765BB96DA21CC4108A1873477E22CAA6A2")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseSha384().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "F6CAF4688471120BFF98F0F53D9F5A403C9991F9F196F93713C4D6262A6787F890DFB300807354A199715E1CA4A43EA5")]
    [InlineData("Original Message to hash 2", "5F495CFE9F2089A4983D7E233C66ED44A684CC3DA6176334145F2A8646A1AF765BB96DA21CC4108A1873477E22CAA6A2")]
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
    [InlineData("Original Message to hash 2", "myscretekey", "67A1394CE10D49147243D9DD4A7FDD9358C7A4BC054B1F35A70047B299657A5ABEB4CAF784C55F033C71A2DDE063E038")]
    [InlineData("Original Message to hash", "myscretekey2", "ADDEBB0F609995810979CE7D44ACD8B7E333D31B883EEF9FAB6E94E3EDF2D905E776A00812411C3E88E2526CC48450CE")]
    [InlineData("Original Message to hash 2", "myscretekey2", "FA50077B2A9D78D6353EC52D23CCDD36AA4FA2131DFA2C6D056FE783A6FA99BED4E7C442EE91E67BA808A1291B95431B")]
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
    [InlineData("Original Message to hash 2", "myscretekey", "67A1394CE10D49147243D9DD4A7FDD9358C7A4BC054B1F35A70047B299657A5ABEB4CAF784C55F033C71A2DDE063E038")]
    [InlineData("Original Message to hash", "myscretekey2", "ADDEBB0F609995810979CE7D44ACD8B7E333D31B883EEF9FAB6E94E3EDF2D905E776A00812411C3E88E2526CC48450CE")]
    [InlineData("Original Message to hash 2", "myscretekey2", "FA50077B2A9D78D6353EC52D23CCDD36AA4FA2131DFA2C6D056FE783A6FA99BED4E7C442EE91E67BA808A1291B95431B")]
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
