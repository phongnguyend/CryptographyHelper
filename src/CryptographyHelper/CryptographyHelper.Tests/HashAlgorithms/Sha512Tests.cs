using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class Sha512Tests
{
    [Theory]
    [InlineData("Original Message to hash", "4BC7C892C45B94157C58D07F40B52CC2325505A560C7EB30472B43A15717E32307BF1B7A2CAD08446A9EF220F5255A9763FACA8632CFBC35D2C1E3131A250986")]
    [InlineData("Original Message to hash 2", "F6F86F7A9B40F953BA5D2CA0D9CD40814B0C4B8EFC4A1277E6C094C61CE40DDFB5B1B884F0FB20A899227A2AA70196FB0C91F5DA77496D8652C13DFEAEB72338")]
    public void HashString(string originalMessage, string expected)
    {
        // Act
        var hashed = originalMessage.UseSha512().ComputeHash().ToHexString();

        // Assert
        Assert.Equal(expected, hashed);
    }

    [Theory]
    [InlineData("Original Message to hash", "4BC7C892C45B94157C58D07F40B52CC2325505A560C7EB30472B43A15717E32307BF1B7A2CAD08446A9EF220F5255A9763FACA8632CFBC35D2C1E3131A250986")]
    [InlineData("Original Message to hash 2", "F6F86F7A9B40F953BA5D2CA0D9CD40814B0C4B8EFC4A1277E6C094C61CE40DDFB5B1B884F0FB20A899227A2AA70196FB0C91F5DA77496D8652C13DFEAEB72338")]
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
    [InlineData("Original Message to hash 2", "myscretekey", "1477F1ABACB1799A53CBD4A890D80BD1D6BDF7DB380C27ABC5C07DE05B691E6178F96469EA0E090D0B21BCB3265DE0CF13B9E6B2B9D461BE3D3BB05A96257971")]
    [InlineData("Original Message to hash", "myscretekey2", "98A2DFF32282B76EB8E5B284193BE7F3779F0EF83A627D7DCCB9345C53CE851C33142F4695FC525AF9B801C98EB60D788DC21E1D46C8A80EFBD717CB4CE8BD6C")]
    [InlineData("Original Message to hash 2", "myscretekey2", "7815F6AA15CB5EECBF2D8538209688573011AB803EB64954801E9B4747AAFEEAAE873B3E35F7B545720471B36413E92EC0417AA7101A0546D7C5A328D265CFF6")]
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
    [InlineData("Original Message to hash 2", "myscretekey", "1477F1ABACB1799A53CBD4A890D80BD1D6BDF7DB380C27ABC5C07DE05B691E6178F96469EA0E090D0B21BCB3265DE0CF13B9E6B2B9D461BE3D3BB05A96257971")]
    [InlineData("Original Message to hash", "myscretekey2", "98A2DFF32282B76EB8E5B284193BE7F3779F0EF83A627D7DCCB9345C53CE851C33142F4695FC525AF9B801C98EB60D788DC21E1D46C8A80EFBD717CB4CE8BD6C")]
    [InlineData("Original Message to hash 2", "myscretekey2", "7815F6AA15CB5EECBF2D8538209688573011AB803EB64954801E9B4747AAFEEAAE873B3E35F7B545720471B36413E92EC0417AA7101A0546D7C5A328D265CFF6")]
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
