using CryptographyHelper.HashAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.HashAlgorithms;

public class PBKDF2Tests
{
    [Theory]
    [InlineData(
        "MyVeryComplexPassword",
        "65QuFYgSxqIW0d9Y/QKRX9veWK0DOyX0g7+nbr9yux8=",
        500000,
        32,
        "c1M3Di0Eu5x/Uno80OLzf7AEdQepN0aPIO4xRnOe1D8=")]
    public void Hash(
        string passwordToHash,
        string saltBase64,
        int iterationCount,
        int byteCount,
        string expected)
    {
        // Arrange
        var salt = saltBase64.FromBase64String();

        // Act
        var hashedPassword = passwordToHash
            .UsePBKDF2(salt, iterationCount)
            .GetBytes(byteCount)
            .ToBase64String();

        // Assert
        Assert.Equal(expected, hashedPassword);
    }
}
