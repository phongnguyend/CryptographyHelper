using System.IO;
using System.Security.Cryptography;
using CryptographyHelper.HashAlgorithms;
using CryptographyHelper.SymmetricAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.SymmetricAlgorithms;

public class AESTests
{
    [Theory]
    [InlineData(
        "Text to encrypt",
        "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=",
        "bXhlXQwu0R9qMjbCfEo7GA==",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "NrKAB/j0THWXFjYbl+HSCA==")]
    public void Encrypt(
        string original,
        string keyBase64,
        string ivBase64,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        string expected)
    {
        // Arrange
        var key = keyBase64.FromBase64String();
        var iv = ivBase64.FromBase64String();

        // Act
        var encrypted = original
            .UseAES(key)
            .WithCipher(cipherMode)
            .WithPadding(paddingMode)
            .WithIV(iv)
            .Encrypt();

        // Assert
        Assert.Equal(expected, encrypted.ToBase64String());
    }

    [Theory]
    [InlineData(
        "NrKAB/j0THWXFjYbl+HSCA==",
        "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=",
        "bXhlXQwu0R9qMjbCfEo7GA==",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "Text to encrypt")]
    public void Decrypt(
        string encryptedBase64,
        string keyBase64,
        string ivBase64,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        string expected)
    {
        // Arrange
        var encrypted = encryptedBase64.FromBase64String();
        var key = keyBase64.FromBase64String();
        var iv = ivBase64.FromBase64String();

        // Act
        var decrypted = encrypted
            .UseAES(key)
            .WithCipher(cipherMode)
            .WithPadding(paddingMode)
            .WithIV(iv)
            .Decrypt();

        // Assert
        Assert.Equal(expected, decrypted.GetString());
    }


    [Theory]
    [InlineData(
        "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=",
        "bXhlXQwu0R9qMjbCfEo7GA==",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "E9BEF8A00841C82C52C35A512DAD8093",
        "37161FD25E7B4FDB229645656E80CB55")]
    public void EncryptDecryptFile(
        string keyBase64,
        string ivBase64,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        string expectedOriginalHash,
        string expectedEncryptedHash)
    {
        // Arrange
        const string originalFileName = "SymmetricAlgorithms/File.xlsx";
        const string encryptedFileName = "SymmetricAlgorithms/EncryptedAES.xlsx";
        const string decryptedFileName = "SymmetricAlgorithms/DecryptedAES.xlsx";
        var key = keyBase64.FromBase64String();
        var iv = ivBase64.FromBase64String();

        // Act
        using var inputStream = File.OpenRead(originalFileName);
        using var outputStream = File.OpenWrite(encryptedFileName);
        {
            inputStream
                .UseAES(key)
                .WithCipher(cipherMode)
                .WithPadding(paddingMode)
                .WithIV(iv)
                .Encrypt(outputStream);
        }

        using var inputStream2 = File.OpenRead(encryptedFileName);
        using var outputStream2 = File.OpenWrite(decryptedFileName);
        {
            inputStream2
                .UseAES(key)
                .WithCipher(cipherMode)
                .WithPadding(paddingMode)
                .WithIV(iv)
                .Decrypt(outputStream2);
        }

        var hashed1 = originalFileName.ToFileInfo().UseMd5().ComputeHashedString();
        var hashed2 = decryptedFileName.ToFileInfo().UseMd5().ComputeHashedString();
        var hashed3 = encryptedFileName.ToFileInfo().UseMd5().ComputeHashedString();

        // Assert
        Assert.Equal(hashed1, hashed2);
        Assert.Equal(expectedOriginalHash, hashed1);
        Assert.Equal(expectedOriginalHash, hashed2);
        Assert.Equal(expectedEncryptedHash, hashed3);
    }
}
