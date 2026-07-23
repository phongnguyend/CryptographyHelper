using System.IO;
using System.Security.Cryptography;
using CryptographyHelper.HashAlgorithms;
using CryptographyHelper.SymmetricAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.SymmetricAlgorithms;

public class AESTests
{
    [Fact]
    public void Encrypt()
    {
        // Arrange
        const string original = "Text to encrypt";
        var key = "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=".FromBase64String();
        var iv = "bXhlXQwu0R9qMjbCfEo7GA==".FromBase64String();

        // Act
        var encrypted = original
            .UseAES(key)
            .WithCipher(CipherMode.ECB)
            .WithPadding(PaddingMode.PKCS7)
            .WithIV(iv)
            .Encrypt();

        // Assert
        Assert.Equal("NrKAB/j0THWXFjYbl+HSCA==", encrypted.ToBase64String());
    }

    [Fact]
    public void Decrypt()
    {
        // Arrange
        var encrypted = "NrKAB/j0THWXFjYbl+HSCA==".FromBase64String();
        var key = "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=".FromBase64String();
        var iv = "bXhlXQwu0R9qMjbCfEo7GA==".FromBase64String();

        // Act
        var decrypted = encrypted
            .UseAES(key)
            .WithCipher(CipherMode.ECB)
            .WithPadding(PaddingMode.PKCS7)
            .WithIV(iv)
            .Decrypt();

        // Assert
        Assert.Equal("Text to encrypt", decrypted.GetString());
    }


    [Fact]
    public void EncryptDecryptFile()
    {
        // Arrange
        const string originalFileName = "SymmetricAlgorithms/File.xlsx";
        const string encryptedFileName = "SymmetricAlgorithms/EncryptedAES.xlsx";
        const string decryptedFileName = "SymmetricAlgorithms/DecryptedAES.xlsx";
        var key = "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=".FromBase64String();
        var iv = "bXhlXQwu0R9qMjbCfEo7GA==".FromBase64String();

        // Act
        using var inputStream = File.OpenRead(originalFileName);
        using var outputStream = File.OpenWrite(encryptedFileName);
        {
            inputStream
                .UseAES(key)
                .WithCipher(CipherMode.ECB)
                .WithPadding(PaddingMode.PKCS7)
                .WithIV(iv)
                .Encrypt(outputStream);
        }

        using var inputStream2 = File.OpenRead(encryptedFileName);
        using var outputStream2 = File.OpenWrite(decryptedFileName);
        {
            inputStream2
                .UseAES(key)
                .WithCipher(CipherMode.ECB)
                .WithPadding(PaddingMode.PKCS7)
                .WithIV(iv)
                .Decrypt(outputStream2);
        }

        var hashed1 = originalFileName.ToFileInfo().UseMd5().ComputeHashedString();
        var hashed2 = decryptedFileName.ToFileInfo().UseMd5().ComputeHashedString();
        var hashed3 = encryptedFileName.ToFileInfo().UseMd5().ComputeHashedString();

        // Assert
        Assert.Equal(hashed1, hashed2);
        Assert.Equal("E9BEF8A00841C82C52C35A512DAD8093", hashed1);
        Assert.Equal("E9BEF8A00841C82C52C35A512DAD8093", hashed2);
        Assert.Equal("37161FD25E7B4FDB229645656E80CB55", hashed3);
    }
}
