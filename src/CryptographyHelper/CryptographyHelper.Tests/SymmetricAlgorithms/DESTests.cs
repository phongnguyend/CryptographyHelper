using System.IO;
using System.Security.Cryptography;
using CryptographyHelper.HashAlgorithms;
using CryptographyHelper.SymmetricAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.SymmetricAlgorithms;

public class DESTests
{
    [Fact]
    public void Encrypt()
    {
        // Arrange
        const string original = "Text to encrypt";
        var key = "cmjP+yg9d3Q=".FromBase64String();
        var iv = "bFWtV5H1BDc=".FromBase64String();

        // Act
        var encrypted = original
            .UseDES(key)
            .WithCipher(CipherMode.ECB)
            .WithPadding(PaddingMode.PKCS7)
            .WithIV(iv)
            .Encrypt();

        // Assert
        Assert.Equal("faa7hXl/f/UVa+/ox02gDQ==", encrypted.ToBase64String());
    }

    [Fact]
    public void Decrypt()
    {
        // Arrange
        var encrypted = "faa7hXl/f/UVa+/ox02gDQ==".FromBase64String();
        var key = "cmjP+yg9d3Q=".FromBase64String();
        var iv = "bFWtV5H1BDc=".FromBase64String();

        // Act
        var decrypted = encrypted
            .UseDES(key)
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
        const string encryptedFileName = "SymmetricAlgorithms/EncryptedDES.xlsx";
        const string decryptedFileName = "SymmetricAlgorithms/DecryptedDES.xlsx";
        var key = "cmjP+yg9d3Q=".FromBase64String();
        var iv = "bFWtV5H1BDc=".FromBase64String();

        // Act
        using var inputStream = File.OpenRead(originalFileName);
        using var outputStream = File.OpenWrite(encryptedFileName);
        {
            inputStream
                .UseDES(key)
                .WithCipher(CipherMode.ECB)
                .WithPadding(PaddingMode.PKCS7)
                .WithIV(iv)
                .Encrypt(outputStream);
        }

        using var inputStream2 = File.OpenRead(encryptedFileName);
        using var outputStream2 = File.OpenWrite(decryptedFileName);
        {
            inputStream2
                .UseDES(key)
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
        Assert.Equal("37F4E82230402EEC16E1D26CB903CC73", hashed3);
    }
}
