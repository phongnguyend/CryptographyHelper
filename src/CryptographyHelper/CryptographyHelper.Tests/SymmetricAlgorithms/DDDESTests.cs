using System.IO;
using System.Security.Cryptography;
using CryptographyHelper.HashAlgorithms;
using CryptographyHelper.SymmetricAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.SymmetricAlgorithms;

public class DDDESTests
{
    [Fact]
    public void Encrypt()
    {
        // Arrange
        const string original = "Text to encrypt";
        var key = "e0x8U5MyotKHiY1uxqxurg==".FromBase64String();
        var iv = "Z1kmtPGvz1g=".FromBase64String();

        // Act
        var encrypted = original
            .UseTripleDES(key)
            .WithCipher(CipherMode.ECB)
            .WithPadding(PaddingMode.PKCS7)
            .WithIV(iv)
            .Encrypt();

        // Assert
        Assert.Equal("BMAQOzU6W/qAZBoRMlauWg==", encrypted.ToBase64String());
    }

    [Fact]
    public void Decrypt()
    {
        // Arrange
        var encrypted = "BMAQOzU6W/qAZBoRMlauWg==".FromBase64String();
        var key = "e0x8U5MyotKHiY1uxqxurg==".FromBase64String();
        var iv = "Z1kmtPGvz1g=".FromBase64String();

        // Act
        var decrypted = encrypted
            .UseTripleDES(key)
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
        const string encryptedFileName = "SymmetricAlgorithms/EncryptedDDDES.xlsx";
        const string decryptedFileName = "SymmetricAlgorithms/DecryptedDDDES.xlsx";
        var key = "e0x8U5MyotKHiY1uxqxurg==".FromBase64String();
        var iv = "Z1kmtPGvz1g=".FromBase64String();

        // Act
        using var inputStream = File.OpenRead(originalFileName);
        using var outputStream = File.OpenWrite(encryptedFileName);
        {
            inputStream
                .UseTripleDES(key)
                .WithCipher(CipherMode.ECB)
                .WithPadding(PaddingMode.PKCS7)
                .WithIV(iv)
                .Encrypt(outputStream);
        }

        using var inputStream2 = File.OpenRead(encryptedFileName);
        using var outputStream2 = File.OpenWrite(decryptedFileName);
        {
            inputStream2
                .UseTripleDES(key)
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
        Assert.Equal("2DF2C5306B807D5817DAE37629973140", hashed3);
    }
}
