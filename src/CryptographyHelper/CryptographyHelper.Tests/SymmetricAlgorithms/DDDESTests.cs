using System.IO;
using System.Security.Cryptography;
using CryptographyHelper.HashAlgorithms;
using CryptographyHelper.SymmetricAlgorithms;
using Xunit;

namespace CryptographyHelper.Tests.SymmetricAlgorithms;

public class DDDESTests
{
    [Theory]
    [InlineData(
        "Text to encrypt",
        "e0x8U5MyotKHiY1uxqxurg==",
        "Z1kmtPGvz1g=",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "BMAQOzU6W/qAZBoRMlauWg==")]
    [InlineData(
        "Text to encrypt 2",
        "e0x8U5MyotKHiY1uxqxurg==",
        "Z1kmtPGvz1g=",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "BMAQOzU6W/qDBScpkdMgJ0/BafSVkfyT")]
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
            .UseTripleDES(key)
            .WithCipher(cipherMode)
            .WithPadding(paddingMode)
            .WithIV(iv)
            .Encrypt();

        // Assert
        Assert.Equal(expected, encrypted.ToBase64String());
    }

    [Theory]
    [InlineData(
        "BMAQOzU6W/qAZBoRMlauWg==",
        "e0x8U5MyotKHiY1uxqxurg==",
        "Z1kmtPGvz1g=",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "Text to encrypt")]
    [InlineData(
        "BMAQOzU6W/qDBScpkdMgJ0/BafSVkfyT",
        "e0x8U5MyotKHiY1uxqxurg==",
        "Z1kmtPGvz1g=",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "Text to encrypt 2")]
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
            .UseTripleDES(key)
            .WithCipher(cipherMode)
            .WithPadding(paddingMode)
            .WithIV(iv)
            .Decrypt();
        
        // Assert
        Assert.Equal(expected, decrypted.GetString());
    }

    [Theory]
    [InlineData(
        "e0x8U5MyotKHiY1uxqxurg==",
        "Z1kmtPGvz1g=",
        CipherMode.ECB,
        PaddingMode.PKCS7,
        "E9BEF8A00841C82C52C35A512DAD8093",
        "2DF2C5306B807D5817DAE37629973140")]
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
        const string encryptedFileName = "SymmetricAlgorithms/EncryptedDDDES.xlsx";
        const string decryptedFileName = "SymmetricAlgorithms/DecryptedDDDES.xlsx";
        var key = keyBase64.FromBase64String();
        var iv = ivBase64.FromBase64String();

        // Act
        using var inputStream = File.OpenRead(originalFileName);
        using var outputStream = File.OpenWrite(encryptedFileName);
        {
            inputStream
                .UseTripleDES(key)
                .WithCipher(cipherMode)
                .WithPadding(paddingMode)
                .WithIV(iv)
                .Encrypt(outputStream);
        }

        using var inputStream2 = File.OpenRead(encryptedFileName);
        using var outputStream2 = File.OpenWrite(decryptedFileName);
        {
            inputStream2
                .UseTripleDES(key)
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
