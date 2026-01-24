using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelper.SymmetricAlgorithms;

public abstract class SymmetricCrypto
{
    public static byte[] GenerateKey(int length = 128)
    {
        return RandomNumberGenerator.GetBytes(length);
    }

    protected byte[] _bytes;
    protected Stream _stream;
    protected byte[] _key;
    protected CipherMode? _cipherMode;
    protected PaddingMode? _paddingMode;
    protected byte[] _iv;

    public SymmetricCrypto WithCipher(CipherMode cipherMode)
    {
        _cipherMode = cipherMode;
        return this;
    }

    public SymmetricCrypto WithPadding(PaddingMode paddingMode)
    {
        _paddingMode = paddingMode;
        return this;
    }

    public SymmetricCrypto WithIV(byte[] iv)
    {
        _iv = iv;
        return this;
    }

    protected abstract SymmetricAlgorithm GetSymmetricAlgorithm();

    private void Encrypt(Stream input, Stream output, bool leaveOpen)
    {
        using var crypto = GetSymmetricAlgorithm();
        crypto.Key = _key;
        crypto.Mode = _cipherMode ?? crypto.Mode;
        crypto.Padding = _paddingMode ?? crypto.Padding;
        crypto.IV = _iv ?? crypto.IV;

        using var cryptoStream = new CryptoStream(output, crypto.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen);
        int count = 0;
        int offset = 0;

        int blockSizeBytes = crypto.BlockSize / 8;
        byte[] data = new byte[blockSizeBytes];
        int bytesRead = 0;

        do
        {
            count = input.Read(data, 0, blockSizeBytes);
            offset += count;
            cryptoStream.Write(data, 0, count);
            bytesRead += blockSizeBytes;
        }
        while (count > 0);

        cryptoStream.FlushFinalBlock();
        cryptoStream.Close();
    }

    private void Decrypt(Stream input, Stream output, bool leaveOpen)
    {
        using var crypto = GetSymmetricAlgorithm();
        crypto.Key = _key;
        crypto.Mode = _cipherMode ?? crypto.Mode;
        crypto.Padding = _paddingMode ?? crypto.Padding;
        crypto.IV = _iv ?? crypto.IV;

        using var cryptoStream = new CryptoStream(output, crypto.CreateDecryptor(), CryptoStreamMode.Write, leaveOpen);
        int count = 0;
        int offset = 0;

        int blockSizeBytes = crypto.BlockSize / 8;
        byte[] data = new byte[blockSizeBytes];
        int bytesRead = 0;

        do
        {
            count = input.Read(data, 0, blockSizeBytes);
            offset += count;
            cryptoStream.Write(data, 0, count);
            bytesRead += blockSizeBytes;
        }
        while (count > 0);

        cryptoStream.FlushFinalBlock();
        cryptoStream.Close();
    }

    public byte[] Encrypt()
    {
        using var output = new MemoryStream();
        Encrypt(output);
        return output.ToArray();
    }

    public byte[] Decrypt()
    {
        using var output = new MemoryStream();
        Decrypt(output);
        return output.ToArray();
    }

    public void Encrypt(Stream output, bool leaveOpen = false)
    {
        if (_stream != null)
        {
            Encrypt(_stream, output, leaveOpen);
        }
        else
        {
            using var stream = _bytes.ToStream();
            Encrypt(stream, output, leaveOpen);
        }
    }

    public void Decrypt(Stream output, bool leaveOpen = false)
    {
        if (_stream != null)
        {
            Decrypt(_stream, output, leaveOpen);
        }
        else
        {
            using var stream = _bytes.ToStream();
            Decrypt(stream, output, leaveOpen);
        }
    }
}
