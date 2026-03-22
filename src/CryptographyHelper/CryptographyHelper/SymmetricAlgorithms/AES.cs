using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelper.SymmetricAlgorithms;

public class AES : SymmetricCrypto
{
    public static AES Use(byte[] data, byte[] key)
    {
        return new AES
        {
            _bytes = data,
            _key = key,
        };
    }

    public static AES Use(Stream data, byte[] key)
    {
        return new AES
        {
            _stream = data,
            _key = key,
        };
    }

    private AES()
    {
    }

    protected override SymmetricAlgorithm GetSymmetricAlgorithm()
    {
        return Aes.Create();
    }


    public (byte[], byte[]) EncryptCcm(byte[] nonce, byte[] asociatedData)
    {
        var tag = new byte[16];
        var cipherText = new byte[_bytes.Length];

        using var aesGcm = new AesCcm(_key);
        aesGcm.Encrypt(nonce, _bytes, cipherText, tag, asociatedData);

        return (cipherText, tag);
    }

    public byte[] DecryptCcm(byte[] nonce, byte[] asociatedData, byte[] tag)
    {
        var decryptedData = new byte[_bytes.Length];

        using var aesGcm = new AesCcm(_key);
        aesGcm.Decrypt(nonce, _bytes, decryptedData, tag, asociatedData);

        return decryptedData;
    }
}
