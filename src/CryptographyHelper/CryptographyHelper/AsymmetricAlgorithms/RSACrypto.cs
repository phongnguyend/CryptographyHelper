using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptographyHelper.AsymmetricAlgorithms;

public class RSACrypto
{
    public static string GenerateKey(int size = 1024)
    {
        using var crypto = new RSACryptoServiceProvider(size);
        return crypto.ToXmlString(true);
    }

    public static string ExportPublicKey(string keyXml)
    {
        using var crypto = new RSACryptoServiceProvider();
        crypto.FromXmlString(keyXml);
        return crypto.ToXmlString(false);
    }

    X509Certificate2 _cert;
    private RSA _crypto;
    private byte[] _data;

    public static RSACrypto Use(byte[] data, string key, KeyFormat format)
    {
        RSA crypto = null;

        if (format == KeyFormat.Xml)
        {
            crypto = new RSACryptoServiceProvider();
            crypto.FromXmlString(key);
        }
        else if (format == KeyFormat.Pem)
        {
            crypto = RSA.Create();
            crypto.ImportFromPem(key.ToCharArray());
        }

        return new RSACrypto()
        {
            _data = data,
            _crypto = crypto,
        };
    }

    public static RSACrypto Use(byte[] data, X509Certificate2 cert)
    {
        return new RSACrypto()
        {
            _data = data,
            _cert = cert
        };
    }

    private RSACrypto()
    {
    }

    public byte[] Encrypt()
    {
        using var crypto = _cert != null ? _cert.GetRSAPublicKey() : _crypto;
        return crypto.Encrypt(_data, RSAEncryptionPadding.Pkcs1);
    }

    public byte[] Decrypt()
    {
        using var crypto = _cert != null ? _cert.GetRSAPrivateKey() : _crypto;
        return crypto.Decrypt(_data, RSAEncryptionPadding.Pkcs1);
    }

    public byte[] SignHash(HashAlgorithmName hashAlgorithmName)
    {
        using var crypto = _cert != null ? _cert.GetRSAPrivateKey() : _crypto;
        return crypto.SignHash(_data, hashAlgorithmName, RSASignaturePadding.Pkcs1);
    }

    public bool VerifyHash(byte[] signature, HashAlgorithmName hashAlgorithmName)
    {
        using var crypto = _cert != null ? _cert.GetRSAPublicKey() : _crypto;
        return crypto.VerifyHash(_data, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
    }

    public byte[] SignData(HashAlgorithmName hashAlgorithmName)
    {
        using var crypto = _cert != null ? _cert.GetRSAPrivateKey() : _crypto;
        return crypto.SignData(_data, hashAlgorithmName, RSASignaturePadding.Pkcs1);
    }

    public bool VerifyData(byte[] signature, HashAlgorithmName hashAlgorithmName)
    {
        using var crypto = _cert != null ? _cert.GetRSAPublicKey() : _crypto;
        return crypto.VerifyData(_data, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
    }
}

public enum KeyFormat
{
    Xml,
    Pem,
}
