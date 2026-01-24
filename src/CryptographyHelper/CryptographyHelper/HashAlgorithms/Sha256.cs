using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelper.HashAlgorithms;

public class Sha256 : Hash
{
    public Sha256(byte[] bytesToBeHashed, Stream streamToBeHashed)
        : base(bytesToBeHashed, streamToBeHashed)
    {
    }

    public Sha256(FileInfo fileToBeHashed) 
        : base(fileToBeHashed)
    {
    }

    protected override HashAlgorithm GetHashAlgorithm()
    {
        return _key == null ? SHA256.Create() : new HMACSHA256(_key);
    }
}
