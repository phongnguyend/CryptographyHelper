using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelper.HashAlgorithms;

public class Sha384 : Hash
{
    public Sha384(byte[] bytesToBeHashed, Stream streamToBeHashed)
        : base(bytesToBeHashed, streamToBeHashed)
    {
    }

    public Sha384(FileInfo fileToBeHashed) 
        : base(fileToBeHashed)
    {
    }

    protected override HashAlgorithm GetHashAlgorithm()
    {
        return _key == null ? SHA384.Create() : new HMACSHA384(_key);
    }
}
