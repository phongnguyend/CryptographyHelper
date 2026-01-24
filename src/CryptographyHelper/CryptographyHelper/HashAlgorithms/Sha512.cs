using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelper.HashAlgorithms;

public class Sha512 : Hash
{
    public Sha512(byte[] bytesToBeHashed, Stream streamToBeHashed)
        : base(bytesToBeHashed, streamToBeHashed)
    {
    }

    public Sha512(FileInfo fileToBeHashed) 
        : base(fileToBeHashed)
    {
    }

    protected override HashAlgorithm GetHashAlgorithm()
    {
        return _key == null ? SHA512.Create() : new HMACSHA512(_key);
    }
}
