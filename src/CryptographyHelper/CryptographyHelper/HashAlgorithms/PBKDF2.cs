using System.Security.Cryptography;

namespace CryptographyHelper.HashAlgorithms;

/// <summary>
/// password-based key derivation functionality
/// </summary>
public class PBKDF2
{
    private readonly string _password;
    private byte[] _salt;
    private int? _iterations;
    private HashAlgorithmName? _hashAlgorithm;

    public PBKDF2(string password)
    {
        _password = password;
    }

    public PBKDF2 WithSalt(byte[] salt)
    {
        _salt = salt;
        return this;
    }

    public PBKDF2 WithIterations(int iterations)
    {
        _iterations = iterations;
        return this;
    }

    public PBKDF2 WithHashAlgorithm(HashAlgorithmName hashAlgorithm)
    {
        _hashAlgorithm = hashAlgorithm;
        return this;
    }

    public byte[] GetBytes(int length)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            _password,
            _salt,
            _iterations ?? 1000,
            _hashAlgorithm ?? HashAlgorithmName.SHA1,
            length);
    }
}
