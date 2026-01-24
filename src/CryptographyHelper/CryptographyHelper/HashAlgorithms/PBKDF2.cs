using System.Security.Cryptography;

namespace CryptographyHelper.HashAlgorithms;

/// <summary>
/// password-based key derivation functionality
/// </summary>
public class PBKDF2
{
    private readonly string _password;
    private byte[] _salt;
    private int? _saltSize;
    private int? _iterations;
    private HashAlgorithmName? _hashAlgorithm;

    public PBKDF2(string password)
    {
        _password = password;
    }

    public PBKDF2 WithSalt(int saltSize)
    {
        _saltSize = saltSize;
        _salt = null;
        return this;
    }

    public PBKDF2 WithSalt(byte[] salt)
    {
        _salt = salt;
        _saltSize = null;
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
        using var rfc2898 = GetRfc2898();
        return rfc2898.GetBytes(length);
    }


    private Rfc2898DeriveBytes GetRfc2898()
    {
        if (_saltSize != null)
        {
            return new Rfc2898DeriveBytes(_password, _saltSize.Value, _iterations ?? 1000, _hashAlgorithm ?? HashAlgorithmName.SHA1);
        }

        return new Rfc2898DeriveBytes(_password, _salt, _iterations ?? 1000, _hashAlgorithm ?? HashAlgorithmName.SHA1);
    }
}
