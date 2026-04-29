namespace CryptographyHelper.HashAlgorithms;

public static class StringExtensions
{
    public static Hash UseMd5(this string data)
    {
        return data.GetBytes().UseMd5();
    }

    public static Hash UseSha1(this string data)
    {
        return data.GetBytes().UseSha1();
    }

    public static Hash UseSha256(this string data)
    {
        return data.GetBytes().UseSha256();
    }

    public static Hash UseSha384(this string data)
    {
        return data.GetBytes().UseSha384();
    }

    public static Hash UseSha512(this string data)
    {
        return data.GetBytes().UseSha512();
    }

    public static PBKDF2 UsePBKDF2(this string password, byte[] salt, int iterations)
    {
        return new PBKDF2(password).WithSalt(salt).WithIterations(iterations);
    }
}
