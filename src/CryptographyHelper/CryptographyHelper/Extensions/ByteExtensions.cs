using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyHelper;

public static class ByteExtensions
{
    public static byte[] Combine(this byte[] first, byte[] second)
    {
        var ret = new byte[first.Length + second.Length];

        Buffer.BlockCopy(first, 0, ret, 0, first.Length);
        Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

        return ret;
    }

    /// <summary>
    /// Compares byte contents in time that depends on their length, not their values.
    /// Two null arrays are equal; a null array and a non-null array are not.
    /// </summary>
    public static bool FixedTimeEquals(this byte[] a, byte[] b)
    {
        if (a == null || b == null)
        {
            return a == null && b == null;
        }

        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    [Obsolete("Use FixedTimeEquals instead. Calling array.Equals(other) uses reference equality, not this extension.")]
    public static bool Equals(this byte[] a, byte[] b)
    {
        return FixedTimeEquals(a, b);
    }

    [Obsolete("Please use ToHexString(byte[]) instead")]
    public static string ToHashedString(this byte[] data)
    {
        return ToHexString(data);
    }

    public static string ToHexString(this byte[] data)
    {
        return Convert.ToHexString(data);
    }

    public static string ToBase64String(this byte[] data, Base64FormattingOptions formattingOptions = Base64FormattingOptions.None)
    {
        return data != null ? Convert.ToBase64String(data, formattingOptions) : null;
    }

    public static string GetString(this byte[] data, Encoding encoding = null)
    {
        return (encoding ?? Encoding.UTF8).GetString(data);
    }

    public static MemoryStream ToStream(this byte[] data)
    {
        return new MemoryStream(data);
    }
}
