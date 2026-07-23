using CryptographyHelper.AsymmetricAlgorithms;
using CryptographyHelper.Certificates;
using CryptographyHelper.HashAlgorithms;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace CryptographyHelper.Tests.AsymmetricAlgorithms;

public class RSATests
{
    [Fact]
    public void ExportPublicKey()
    {
        // Arrange
        var rsaPrivateKey = "<RSAKeyValue><Modulus>ahefVEBt94CwUd8yEjZ+CWXYf4jiQBahnYSxLWxv70/4vy0hHsQoUxkinlcAvTqhuyhrtgvxp6fotIGGq8Tp+GdTl7JASizb4CqRGJOcW2fp+0pzp8YEc7rxBjh3aJexRZh/BT7Ay5L+0EzkNX67GJNV7+MbaFWTfgt1jP+ea9s=</Modulus><Exponent>AQAB</Exponent><P>ptrYlsMKE5o8JdHKqdb8MEkaoGpGEbcNnK1naOLGwpRaK+Wc32UtmS3tNVBL+fRoxUjiJlFwH8OF2EPg9KBRnw==</P><Q>osYgOkMd/Zm9Hp4ZEjmDL6h5O5aWkyiBrnpG0vrUbHbZjNgknoM2bAZ5/8mud2mCa0Ixq3YI7u7L5Xr9iPgURQ==</Q><DP>ECTakfO7FNx2d15OEpLHgdCA8AZ4Uxx4B7HLcJ2Ih6kc9GRaAk9i0xBbhC4Ju9yHCpebsgNtKtWbLKqcqG6elw==</DP><DQ>ZuCMC+bRtLAPXKOVuvQImv2DKgtCPd4TIIB99Oi9i5QOabtOYbUSl3H8d5MzpptT55Cdrf3bJZBd5Ds4tPH+dQ==</DQ><InverseQ>faDRZ4/rsw2Q89/EPonsvtI+nE9X8CMw2TNNP9wiZ63fTFYuLFi/JgiwViOG66PAPwp/8iJXaVAl9ugYnh33ew==</InverseQ><D>Iy9YaRHBJq9oSo7SRVYLMMS1K37TQlv/F4WVWTI4YU7NeWHXNSPrF7wjTg4esaNLVg3Owx5s86RtOcgnSLpSueEAh068/+jaI2q5IpRFzyBZkrv/mDySxqwIQ4UD4SrOwOjLaNQBMT7GHVqFeFYzS8US8C9S/e0s6ouPhYqbwsk=</D></RSAKeyValue>";

        // Act
        var rsaPublicKey = RSACrypto.ExportPublicKey(rsaPrivateKey);

        // Assert
        var expected = "<RSAKeyValue><Modulus>ahefVEBt94CwUd8yEjZ+CWXYf4jiQBahnYSxLWxv70/4vy0hHsQoUxkinlcAvTqhuyhrtgvxp6fotIGGq8Tp+GdTl7JASizb4CqRGJOcW2fp+0pzp8YEc7rxBjh3aJexRZh/BT7Ay5L+0EzkNX67GJNV7+MbaFWTfgt1jP+ea9s=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        Assert.Equal(expected, rsaPublicKey);
    }

    [Fact]
    public void EncryptAndDecrypt()
    {
        // Arrange
        var secret = "supper secret text";
        var rsaPrivateKey = "<RSAKeyValue><Modulus>ahefVEBt94CwUd8yEjZ+CWXYf4jiQBahnYSxLWxv70/4vy0hHsQoUxkinlcAvTqhuyhrtgvxp6fotIGGq8Tp+GdTl7JASizb4CqRGJOcW2fp+0pzp8YEc7rxBjh3aJexRZh/BT7Ay5L+0EzkNX67GJNV7+MbaFWTfgt1jP+ea9s=</Modulus><Exponent>AQAB</Exponent><P>ptrYlsMKE5o8JdHKqdb8MEkaoGpGEbcNnK1naOLGwpRaK+Wc32UtmS3tNVBL+fRoxUjiJlFwH8OF2EPg9KBRnw==</P><Q>osYgOkMd/Zm9Hp4ZEjmDL6h5O5aWkyiBrnpG0vrUbHbZjNgknoM2bAZ5/8mud2mCa0Ixq3YI7u7L5Xr9iPgURQ==</Q><DP>ECTakfO7FNx2d15OEpLHgdCA8AZ4Uxx4B7HLcJ2Ih6kc9GRaAk9i0xBbhC4Ju9yHCpebsgNtKtWbLKqcqG6elw==</DP><DQ>ZuCMC+bRtLAPXKOVuvQImv2DKgtCPd4TIIB99Oi9i5QOabtOYbUSl3H8d5MzpptT55Cdrf3bJZBd5Ds4tPH+dQ==</DQ><InverseQ>faDRZ4/rsw2Q89/EPonsvtI+nE9X8CMw2TNNP9wiZ63fTFYuLFi/JgiwViOG66PAPwp/8iJXaVAl9ugYnh33ew==</InverseQ><D>Iy9YaRHBJq9oSo7SRVYLMMS1K37TQlv/F4WVWTI4YU7NeWHXNSPrF7wjTg4esaNLVg3Owx5s86RtOcgnSLpSueEAh068/+jaI2q5IpRFzyBZkrv/mDySxqwIQ4UD4SrOwOjLaNQBMT7GHVqFeFYzS8US8C9S/e0s6ouPhYqbwsk=</D></RSAKeyValue>";
        var rsaPublicKey = "<RSAKeyValue><Modulus>ahefVEBt94CwUd8yEjZ+CWXYf4jiQBahnYSxLWxv70/4vy0hHsQoUxkinlcAvTqhuyhrtgvxp6fotIGGq8Tp+GdTl7JASizb4CqRGJOcW2fp+0pzp8YEc7rxBjh3aJexRZh/BT7Ay5L+0EzkNX67GJNV7+MbaFWTfgt1jP+ea9s=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        // Act
        var encrypted = secret.UseRSA(rsaPublicKey).Encrypt();
        var decrypted = encrypted.UseRSA(rsaPrivateKey).Decrypt();

        // Assert
        Assert.Equal("supper secret text", decrypted.GetString());
        Assert.Equal("supper secret text", "Qw3C1m2L4R77MYCh349/Lm+n5RrYpVZvmHxv+TH8OoNhzF0w0T35lhWWlm42ml9B384NVIgTL0V6wzNViBWxTv8Nbqw7QbQmIFytLaMaZkKq/XO/k6MGTwHNQCxrTgzMhpOkUUP7EUETmjULSHcerLmOO0Ni9NJVF2GYMR9tuB4=".FromBase64String().UseRSA(rsaPrivateKey).Decrypt().GetString());
    }

    [Fact]
    public void EncryptAndDecryptUsingCert()
    {
        // Arrange
        var secret = "supper secret text";
        var cert = CertificateFile.Find("AsymmetricAlgorithms/classifiedads.identityserver.pfx", "password1234");

        for (var i = 0; i < 10; i++)
        {
            // Act
            var encrypted = secret.UseRSA(cert).Encrypt();
            var decrypted = encrypted.UseRSA(cert).Decrypt();

            // Assert
            Assert.Equal("supper secret text", decrypted.GetString());
            Assert.Equal("supper secret text", "xlWlwufcf48gVuMO9YxcpPr4Y7Ko1aAQE5lEZCWnVtNaA6bigrS2PUxQ/NdEZHDNgs926D+VY2e//b0g2AwN6NKUKJopKdA4QJxH8AP7+EPPC8po6aB1peZCe+5RYvhC3Ax6C6FTdEVct0HDveQ+W+w3R/BHZC4NKX4VdBoCNf7nOaUlJ94bd162Ar7UlhT7AYg3TDg51Al/zGORx5t2r3EJnBRt9Lo9/mTkjP1M14qwYtsgb5S0PAqePSoB6vmNeMzN3ecXQnp/GkdjtZJ+Kew6GdB9VcoBcAcCwwdUfOWem6cQkDw6T1HHMvkjPhoS3ShjG2khcijX/o4+5xDkpA==".FromBase64String().UseRSA(cert).Decrypt().GetString());
        }
    }

    [Fact]
    public void GenerateKey()
    {
        // Arrange
        var secret = "supper secret text";
        var rsaPrivateKey = RSACrypto.GenerateKey();
        var rsaPublicKey = RSACrypto.ExportPublicKey(rsaPrivateKey);

        // Act
        var encrypted = secret.UseRSA(rsaPublicKey).Encrypt();
        var decrypted = encrypted.UseRSA(rsaPrivateKey).Decrypt();

        // Assert
        Assert.Equal("supper secret text", decrypted.GetString());
    }

    [Fact]
    public void SignAndVerifyHash()
    {
        // Arrange
        var secret = "supper secret text".UseSha256().ComputeHash();
        var rsaPrivateKey = RSACrypto.GenerateKey();
        var rsaPublicKey = RSACrypto.ExportPublicKey(rsaPrivateKey);

        // Act
        var signature = secret.UseRSA(rsaPrivateKey).SignHash(HashAlgorithmName.SHA256);
        var verified = secret.UseRSA(rsaPublicKey).VerifyHash(signature, HashAlgorithmName.SHA256);

        // Assert
        Assert.True(verified);
    }

    [Fact]
    public void SignAndVerifyHashUsingCert()
    {
        // Arrange
        var secret = "supper secret text".UseSha256().ComputeHash();
        var cert = X509CertificateLoader.LoadPkcs12FromFile("AsymmetricAlgorithms/classifiedads.identityserver.pfx", "password1234");

        // Act
        var signature = secret.UseRSA(cert).SignHash(HashAlgorithmName.SHA256);
        var verified = secret.UseRSA(cert).VerifyHash(signature, HashAlgorithmName.SHA256);

        // Assert
        Assert.Equal("klXPjRjH+abAbWhqjEuZ37trrrEOaW8P46XCNXaHCy9c1QjC3gWQ2whsZcGoZH0MBWHgqbmourOGwMLHNT9b/t7NszOloYKwJwScb2CrHLjRE3McNUtlMA+BAxSkf8rEDHwISCUbsVfJK73L64AAqAYC6IbYeQeUWnUtGqBu+PoN72C4ugoiGzdMy4NFdAzmRHKcWfBp5T/mOFS5BdcgwPK59svHrfD4utiecph13dNdOYlN9gumox7PQN8fvCJnV6B+oKM64fQZH38/msvevG9O0mUFQvkJZ9BLNpTNVikUKnvgLkK7EjPPPUwAxmrVLR14jpbFijQjE5W/tYWt2g==", signature.ToBase64String());
        Assert.True(verified);
    }

    [Fact]
    public void SignAndVerifyData()
    {
        // Arrange
        var secret = "supper secret text";
        var rsaPrivateKey = RSACrypto.GenerateKey();
        var rsaPublicKey = RSACrypto.ExportPublicKey(rsaPrivateKey);

        // Act
        var signature = secret.UseRSA(rsaPrivateKey).SignData(HashAlgorithmName.SHA512);
        var verified = secret.UseRSA(rsaPublicKey).VerifyData(signature, HashAlgorithmName.SHA512);

        // Assert
        Assert.True(verified);
    }

    [Fact]
    public void SignAndVerifyDataUsingCert()
    {
        // Arrange
        var secret = "supper secret text";
        var cert = X509CertificateLoader.LoadPkcs12FromFile("AsymmetricAlgorithms/classifiedads.identityserver.pfx", "password1234");

        // Act
        var signature = secret.UseRSA(cert).SignData(HashAlgorithmName.SHA512);
        var verified = secret.UseRSA(cert).VerifyData(signature, HashAlgorithmName.SHA512);

        // Assert
        Assert.Equal("WcyBiFivsj86d8iGHg9LG/Ya1AaDZMmnmq5iuMRJtRRqDNtolIRu+voiXiQOEnH5pGBXulu/VeqEgM8SXxfgEUXAWcFhL/fBzIuo08KJK/hGm7R+nENXwKD5UkY1SuZYNvhe4EQLZR1zNcOVICnZuXAWOo+PqOPz8+po1g/r0JT0UvWQbX6WimrgUtMRK1gl+FCHosDSfc4/JnnJm2efmr3riowU+3hvS3xwN0kyLGrlC60xpLrdQUxQtL+7ZeV+RUpIYEf62QyD4pOm9f4bh0hOG2H8kWcRP58I3oN5TROWRwoViDJD9q37QJ9t6TxiiR0tktRz+ErmC1FV8ldISg==", signature.ToBase64String());
        Assert.True(verified);
    }
}
