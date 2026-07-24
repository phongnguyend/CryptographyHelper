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

        var existingEncryptedTexts = new string[]
        {
            "Qw3C1m2L4R77MYCh349/Lm+n5RrYpVZvmHxv+TH8OoNhzF0w0T35lhWWlm42ml9B384NVIgTL0V6wzNViBWxTv8Nbqw7QbQmIFytLaMaZkKq/XO/k6MGTwHNQCxrTgzMhpOkUUP7EUETmjULSHcerLmOO0Ni9NJVF2GYMR9tuB4=",
            "TUhQDHGWIFREkkJCuxk0vis0IfGXYr2T0+isaOm9ohWvIFbUEzU0fSLMsy5PnzeuDOb1idj7rLoWcTk0aD576mf4xTBYOfEhUK8q1JR+T8AP09NkZLmlJSoq/6ayUbngPnJQ0GmGVd/5kz4fxxQuEHrlv/M5OZnkXLfn7i/9PxE=",
            "DVgbGaikvsFJtTCk89WIsZLzeTPpE0v+MjUqgY4uzGznbTOcpVVYyz8wwd7hvu7VNE54V6ScztHx8L1tA4ZT2Y6RvEvJTVu85UIaw17VUEpEA9DKYwk2vNya9WNPALCiJNnxo4aCmxLGqS6hzhVM21DPCgTyYoaV4UEBlEO7Nss=",
            "MIjB7tWLvWHOU8Eb9jN/5Q5O2ZFdptZQzeMmbvhVyvImtAzaL83gGGlk7IeTl7kcuDrzAtKmbZbS8Wa8DDtPZT6c/0x0OQ7mq9M4QyjmsuCFvIjs4/XsF7ac+B78DWCgTwyW9/ueCsv0g2n6+yMkoesfRoha4B8TOaDG/YsI4js=",
            "WBfla2KJ7/LSnHaMSt4HtgGGKea91Zrk0RO8pxy7DJWptXkgGTM98q3IXhNg5dNyvKLxlD13+hPc6kG3Oi3+XuRZ1f59hY14TvV4ejukGILgOScj/QWO9as9Q0fsSmO1/IkIQk8AvX/DypV8jbAb6L1XZQcZPRHNspZ2V/sY67U=",
            "QwdvQvHhwnpdnTa0UETFmnaYF3YEmaNoTeyfXCHW/B/ccoDIfqPBozfQZR3xedMAZxTafYD0doiPlGAdus7/7x98ctL8yOK8gSAQgLmQB34fUTs7AaicS6LLv4XDKBo3hMmHTS23rg98/MzUxmBPtBvJaUJWjTfDGGEsCTQaCxY=",
            "BtRFhw09qa4jvJv6aTMOD34PIc2LN4GEPUVSYWSzIpZ2qPXnCO3XNPAVe+KXywwLVAjSArRF77vjr1yOQYGE1Rjj72ZIBSY9olrIO/871QUANvcQnMmh62apG/iBIbsi8STH76f8tUmWQJbHX/gd8gltvnjFWZDk3nleKgzWAYw=",
            "Wl2QLy9/cc/uqkJnb3b6Ry7rz9KBMvoBXDl3OpcWrkXnPOVmBnWnQnn2b8gAbDWrbLWMYVV3YsP0CK6zL47DAwHT1zwCA2PuRxlNndbR2ohAklglNv2OG00B3FJTky3ThcIhDzsWEbCIoU50d5oCPqM4PThT2NGbxw5pepkYfSA=",
            "Z09tgBFI+MU6u5aO+EPz3XClpQB36+NvjrniVXEhln09IevtSRUIYll2CrqAvN05SYQMfqM1QEAZ72pKpQZ4kxH/dncEFt3uR/uP7rV2cLJ218qE/sE0NMVIxHWrscn4lPNxyVbAfjjNJWOvnyyZn6ItGzl036KEVjWNOlDk330=",
            "HKrhTpKb9gpmXx1eUcew24xhqJX0hsV9W2Ta/K/MPCq+n5gucJv0T1w3ey93qMsnEe7rcUfx8lNh0Yo8H/od8tRjiqfw7CNyl/ACT9jFX1Tg4Xz1SIOnHDIWly2rdkzsPkpwKMr3ZQyzJTHobP7OaxmfNR5caUx3R5YvsWvRTJ4="
        };

        foreach (var text in existingEncryptedTexts)
        {
            Assert.Equal("supper secret text", text.FromBase64String().UseRSA(rsaPrivateKey).Decrypt().GetString());
        }
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

            var existingEncryptedTexts = new string[]
            {
                "xlWlwufcf48gVuMO9YxcpPr4Y7Ko1aAQE5lEZCWnVtNaA6bigrS2PUxQ/NdEZHDNgs926D+VY2e//b0g2AwN6NKUKJopKdA4QJxH8AP7+EPPC8po6aB1peZCe+5RYvhC3Ax6C6FTdEVct0HDveQ+W+w3R/BHZC4NKX4VdBoCNf7nOaUlJ94bd162Ar7UlhT7AYg3TDg51Al/zGORx5t2r3EJnBRt9Lo9/mTkjP1M14qwYtsgb5S0PAqePSoB6vmNeMzN3ecXQnp/GkdjtZJ+Kew6GdB9VcoBcAcCwwdUfOWem6cQkDw6T1HHMvkjPhoS3ShjG2khcijX/o4+5xDkpA==",
                "0j6cz1lBDmIl4VoKqDhzcTY+YKPv0toaI7krN1467ijh7quslDG1U+HA5dqytHaDdOfKb7mXK/kB6XqI07ISWASbmd8ZdwFKdteyf7brAj6t6aScWkCIDbGRkrh+BuRKUBLIn2ddpyBWrr5n2acSUKrVqAxaLRlVtRaDHyiJU9X1VbYy4AUliWzRJFGHrC5il2syeZLnwKp7B3qW/onNFvzBKX5EJ3dA9PupQ5eArPrzQDMt6RHhen0cnqqlpgiUI5+T+Qw6It9WMLpBJ+1i402h2w04fqC8vKHmRA9ylWR0a2TnAwjkco9NxUKhFNpQpuqXd/fnN/z7KEPfrFw/qA==",
                "Ll5FShhS3Y3tlt0NFS+dqXznsW3aS7zXXcfCF1lpvjQ1byf8DmRfdPPXK1JgPgJslZkqM+SB1/leeT9Cj9l/4PwIC+h9T0fbIUTV08MTP8pB9Yv2h3wBN1TVxHphe1J3USMzRpxvM8yHXFHshpycjsyGPPRPLcx1nyHGhwgndXJloLfFV8AnDPUXlYx+mUfSv8KQHCw5GsrG6KFEfDMeM3JVqU8yL3m31IilSLOJ6YDgUcxCiX+mzFwoalMu0+keD27+UQliAuVESvvQLD4Kn1n1G5+YBxSx3g5fjCXnmbQeNc7SaVAoEyjWTlNgThCjfMHj7y8Hm5pDm9oNXcrFbg==",
                "hNlfSEDdrgiFyI2tKZAcZYE+3+V/d+mU7Of45KdbN9wuMGtgAArJTMWScIx0zDbxX9KIHtXKpHJliG46ZBd7mM4FH+4+Hb1iL+svkWZFzuRNWHPM+ZKQKo/hwPwGbmJGYh3bK7+aPa/0R3suXMFuTPkwhJ6g3tkQd7iHTZIr1NZhRwkv00uZ02MTZzjDGjJ5q/beSRVpBLyF7HWbIJhIHO8J8iUx4/QmMwU2k9xv5+xLPeD0+pHMA1ptB+9wUzlEfJCBmfQ6LqvIvl5/U3dkDxfrY6dlW2DUEpCuOb65Sv6wXuISn+ON6YcVHSNvrGq+K6ZUxD0URYiyFruqWmz2yw==",
                "iRmzuCLypxzwtT0v9vcKel06xDOvcUU1rQdrxPyQYLDzPt0P3rNuzKmEjsmz1gD+OTxCPtR2g2vqyRvv0qJ5dBL+DNrfV50CqSJCLYXeJNkCfpupAZ0uYINDIDoZB6z2Z9FVNSwz/XddFo/2Gawly+mGtAUjHtWqCmNz+PjaQpkWHGL4j0JAdUlqi7tb+po/3Pe8erQdTvGPwFnZzgRbDzLpyKgzIKOyw4ga+tAzkVRrkAQh28eK8CNFCEPK6GhuXtBXTKMrvLyyiMOEPbb0WUxjngkapB6yhC6uCT6A8KGEC+m/K/rC+vHpJxLu5j0ewgjwvmTPlYPokLLkNY0FaA==",
                "yY18sxBIIRtoDfkfpwWqr5VnMoxK+QrXqrQpndumdUzGxjFV9hZ/2dvMJWac/czScr/6JKbM4Aq+vxYVHljwVPAXGXnGMT3gxmffvhQmLM3O+y0jQo83SXyY0MMcMJXLRucByPCYZnZZvtYmhYGsX8nuUqFG0t2cc1SYMYwkkVWLBMfSt7QY4oXbCO0z7A2NhRpeZaBLVPD5ySpo+fYWn5FNqoWMR5mcLJs5Pt+VUT0zgfS7JnKpi9Yfl4cP08W5dZ2r+Be5Ap5W8wM05L46w/ny854gWIRc7xXjHKACx5Z5UFSc1rqYiqZk3w/w37/PDTeqxkKj5XReENW8fTpuIQ==",
                "YbJF9lnO6WuYQlLZPnReRfSE50FLEcqCN0CvMzqYRa5Tdqc1kqppgN486sTo9bEghQhSY5NNCnM/yIJhlJg5jWFa8dpRLR9N8qP5mRmRf0iGCyhriNQ0shr698/cMDjz1k1VAsMO+23t1GQwMefTNCbo+w//+8wJXPuxTJ4odSH0eQaB5p1jM2fjvO3G89G24Kl7JjuUX0SRuBNUkZMPwCFVGmWFvzxH+OINtRRQW8hQ66Fv1CYn1Bi2oSyrygjL+VqNXCgEYSMei6AKaAQeC/7uJiBPTXiNW6Y1v7ysNhDNUpbr0c7/SyoAfnwxzhWiJ59Rr4k3ZigznDRaIC99UA==",
                "lLplVgreynQHGEXsmECBZxibNmkbXs6cE1bPD35nxa0LhUPc1vOW7j51rBcWTNOaJMj0x6oGRlMdG8xx6c+YoTLD2iAcHaDgFXV5plz1jOVmP7p5iOAKQFd6+yBN6JRnY0KyAnO/j+eudowSFbpFudw4628r4etLns9R8UC5T/U0K2GOsZarWW26bUyrYpftB3WieUZ5HT60P5yrFPe3u3kIT3+M388exEPCBpfuY+O80lNx/ROBpdwVp9VIQEM1Z648FX4Z4lkC+2ZCHDmMYFeehcpfVx3FnQjAi8RMkBip4HOQuVwKLk2O9HdtHK6BldJfrvXI8puUmOPACNIvRQ==",
                "BZh8ZdgytJTiyC04hYf6LURknw7GrwbsuqdZWwG4YLmfsT8B96o+gEBqC63qftjPrMlxUnoQtxDbo3Wk19Kbgl0WHO1mxgpwH78VFd9GVS7ktr70amWoj36hMNU6EoE/NtqAusz+N6ZkenndNcQ/80lqGj5wNTHhCx9CHWZ3p/K5q7Vy7vv2H4lHVzmFQQ17iTA8MYOtJll5YhED29QwHBk3Bl87nLvbfl7fbmSHSQ7GnlKsVKY3IbY5hOv8Nvm15xNtMLlHRFROP71DDsZgrJpYYBwxoG549PKa5g2M+beNJBF2O+vgA3gkBz5pTye7cd8kHcMKDNbrmA5hDLwtqQ==",
                "Hbtge/ep0634ZXCpGsgYOKIId2JyZSv5SMGQ+/NYE/ivKDoqzsshr3GTttSGjkVmzQVpVnXdO2f3lO6Xw3XS4+Zcm81hoUKLduz68cLLgcXExx5+na8plUAuYQMUs+iSHHA5xPA3PkKbpy+7IeY8c3NBV71EWGPZ8Vmwki4myPcEQ/hRZPjKnalODXQ/+791q4L1OXqUqShVybRZfbh++Ja2k5cdAlSV375/q0O2fjdvtr2wg149/8C7SeDvivC9B2BgdXlHRvm0q4m1C55GV07JQnCBs9GF8xcu4sKMGk77Y9OjU6N0Nb/RZnctEHElimB1gziNmUV9VJRnVXvVjQ==",
            };

            foreach (var text in existingEncryptedTexts)
            {
                Assert.Equal("supper secret text", text.FromBase64String().UseRSA(cert).Decrypt().GetString());
            }
        }
    }

    [Fact]
    public void GenerateKey()
    {
        // Arrange
        var secret = "supper secret text";
        var rsaPrivateKey = RSACrypto.GenerateKey();
        var rsaPublicKey = RSACrypto.ExportPublicKey(rsaPrivateKey);
        var differentRsaPrivateKey = RSACrypto.GenerateKey();

        // Act
        var encrypted = secret.UseRSA(rsaPublicKey).Encrypt();
        var decrypted = encrypted.UseRSA(rsaPrivateKey).Decrypt();

        // Assert
        Assert.Equal("supper secret text", decrypted.GetString());
        Assert.ThrowsAny<CryptographicException>(() => encrypted.UseRSA(differentRsaPrivateKey).Decrypt());
    }

    [Fact]
    public void SignAndVerifyHash()
    {
        // Arrange
        var secret = "supper secret text".UseSha256().ComputeHash();
        var rsaPrivateKey = RSACrypto.GenerateKey();
        var rsaPublicKey = RSACrypto.ExportPublicKey(rsaPrivateKey);
        var differentRsaPublicKey = RSACrypto.ExportPublicKey(RSACrypto.GenerateKey());

        // Act
        var signature = secret.UseRSA(rsaPrivateKey).SignHash(HashAlgorithmName.SHA256);
        var verified = secret.UseRSA(rsaPublicKey).VerifyHash(signature, HashAlgorithmName.SHA256);
        var verifiedWithDifferentKey = secret.UseRSA(differentRsaPublicKey).VerifyHash(signature, HashAlgorithmName.SHA256);

        // Assert
        Assert.True(verified);
        Assert.False(verifiedWithDifferentKey);
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
        var differentRsaPublicKey = RSACrypto.ExportPublicKey(RSACrypto.GenerateKey());

        // Act
        var signature = secret.UseRSA(rsaPrivateKey).SignData(HashAlgorithmName.SHA512);
        var verified = secret.UseRSA(rsaPublicKey).VerifyData(signature, HashAlgorithmName.SHA512);
        var verifiedWithDifferentKey = secret.UseRSA(differentRsaPublicKey).VerifyData(signature, HashAlgorithmName.SHA512);

        // Assert
        Assert.True(verified);
        Assert.False(verifiedWithDifferentKey);
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
