# Nuget
https://www.nuget.org/packages/CryptographyHelper

# Cryptography Object Inheritance In .Net

**Hash Algorithms:**

![alt text](/docs/imgs/HashAlgorithm.png)

**Symmetric Algorithms:**

![alt text](/docs/imgs/SymmetricAlgorithm.png)

**Asymmetric Algorithms:**

![alt text](/docs/imgs/AsymmetricAlgorithm.png)

---

## Hash Algorithms

Supports hashing data from a `string`, `byte[]`, `Stream`, or `FileInfo` using MD5, SHA-1, SHA-256, SHA-384, or SHA-512. An optional HMAC key can be provided via `.WithKey()`. Results can be retrieved as `byte[]`, a hex string, or a Base64 string.

### Supported Algorithms

| Method | Algorithm |
|---|---|
| `UseMd5()` | MD5 |
| `UseSha1()` | SHA-1 |
| `UseSha256()` | SHA-256 |
| `UseSha384()` | SHA-384 |
| `UseSha512()` | SHA-512 |

### Hash a String

```csharp
using CryptographyHelper.HashAlgorithms;

// Hex string output
var hashed = "Original Message to hash".UseSha256().ComputeHash().ToHexString();

// Base64 string output
var hashed = "Original Message to hash".UseSha256().ComputeHashedString(Hash.StringFormat.Base64);
```

### Hash a byte Array

```csharp
using CryptographyHelper.HashAlgorithms;

byte[] data = "Original Message to hash".GetBytes();
var hashed = data.UseSha256().ComputeHash().ToHexString();
```

### Hash a Stream

```csharp
using CryptographyHelper.HashAlgorithms;

using var stream = File.OpenRead("file.txt");
var hashed = stream.UseSha256().ComputeHash().ToHexString();
```

### Compute a File Checksum

```csharp
using CryptographyHelper.HashAlgorithms;

var checksum = "path/to/file.xlsx".ToFileInfo().UseMd5().ComputeHashedString();
```

### HMAC (Hash with Key)

```csharp
using CryptographyHelper.HashAlgorithms;

var key = "mysecretkey".GetBytes();
var hashed = "Original Message to hash".UseSha512().WithKey(key).ComputeHash().ToHexString();
```

### PBKDF2 (Password-Based Key Derivation)

Derive a cryptographic key from a password using `PBKDF2`. You can provide a salt as a `byte[]`, set the number of iterations, and optionally choose a hash algorithm.

```csharp
using CryptographyHelper.HashAlgorithms;
using System.Security.Cryptography;

var salt = "65QuFYgSxqIW0d9Y/QKRX9veWK0DOyX0g7+nbr9yux8=".FromBase64String();
var key = "MyVeryComplexPassword"
    .UsePBKDF2(salt, iterations: 500000)
    .GetBytes(32)
    .ToBase64String();
```

---

## Symmetric Algorithms

Supports encrypting and decrypting data from a `string`, `byte[]`, or `Stream` using DES, Triple DES, or AES. Cipher mode, padding mode, and IV can be configured with a fluent API.

### Supported Algorithms

| Method | Algorithm |
|---|---|
| `UseDES(key)` | DES (64-bit key) |
| `UseTripleDES(key)` | Triple DES (128-bit or 192-bit key) |
| `UseAES(key)` | AES (128, 192, or 256-bit key) |

### Generate a Random Key

```csharp
using CryptographyHelper.SymmetricAlgorithms;

byte[] key = SymmetricCrypto.GenerateKey(32); // 32 bytes = 256-bit key
```

### Encrypt and Decrypt a String

```csharp
using CryptographyHelper.SymmetricAlgorithms;
using System.Security.Cryptography;

var key = "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=".FromBase64String();
var iv  = "bXhlXQwu0R9qMjbCfEo7GA==".FromBase64String();

// Encrypt
var encrypted = "Text to encrypt"
    .UseAES(key)
    .WithCipher(CipherMode.CBC)
    .WithPadding(PaddingMode.PKCS7)
    .WithIV(iv)
    .Encrypt();

// Decrypt
var decrypted = encrypted
    .UseAES(key)
    .WithCipher(CipherMode.CBC)
    .WithPadding(PaddingMode.PKCS7)
    .WithIV(iv)
    .Decrypt()
    .GetString();
```

### Encrypt and Decrypt a byte Array

```csharp
using CryptographyHelper.SymmetricAlgorithms;
using System.Security.Cryptography;

byte[] data = "Text to encrypt".GetBytes();
var key = "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=".FromBase64String();
var iv  = "bXhlXQwu0R9qMjbCfEo7GA==".FromBase64String();

var encrypted = data.UseAES(key).WithCipher(CipherMode.CBC).WithIV(iv).Encrypt();
var decrypted = encrypted.UseAES(key).WithCipher(CipherMode.CBC).WithIV(iv).Decrypt().GetString();
```

### Encrypt and Decrypt a File (Stream)

```csharp
using CryptographyHelper.SymmetricAlgorithms;
using System.Security.Cryptography;

var key = "MeNFuKVG63Ks7dChmDvA67lSN6eKDE1QVuZT1dGCYlI=".FromBase64String();
var iv  = "bXhlXQwu0R9qMjbCfEo7GA==".FromBase64String();

// Encrypt
using var inputStream  = File.OpenRead("original.xlsx");
using var outputStream = File.OpenWrite("encrypted.xlsx");
inputStream.UseAES(key).WithCipher(CipherMode.CBC).WithIV(iv).Encrypt(outputStream);

// Decrypt
using var inputStream2  = File.OpenRead("encrypted.xlsx");
using var outputStream2 = File.OpenWrite("decrypted.xlsx");
inputStream2.UseAES(key).WithCipher(CipherMode.CBC).WithIV(iv).Decrypt(outputStream2);
```

### DES and Triple DES

The same fluent API applies to DES and Triple DES:

```csharp
// DES
var encrypted = "Text to encrypt".UseDES(key).WithCipher(CipherMode.CBC).WithIV(iv).Encrypt();

// Triple DES
var encrypted = "Text to encrypt".UseTripleDES(key).WithCipher(CipherMode.CBC).WithIV(iv).Encrypt();
```

---

## Asymmetric Algorithms

Supports RSA encryption/decryption and RSA signing/verification using XML keys, PEM keys, or X.509 certificates.

### Generate and Export RSA Keys

```csharp
using CryptographyHelper.AsymmetricAlgorithms;

// Generate an XML-formatted private key (includes public key)
string privateKey = RSACrypto.GenerateKey(size: 2048);

// Export just the public key portion
string publicKey = RSACrypto.ExportPublicKey(privateKey);
```

### Encrypt and Decrypt

```csharp
using CryptographyHelper.AsymmetricAlgorithms;

string privateKey = RSACrypto.GenerateKey();
string publicKey  = RSACrypto.ExportPublicKey(privateKey);

// Encrypt with public key
byte[] encrypted = "super secret text".UseRSA(publicKey).Encrypt();

// Decrypt with private key
string decrypted = encrypted.UseRSA(privateKey).Decrypt().GetString();
```

### Encrypt and Decrypt Using PEM Keys

```csharp
using CryptographyHelper.AsymmetricAlgorithms;

string pemPublicKey  = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
string pemPrivateKey = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";

byte[] encrypted = "super secret text".UseRSA(pemPublicKey, KeyFormat.Pem).Encrypt();
string decrypted = encrypted.UseRSA(pemPrivateKey, KeyFormat.Pem).Decrypt().GetString();
```

### Encrypt and Decrypt Using a Certificate

```csharp
using CryptographyHelper.AsymmetricAlgorithms;
using CryptographyHelper.Certificates;

var cert = CertificateFile.Find("path/to/cert.pfx", "password");

byte[] encrypted = "super secret text".UseRSA(cert).Encrypt();
string decrypted = encrypted.UseRSA(cert).Decrypt().GetString();
```

### Sign and Verify a Hash

```csharp
using CryptographyHelper.AsymmetricAlgorithms;
using CryptographyHelper.HashAlgorithms;
using System.Security.Cryptography;

string privateKey = RSACrypto.GenerateKey();
string publicKey  = RSACrypto.ExportPublicKey(privateKey);

byte[] hash = "super secret text".UseSha256().ComputeHash();

byte[] signature = hash.UseRSA(privateKey).SignHash(HashAlgorithmName.SHA256);
bool   verified  = hash.UseRSA(publicKey).VerifyHash(signature, HashAlgorithmName.SHA256);
```

### Sign and Verify Data

```csharp
using CryptographyHelper.AsymmetricAlgorithms;
using System.Security.Cryptography;

string privateKey = RSACrypto.GenerateKey();
string publicKey  = RSACrypto.ExportPublicKey(privateKey);

byte[] signature = "super secret text".UseRSA(privateKey).SignData(HashAlgorithmName.SHA512);
bool   verified  = "super secret text".UseRSA(publicKey).VerifyData(signature, HashAlgorithmName.SHA512);
```

### Sign and Verify Using a Certificate

```csharp
using CryptographyHelper.AsymmetricAlgorithms;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var cert = new X509Certificate2("path/to/cert.pfx", "password");

byte[] signature = "super secret text".UseRSA(cert).SignData(HashAlgorithmName.SHA512);
bool   verified  = "super secret text".UseRSA(cert).VerifyData(signature, HashAlgorithmName.SHA512);
