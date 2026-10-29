using System.Security.Cryptography;
using System.Text;
using System.Xml;
using CryptographyHelper.AsymmetricAlgorithms;
using CryptographyHelper.HashAlgorithms;
using CryptographyHelper.SymmetricAlgorithms;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 2_000_000);
builder.Services.AddProblemDetails();
var app = builder.Build();
app.UseExceptionHandler();
app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";
    try { await next(context); }
    catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException or XmlException)
    {
        await Results.Problem(statusCode: 400, title: "Check your inputs", detail: ex.Message).ExecuteAsync(context);
    }
});
app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));
app.MapPost("/api/hash", (HashRequest request) =>
{
    var data = Playground.Decode(request.Input, request.Encoding);
    Hash hash = request.Algorithm switch
    {
        "MD5" => data.UseMd5(), "SHA1" => data.UseSha1(), "SHA256" => data.UseSha256(),
        "SHA384" => data.UseSha384(), "SHA512" => data.UseSha512(),
        _ => throw new ArgumentException("Choose a supported hash algorithm.")
    };
    if (request.Hmac) hash.WithKey(Playground.Decode(request.Key, request.KeyEncoding));
    return Playground.Output(hash.ComputeHash());
});
app.MapPost("/api/pbkdf2", (DeriveRequest request) =>
{
    ArgumentNullException.ThrowIfNull(request.Password);
    if (request.Iterations is < 1 or > 1_000_000 || request.Length is < 1 or > 128)
        throw new ArgumentException("Use 1–1,000,000 iterations and 1–128 output bytes.");
    var salt = Playground.Decode(request.Salt, "Base64");
    if (salt.Length < 8) throw new ArgumentException("Salt must contain at least 8 bytes.");
    return Playground.Output(new PBKDF2(request.Password).WithSalt(salt)
        .WithIterations(request.Iterations).WithHashAlgorithm(Playground.HashName(request.Algorithm)).GetBytes(request.Length));
});
app.MapPost("/api/random", (RandomRequest request) =>
{
    if (request.Length is < 1 or > 128) throw new ArgumentException("Use 1–128 random bytes.");
    return Playground.Output(SymmetricCrypto.GenerateKey(request.Length));
});
app.MapPost("/api/symmetric", (SymmetricRequest request) =>
{
    var data = Playground.Decode(request.Input, request.Operation == "decrypt" ? "Base64" : request.Encoding);
    var key = Playground.Decode(request.Key, "Base64");
    SymmetricCrypto crypto = request.Algorithm switch
    {
        "AES" => data.UseAES(key), "DES" => data.UseDES(key), "TripleDES" => data.UseTripleDES(key),
        _ => throw new ArgumentException("Choose AES, DES, or TripleDES.")
    };
    crypto.WithCipher(request.Mode switch { "CBC" => CipherMode.CBC, "ECB" => CipherMode.ECB,
        _ => throw new ArgumentException("Choose CBC or ECB.") });
    crypto.WithPadding(request.Padding switch { "PKCS7" => PaddingMode.PKCS7, "None" => PaddingMode.None,
        "Zeros" => PaddingMode.Zeros, "ANSIX923" => PaddingMode.ANSIX923,
        _ => throw new ArgumentException("Unsupported padding.") });
    if (request.Mode != "ECB") crypto.WithIV(Playground.Decode(request.Iv, "Base64"));
    return request.Operation switch
    {
        "encrypt" => Playground.Output(crypto.Encrypt()),
        "decrypt" => Playground.Output(crypto.Decrypt(), true),
        _ => throw new ArgumentException("Choose encrypt or decrypt.")
    };
});
app.MapPost("/api/rsa/keys", (RsaKeysRequest request) =>
{
    if (request.Size is not (2048 or 3072 or 4096)) throw new ArgumentException("Choose 2048, 3072, or 4096 bits.");
    var privateKey = RSACrypto.GenerateKey(request.Size);
    if (request.Format == "Xml") return new { privateKey, publicKey = RSACrypto.ExportPublicKey(privateKey) };
    if (request.Format != "Pem") throw new ArgumentException("Choose Xml or Pem.");
    using var rsa = RSA.Create();
    rsa.FromXmlString(privateKey);
    return new { privateKey = rsa.ExportPkcs8PrivateKeyPem(), publicKey = rsa.ExportSubjectPublicKeyInfoPem() };
});
app.MapPost("/api/rsa", (RsaRequest request) =>
{
    if (request.Operation is not ("encrypt" or "decrypt" or "sign" or "verify" or "signHash" or "verifyHash"))
        throw new ArgumentException("Unsupported RSA operation.");
    var format = request.Format switch { "Xml" => KeyFormat.Xml, "Pem" => KeyFormat.Pem,
        _ => throw new ArgumentException("Choose Xml or Pem.") };
    var hash = Playground.HashName(request.Algorithm);
    var padding = request.Padding switch { "OAEP-SHA256" => RSAEncryptionPadding.OaepSHA256,
        "OAEP-SHA1" => RSAEncryptionPadding.OaepSHA1, "PKCS1" => RSAEncryptionPadding.Pkcs1,
        _ => throw new ArgumentException("Unsupported encryption padding.") };
    var signaturePadding = request.SignaturePadding switch { "PSS" => RSASignaturePadding.Pss,
        "PKCS1" => RSASignaturePadding.Pkcs1, _ => throw new ArgumentException("Unsupported signature padding.") };
    var data = Playground.Decode(request.Input, request.Operation == "decrypt" ? "Base64" : request.Encoding);
    var signature = request.Operation.StartsWith("verify") ? Playground.Decode(request.Signature, "Base64") : [];
    ArgumentException.ThrowIfNullOrWhiteSpace(request.Key);
    var crypto = data.UseRSA(request.Key, format);
    return request.Operation switch
    {
        "encrypt" => (object)Playground.Output(crypto.Encrypt(padding)),
        "decrypt" => Playground.Output(crypto.Decrypt(padding), true),
        "sign" => Playground.Output(crypto.SignData(hash, signaturePadding)),
        "signHash" => Playground.Output(crypto.SignHash(hash, signaturePadding)),
        "verifyHash" => new { verified = crypto.VerifyHash(signature, hash, signaturePadding) },
        _ => new { verified = crypto.VerifyData(signature, hash, signaturePadding) }
    };
});
app.Run();

static class Playground
{
    public static byte[] Decode(string input, string encoding)
    {
        ArgumentNullException.ThrowIfNull(input);
        return encoding switch { "Text" => Encoding.UTF8.GetBytes(input), "Base64" => Convert.FromBase64String(input),
            "Hex" => Convert.FromHexString(input), _ => throw new ArgumentException("Choose Text, Base64, or Hex encoding.") };
    }
    public static HashAlgorithmName HashName(string name) => name switch
    {
        "SHA1" => HashAlgorithmName.SHA1, "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384, "SHA512" => HashAlgorithmName.SHA512,
        _ => throw new ArgumentException("Unsupported hash algorithm.")
    };
    public static object Output(byte[] data, bool text = false) => new
    { hex = Convert.ToHexString(data), base64 = Convert.ToBase64String(data), bytes = data.Length, text = text ? Encoding.UTF8.GetString(data) : null };
}
record HashRequest(string Input, string Algorithm = "SHA256", string Encoding = "Text", bool Hmac = false, string Key = "", string KeyEncoding = "Text");
record DeriveRequest(string Password, string Salt, int Iterations = 100000, int Length = 32, string Algorithm = "SHA256");
record RandomRequest(int Length = 32);
record SymmetricRequest(string Input, string Key, string Iv = "", string Algorithm = "AES", string Operation = "encrypt", string Encoding = "Text", string Mode = "CBC", string Padding = "PKCS7");
record RsaKeysRequest(int Size = 2048, string Format = "Pem");
record RsaRequest(string Input, string Key, string Operation = "encrypt", string Format = "Pem", string Encoding = "Text", string Padding = "OAEP-SHA256", string Algorithm = "SHA256", string SignaturePadding = "PSS", string Signature = "");
