using System.Text;

namespace System.Security.Cryptography.X509Certificates;

public static class X509Certificate2Extensions
{
    public static string GetRSAPublicKeyXml(this X509Certificate2 cert)
    {
        return cert.GetRSAPublicKey().ToXmlString(false);
    }

    public static string GetRSAPublicKeyBase64(this X509Certificate2 cert)
    {
        var builder = new StringBuilder();

        builder.AppendLine("-----BEGIN CERTIFICATE-----");
        builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END CERTIFICATE-----");

        return builder.ToString();
    }
}
