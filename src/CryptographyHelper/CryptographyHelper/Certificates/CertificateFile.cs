using System.Security.Cryptography.X509Certificates;

namespace CryptographyHelper.Certificates;

public class CertificateFile
{
    public static X509Certificate2 Find(string fileName, string password = null, X509KeyStorageFlags? x509KeyStorageFlags = null)
    {
        if (X509Certificate2.GetCertContentType(fileName) != X509ContentType.Pkcs12)
        {
            return X509CertificateLoader.LoadCertificateFromFile(fileName);
        }

        return X509CertificateLoader.LoadPkcs12FromFile(
            fileName,
            password,
            x509KeyStorageFlags ?? X509KeyStorageFlags.DefaultKeySet);
    }
}
