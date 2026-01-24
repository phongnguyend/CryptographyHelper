using System;
using System.Security.Cryptography.X509Certificates;

namespace CryptographyHelper.Certificates;

public static class CertificateStore
{
    public static X509Certificate2 Find(string thumbprint)
    {
        return Find(StoreName.My, StoreLocation.CurrentUser, thumbprint)
            ?? Find(StoreName.My, StoreLocation.LocalMachine, thumbprint);
    }

    public static X509Certificate2 Find(StoreName storeName, StoreLocation storeLocation, string thumbprint)
    {
        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);
        foreach (var cert in store.Certificates)
        {
            if (cert.Thumbprint.Equals(thumbprint, StringComparison.CurrentCultureIgnoreCase))
            {
                return cert;
            }
        }
        return null;
    }
}
