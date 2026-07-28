using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LunaPacketSniffer.Proxy;

public sealed class RootCertificateAuthority
{
    private const string Subject = "CN=LunaPacketSniffer Root CA";
    private const string FriendlyName = "LunaPacketSniffer Root CA";
    private X509Certificate2? _certificate;

    public bool IsInstalled() => FindCertificate(StoreName.Root, false) is not null;

    public X509Certificate2 EnsureInstalled()
    {
        if (_certificate is not null && _certificate.HasPrivateKey)
        {
            return _certificate;
        }

        var certificate = FindCertificate(StoreName.My, true);
        if (certificate is null || !certificate.HasPrivateKey)
        {
            certificate?.Dispose();
            RemoveFromStore(StoreName.Root);
            RemoveFromStore(StoreName.My);
            certificate = CreateCertificate();
        }

        AddToStore(StoreName.My, certificate);
        AddToStore(StoreName.Root, certificate);
        _certificate = certificate;
        return certificate;
    }

    public void Remove()
    {
        RemoveFromStore(StoreName.Root);
        RemoveFromStore(StoreName.My);
        _certificate?.Dispose();
        _certificate = null;
    }

    public X509Certificate2 CreateLeafCertificate(string hostName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        var rootCertificate = EnsureInstalled();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={hostName}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            true));
        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        subjectAlternativeNames.AddDnsName(hostName);
        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var serialNumber = RandomNumberGenerator.GetBytes(16);
        using var issuedCertificate = request.Create(
            rootCertificate,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(30),
            serialNumber);
        using var certificateWithPrivateKey = issuedCertificate.CopyWithPrivateKey(key);
        return X509CertificateLoader.LoadPkcs12(
            certificateWithPrivateKey.Export(X509ContentType.Pkcs12),
            password: null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
            true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
        var persistentCertificate = X509CertificateLoader.LoadPkcs12(
            certificate.Export(X509ContentType.Pkcs12),
            password: null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        persistentCertificate.FriendlyName = FriendlyName;
        return persistentCertificate;
    }

    private static X509Certificate2? FindCertificate(StoreName storeName, bool validOnly)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        return store.Certificates
            .Find(X509FindType.FindBySubjectDistinguishedName, Subject, validOnly)
            .OfType<X509Certificate2>()
            .FirstOrDefault(certificate => certificate.FriendlyName == FriendlyName);
    }

    private static void AddToStore(StoreName storeName, X509Certificate2 certificate)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        if (!store.Certificates.OfType<X509Certificate2>().Any(existing => existing.Thumbprint == certificate.Thumbprint))
        {
            store.Add(certificate);
        }
    }

    private static void RemoveFromStore(StoreName storeName)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
        foreach (var certificate in store.Certificates
                     .Find(X509FindType.FindBySubjectDistinguishedName, Subject, false)
                     .OfType<X509Certificate2>()
                     .Where(certificate => certificate.FriendlyName == FriendlyName)
                     .ToArray())
        {
            store.Remove(certificate);
        }
    }
}
