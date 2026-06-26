using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WpfApp
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static class CertificateManager
    {
        private const string CertFileName = "server_certificate.pfx";
        private const string CertPasswordFile = "server_cert_password.txt";

        public static string CertPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, CertFileName);
        public static string CertPasswordPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, CertPasswordFile);

        public static bool CertificateExists()
        {
            return File.Exists(CertPath) && File.Exists(CertPasswordPath);
        }

        public static X509Certificate2 GenerateCertificate(string subjectName = "Trap-Panel Server CA")
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                $"CN={subjectName}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    true));
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                    false));

            var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.MaxValue);

            return certificate;
        }

        public static void SaveCertificate(X509Certificate2 certificate, string password)
        {
            byte[] certBytes = certificate.Export(X509ContentType.Pkcs12, password);
            File.WriteAllBytes(CertPath, certBytes);
            File.WriteAllText(CertPasswordPath, password);
        }

        public static X509Certificate2 LoadCertificate()
        {
            if (!CertificateExists())
                throw new FileNotFoundException("Certificate files not found.");

            string password = File.ReadAllText(CertPasswordPath);
            var cert = new X509Certificate2(CertPath, password, X509KeyStorageFlags.Exportable);

            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                bool found = false;
                foreach (var existing in store.Certificates)
                {
                    if (existing.Thumbprint == cert.Thumbprint)
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    store.Add(cert);
            }
            catch { }

            return cert;
        }

        public static byte[] GetCertificatePublicKeyBytes(X509Certificate2 certificate)
        {
            return certificate.Export(X509ContentType.Cert);
        }

        public static void DeleteCertificate()
        {
            if (File.Exists(CertPath)) File.Delete(CertPath);
            if (File.Exists(CertPasswordPath)) File.Delete(CertPasswordPath);

            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                foreach (var cert in store.Certificates)
                {
                    if (cert.Subject.Contains("Trap-Panel Server"))
                    {
                        store.Remove(cert);
                    }
                }
            }
            catch { }
        }
    }
}
