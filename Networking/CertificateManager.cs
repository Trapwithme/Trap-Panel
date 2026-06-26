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
            using var rsa = RSA.Create(4096);
            var request = new CertificateRequest(
                $"CN={subjectName}",
                rsa,
                HashAlgorithmName.SHA512,
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
                    true));

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
            return new X509Certificate2(CertPath, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        public static byte[] GetCertificatePublicKeyBytes(X509Certificate2 certificate)
        {
            return certificate.Export(X509ContentType.Cert);
        }

        public static void DeleteCertificate()
        {
            if (File.Exists(CertPath)) File.Delete(CertPath);
            if (File.Exists(CertPasswordPath)) File.Delete(CertPasswordPath);
        }
    }
}
