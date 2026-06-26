using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Windows;

namespace WpfApp
{
    [SupportedOSPlatform("windows")]
    public partial class CertificateDialog : Window
    {
        private X509Certificate2 _certificate;
        private string _certPassword;

        public X509Certificate2 Certificate => _certificate;

        public CertificateDialog()
        {
            InitializeComponent();
        }

        private void SetCertificate(X509Certificate2 certificate, string password = null)
        {
            _certificate = certificate;
            _certPassword = password ?? GeneratePassword();
            txtDetails.Text = certificate.ToString(true);
            btnSave.IsEnabled = true;
        }

        private void BtnCreate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var cert = CertificateManager.GenerateCertificate("Trap-Panel Server CA");
                SetCertificate(cert);
                AppendLog("Certificate created: RSA 2048-bit, SHA-256, self-signed CA");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Failed to create certificate:\n{ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnImport_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new Microsoft.Win32.OpenFileDialog
            {
                CheckFileExists = true,
                Filter = "PKCS12 Certificate (*.pfx;*.p12)|*.pfx;*.p12",
                Multiselect = false,
                InitialDirectory = AppDomain.CurrentDomain.BaseDirectory
            };

            if (ofd.ShowDialog(this) == true)
            {
                try
                {
                    var passwordDialog = new PasswordPromptDialog();
                    if (passwordDialog.ShowDialog() == true)
                    {
                        var cert = new X509Certificate2(ofd.FileName, passwordDialog.Password,
                            X509KeyStorageFlags.Exportable);
                        SetCertificate(cert, passwordDialog.Password);
                        AppendLog($"Imported certificate from: {ofd.FileName}");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, $"Failed to import certificate:\n{ex.Message}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_certificate == null)
                    throw new InvalidOperationException("No certificate to save.");

                if (!_certificate.HasPrivateKey)
                    throw new InvalidOperationException("Certificate has no private key.");

                CertificateManager.SaveCertificate(_certificate, _certPassword);

                MessageBox.Show(this,
                    "Please backup this certificate. Loss of the certificate means all existing clients will need to be rebuilt.",
                    "Certificate Backup",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Failed to save certificate:\n{ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnExit_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private string GeneratePassword()
        {
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        private void AppendLog(string msg)
        {
            txtDetails.Text += $"\n[INFO] {msg}";
            txtDetails.ScrollToEnd();
        }
    }
}
