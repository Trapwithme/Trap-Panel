using System;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class Socks5UI : UserControl, IDisposable
    {
        private readonly PluginContext _ctx;
        private readonly PluginHost _host;
        private Socks5Server _server;
        private bool _disposed;
        private bool _clientReady;
        private DispatcherTimer _statsTimer;

        private readonly TextBox _portBox;
        private readonly TextBox _bindBox;
        private readonly Button _startBtn;
        private readonly Button _stopBtn;
        private readonly TextBlock _statusText;
        private readonly TextBlock _connCountText;
        private readonly TextBlock _bytesInText;
        private readonly TextBlock _bytesOutText;
        private readonly TextBlock _totalConnsText;
        private readonly TextBox _logBox;
        private readonly Border _indicator;
        private int _logLines;

        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        SolidColorBrush BgDark => B("BackgroundBrush");
        SolidColorBrush BgMed => B("SurfaceBrush");
        SolidColorBrush BgLight => B("SurfaceLightBrush");
        SolidColorBrush BdBrush => B("BorderBrush");
        SolidColorBrush TxBrush => B("TextPrimaryBrush");
        SolidColorBrush DmBrush => B("TextSecondaryBrush");
        SolidColorBrush GnBrush => B("SuccessBrush");
        SolidColorBrush RdBrush => B("DangerBrush");
        SolidColorBrush BlBrush => B("PrimaryBrush");
        SolidColorBrush YlBrush => B("WarningBrush");
        SolidColorBrush DsBrush => B("ButtonBgBrush");
        Color ButtonBorderClr => C("ButtonBorderColor");

        public Socks5UI(PluginContext ctx, PluginHost host)
        {
            _ctx = ctx;
            _host = host;

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // Row 0: Config toolbar
            var configBorder = new Border
            {
                Background = BgMed,
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(12, 8, 12, 8)
            };
            var configPanel = new DockPanel { LastChildFill = false };

            _indicator = new Border
            {
                Width = 10,
                Height = 10,
                CornerRadius = new CornerRadius(5),
                Background = DsBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Waiting for client..."
            };
            _statusText = new TextBlock
            {
                Text = "Waiting for client...",
                Foreground = YlBrush,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            var leftConfig = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            leftConfig.Children.Add(_indicator);
            leftConfig.Children.Add(_statusText);
            leftConfig.Children.Add(Lbl("Bind:"));
            _bindBox = MakeTextBox("127.0.0.1");
            _bindBox.Width = 140;
            leftConfig.Children.Add(_bindBox);
            leftConfig.Children.Add(Lbl("Port:"));
            _portBox = MakeTextBox("1080");
            _portBox.Width = 80;
            leftConfig.Children.Add(_portBox);
            DockPanel.SetDock(leftConfig, Dock.Left);
            configPanel.Children.Add(leftConfig);

            _startBtn = MakeBtn("Start", C("SuccessColor"), C("SuccessHoverColor"));
            _startBtn.Click += (s, e) => StartProxy();
            _stopBtn = MakeBtn("Stop", C("DangerColor"), C("DangerHoverColor"));
            _stopBtn.IsEnabled = false;
            _stopBtn.Click += (s, e) => StopProxy();
            var rightBtns = new StackPanel { Orientation = Orientation.Horizontal };
            rightBtns.Children.Add(_startBtn);
            rightBtns.Children.Add(_stopBtn);
            DockPanel.SetDock(rightBtns, Dock.Right);
            configPanel.Children.Add(rightBtns);

            configBorder.Child = configPanel;
            Grid.SetRow(configBorder, 0);
            root.Children.Add(configBorder);

            // Row 1: Stats
            var statsBorder = new Border
            {
                Background = BgMed,
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 10, 16, 10)
            };
            var statsPanel = new StackPanel { Orientation = Orientation.Horizontal };

            _connCountText = MakeStatValue("0", GnBrush);
            _totalConnsText = MakeStatValue("0", BlBrush);
            _bytesInText = MakeStatValue("0 B", BlBrush);
            _bytesOutText = MakeStatValue("0 B", BlBrush);

            statsPanel.Children.Add(MakeStatGroup("Active", _connCountText));
            statsPanel.Children.Add(MakeStatSep());
            statsPanel.Children.Add(MakeStatGroup("Total", _totalConnsText));
            statsPanel.Children.Add(MakeStatSep());
            statsPanel.Children.Add(MakeStatGroup("↓ Received", _bytesInText));
            statsPanel.Children.Add(MakeStatSep());
            statsPanel.Children.Add(MakeStatGroup("↑ Sent", _bytesOutText));

            statsBorder.Child = statsPanel;
            Grid.SetRow(statsBorder, 1);
            root.Children.Add(statsBorder);

            // Row 3: Log
            var logOuter = new DockPanel();

            var logHeader = new Border
            {
                Background = BgMed,
                Padding = new Thickness(12, 6, 12, 6),
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            var logHeaderPanel = new DockPanel();
            var clearBtn = MakeBtn("Clear", C("SurfaceLightColor"), C("ButtonBgHoverColor"));
            clearBtn.Click += (s, e) => { _logBox.Text = ""; _logLines = 0; };
            DockPanel.SetDock(clearBtn, Dock.Right);
            logHeaderPanel.Children.Add(clearBtn);
            logHeaderPanel.Children.Add(new TextBlock
            {
                Text = "Activity Log",
                Foreground = DmBrush,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            logHeader.Child = logHeaderPanel;
            DockPanel.SetDock(logHeader, Dock.Top);
            logOuter.Children.Add(logHeader);

            _logBox = new TextBox
            {
                Background = BgDark,
                Foreground = GnBrush,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11.5,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(12, 8, 12, 8),
                CaretBrush = Brushes.Transparent,
                AcceptsReturn = true,
                Style = null
            };
            logOuter.Children.Add(_logBox);
            Grid.SetRow(logOuter, 2);
            root.Children.Add(logOuter);

            Content = root;
            Background = BgDark;

            _statsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _statsTimer.Tick += (s, e) => UpdateStats();
            _statsTimer.Start();

            Log("SOCKS5 proxy plugin initialized");
            Log("Waiting for client plugin to connect...");
        }

        private TextBlock MakeStatValue(string text, SolidColorBrush color)
        {
            return new TextBlock
            {
                Text = text,
                Foreground = color,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
        }

        private StackPanel MakeStatGroup(string label, TextBlock value)
        {
            var sp = new StackPanel { Margin = new Thickness(0, 0, 20, 0) };
            sp.Children.Add(new TextBlock
            {
                Text = label,
                Foreground = DmBrush,
                FontSize = 10,
                Margin = new Thickness(0, 0, 0, 2)
            });
            sp.Children.Add(value);
            return sp;
        }

        private Border MakeStatSep()
        {
            return new Border
            {
                Width = 1,
                Background = new SolidColorBrush(C("BorderColor")),
                Margin = new Thickness(12, 2, 20, 2)
            };
        }

        private void UpdateStats()
        {
            if (_disposed || _server == null) return;
            _connCountText.Text = _server.ActiveConnections.ToString();
            _totalConnsText.Text = _server.TotalConnections.ToString();
            _bytesInText.Text = FormatBytes(_server.TotalBytesIn);
            _bytesOutText.Text = FormatBytes(_server.TotalBytesOut);
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        }

        private void StartProxy()
        {
            if (!_clientReady)
            {
                Log("Client plugin not ready yet");
                return;
            }

            if (!int.TryParse(_portBox.Text.Trim(), out int port) || port < 1 || port > 65535)
            {
                Log("Invalid port number");
                return;
            }

            string bind = _bindBox.Text.Trim();
            if (string.IsNullOrEmpty(bind)) bind = "127.0.0.1";

            try
            {
                _server = new Socks5Server(_ctx, s => Log(s), c => { });
                _server.Start(port, bind);
                _startBtn.IsEnabled = false;
                _stopBtn.IsEnabled = true;
                _portBox.IsEnabled = false;
                _bindBox.IsEnabled = false;
                _statusText.Text = $"Running on {bind}:{port}";
                _statusText.Foreground = GnBrush;
                _indicator.Background = GnBrush;
                _indicator.ToolTip = "Proxy running";
            }
            catch (Exception ex)
            {
                Log($"Failed to start: {ex.Message}");
            }
        }

        private void StopProxy()
        {
            _server?.Stop();
            _server?.Dispose();
            _server = null;
            _startBtn.IsEnabled = _clientReady;
            _stopBtn.IsEnabled = false;
            _portBox.IsEnabled = true;
            _bindBox.IsEnabled = true;
            _statusText.Text = "Stopped";
            _statusText.Foreground = RdBrush;
            _indicator.Background = RdBrush;
            _indicator.ToolTip = "Proxy stopped";
        }

        private void Log(string msg)
        {
            if (_disposed) return;
            var line = $"[{DateTime.Now:HH:mm:ss}] {msg}\n";
            if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => LogInternal(line)); return; }
            LogInternal(line);
        }

        private void LogInternal(string line)
        {
            if (_disposed) return;
            _logBox.AppendText(line);
            _logLines++;
            if (_logLines > 500)
            {
                var t = _logBox.Text;
                int cut = 0;
                for (int i = 0; i < 50 && cut < t.Length; i++)
                {
                    int nl = t.IndexOf('\n', cut);
                    if (nl < 0) break;
                    cut = nl + 1;
                }
                if (cut > 0) { _logBox.Text = t.Substring(cut); _logLines -= 50; }
            }
            _logBox.ScrollToEnd();
        }

        public void OnData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;

            switch (data[0])
            {
                case 0x01:
                    Dispatcher.BeginInvoke(() =>
                    {
                        _clientReady = true;
                        _startBtn.IsEnabled = true;
                        _statusText.Text = "Client ready";
                        _statusText.Foreground = BlBrush;
                        _indicator.Background = BlBrush;
                        _indicator.ToolTip = "Client connected";
                        Log("Client plugin connected and ready");
                    });
                    break;
                case 0xFD:
                    if (data.Length > 1)
                        Log(Encoding.UTF8.GetString(data, 1, data.Length - 1));
                    break;
                case 0xFE:
                    if (data.Length > 2)
                        Log($"[ACK] {Encoding.UTF8.GetString(data, 2, data.Length - 2)}");
                    break;
                case 0x11:
                case 0x12:
                case 0x13:
                case 0x14:
                    _server?.HandleClientData(data);
                    break;
            }
        }

        private TextBlock Lbl(string text)
        {
            return new TextBlock
            {
                Text = text,
                Foreground = DmBrush,
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 6, 0)
            };
        }

        private TextBox MakeTextBox(string text)
        {
            return new TextBox
            {
                Text = text,
                Background = BgDark,
                Foreground = TxBrush,
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 7, 10, 7),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                CaretBrush = TxBrush,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 4, 0),
                Style = null
            };
        }

        private Button MakeBtn(string text, Color bg, Color hover, SolidColorBrush fg = null)
        {
            var nb = new SolidColorBrush(bg); var hb = new SolidColorBrush(hover);
            var bb = new SolidColorBrush(ButtonBorderClr); var db = new SolidColorBrush(C("ButtonBgColor"));
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
            var p = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(p);
            var d = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; d.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); d.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tp.Triggers.Add(d);
            return new Button { Content = text, Template = tp, Foreground = fg ?? TxBrush, Cursor = Cursors.Hand, Margin = new Thickness(6, 0, 4, 0), FontSize = 13, FontWeight = FontWeights.SemiBold };
        }

        public void Dispose()
        {
            _disposed = true;
            _statsTimer?.Stop();
            _server?.Dispose();
        }
    }
}
