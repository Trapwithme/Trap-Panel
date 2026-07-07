using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class WebcamUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BgCol => C("BackgroundColor");
        private Color SurfCol => C("SurfaceColor");
        private Color SurfLCol => C("SurfaceLightColor");
        private Color BrdCol => C("BorderColor");
        private Color TxtCol => C("TextPrimaryColor");
        private Color DimCol => C("TextSecondaryColor");
        private Color OkCol => C("SuccessColor");
        private Color OkHov => C("SuccessHoverColor");
        private Color DanCol => C("DangerColor");
        private Color DanHov => C("DangerHoverColor");
        private Color DisCol => C("ButtonBgColor");
        private Color ButtonBorderClr => C("ButtonBorderColor");
        private Color ButtonBgClr => C("ButtonBgColor");
        private Color ButtonBgHoverClr => C("ButtonBgHoverColor");

        private SolidColorBrush BgB => B("BackgroundBrush");
        private SolidColorBrush SfB => B("SurfaceBrush");
        private SolidColorBrush TxB => B("TextPrimaryBrush");
        private SolidColorBrush DmB => B("TextSecondaryBrush");
        private SolidColorBrush GnB => B("SuccessBrush");
        private SolidColorBrush BdB => B("BorderBrush");
        private SolidColorBrush DsB => B("ButtonBgBrush");

        private PluginContext _context;
        private PluginHost _host;
        private WebcamPlugin _plugin;

        private readonly Image _img;
        private readonly TextBlock _status;
        private readonly TextBlock _fpsLbl;
        private readonly TextBlock _bpsLbl;
        private readonly ComboBox _devSel;
        private readonly Slider _qSlider;
        private readonly TextBlock _qLbl;
        private readonly Button _startBtn;
        private readonly Button _stopBtn;
        private readonly TextBox _logBox;
        private readonly Border _logBrd;
        private readonly CheckBox _logToggle;

        private bool _streaming;
        private int _rw = 640, _rh = 480;
        private int _fc;
        private DateTime _lastFps = DateTime.UtcNow;
        private int _fpc;
        private long _bpc;
        private readonly List<(int index, string name)> _devices = new();
        private bool _disposed;
        private bool _suppress;
        private int _logLines;

        private volatile BitmapImage _pendingBitmap;
        private volatile int _pendingW, _pendingH;
        private int _pendingBytesAccum;
        private int _pendingFrameCount;
        private bool _renderScheduled;

        public WebcamUI(PluginContext ctx, PluginHost host, WebcamPlugin plugin)
        {
            _context = ctx; _host = host; _plugin = plugin;

            var g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var tb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 3, 4, 3) };
            var tw = new StackPanel { Orientation = Orientation.Horizontal };
            _startBtn = Btn("Start", OkCol, OkHov, null); _startBtn.Click += StartBtn_Click;
            _stopBtn = Btn("Stop", DanCol, DanHov, null); _stopBtn.IsEnabled = false; _stopBtn.Click += StopBtn_Click;
            var refBtn = Btn("Refresh", ButtonBgClr, ButtonBgHoverClr); refBtn.Click += RefreshBtn_Click;
            var svb = Btn("Save", ButtonBgClr, ButtonBgHoverClr); svb.Click += (s, e) => DoSave();
            tw.Children.Add(_startBtn); tw.Children.Add(_stopBtn); tw.Children.Add(Sep());
            tw.Children.Add(refBtn); tw.Children.Add(svb); tw.Children.Add(Sep());
            _logToggle = new CheckBox
            {
                Content = "Log",
                Foreground = DmB,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 2, 4, 2)
            };
            _logToggle.Checked += (s, e) => _logBrd.Visibility = Visibility.Visible;
            _logToggle.Unchecked += (s, e) => _logBrd.Visibility = Visibility.Collapsed;
            tw.Children.Add(_logToggle);
            var clrBtn = Btn("Clear", ButtonBgClr, ButtonBgHoverClr); clrBtn.Click += (s, e) => { _logBox.Text = ""; _logLines = 0; };
            tw.Children.Add(clrBtn);
            tb.Child = tw; Grid.SetRow(tb, 0); g.Children.Add(tb);

            var settBar = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 2, 4, 2) };
            var settWrap = new WrapPanel();
            settWrap.Children.Add(Lbl("Device:"));

            _devSel = new ComboBox
            {
                Width = 260,
                Margin = new Thickness(4, 2, 8, 2),
                Background = BgB,
                Foreground = TxB,
                BorderBrush = BdB,
                FontSize = 12,
                Style = null
            };
            ApplyComboTheme(_devSel);
            settWrap.Children.Add(_devSel);
            settWrap.Children.Add(Lbl("Quality:"));
            _qSlider = new Slider { Width = 80, Minimum = 10, Maximum = 100, Value = 70, TickFrequency = 5, IsSnapToTickEnabled = true, Margin = new Thickness(4, 2, 4, 2), VerticalAlignment = VerticalAlignment.Center };
            _qSlider.ValueChanged += QSlider_ValueChanged;
            settWrap.Children.Add(_qSlider);
            _qLbl = Lbl("70%"); settWrap.Children.Add(_qLbl);
            _fpsLbl = new TextBlock { Text = "0 fps", Foreground = GnB, FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 2, 4, 2) };
            settWrap.Children.Add(_fpsLbl);
            _bpsLbl = new TextBlock { Text = "", Foreground = DmB, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 2, 4, 2) };
            settWrap.Children.Add(_bpsLbl);
            settBar.Child = settWrap; Grid.SetRow(settBar, 1); g.Children.Add(settBar);

            var ib = new Border { Background = BgB, ClipToBounds = true };
            _img = new Image { Stretch = Stretch.Fill };
            RenderOptions.SetBitmapScalingMode(_img, BitmapScalingMode.LowQuality);
            ib.Child = _img; Grid.SetRow(ib, 2); g.Children.Add(ib);

            _logBrd = new Border { Background = new SolidColorBrush(BgCol), BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Height = 140, Visibility = Visibility.Collapsed };
            _logBox = new TextBox { Background = new SolidColorBrush(BgCol), Foreground = new SolidColorBrush(OkCol), BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"), FontSize = 11, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(4), CaretBrush = Brushes.Transparent, AcceptsReturn = true, Style = null };
            _logBrd.Child = _logBox; Grid.SetRow(_logBrd, 3); g.Children.Add(_logBrd);

            var stb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(10, 5, 10, 5) };
            _status = new TextBlock { Text = "Ready", Foreground = DmB, FontSize = 12 };
            stb.Child = _status; Grid.SetRow(stb, 4); g.Children.Add(stb);

            Content = g; Background = BgB; MinWidth = 640; MinHeight = 440;
        }

        private void StartBtn_Click(object sender, RoutedEventArgs e) => DoStart();
        private void StopBtn_Click(object sender, RoutedEventArgs e) => DoStop();
        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => DoRefresh();

        private void QSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_qLbl == null) return;
            _qLbl.Text = ((int)_qSlider.Value).ToString() + "%";
            if (_streaming) SendQuality();
        }

        void Log(string m)
        {
            if (_disposed) return;
            var l = "[" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + m + "\n";
            if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => LogI(l)); else LogI(l);
        }

        void LogI(string l)
        {
            if (_disposed) return;
            _logBox.AppendText(l); _logLines++;
            if (_logLines > 300)
            {
                var t = _logBox.Text;
                int c = 0;
                for (int i = 0; i < 50 && c < t.Length; i++)
                {
                    int n = t.IndexOf('\n', c);
                    if (n < 0) break;
                    c = n + 1;
                }
                if (c > 0) { _logBox.Text = t.Substring(c); _logLines -= 50; }
            }
            _logBox.ScrollToEnd();
        }

        Button Btn(string t, Color bg, Color hv, SolidColorBrush fg = null)
        {
            var nb = new SolidColorBrush(bg); var hb = new SolidColorBrush(hv);
            var bb = new SolidColorBrush(C("ButtonBorderColor")); var db = new SolidColorBrush(C("ButtonBgColor"));
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
            return new Button { Content = t, Template = tp, Foreground = fg ?? TxB, Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        TextBlock Lbl(string t) => new() { Text = t, Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 2, 4, 2) };
        Border Sep() => new() { Width = 1, Background = new SolidColorBrush(C("ButtonBorderColor")), Margin = new Thickness(4, 2, 4, 2) };
        void ApplyComboTheme(ComboBox combo)
        {
            combo.Resources[SystemColors.WindowBrushKey] = BgB;
            combo.Resources[SystemColors.HighlightBrushKey] = new SolidColorBrush(OkCol);
            combo.Resources[SystemColors.HighlightTextBrushKey] = TxB;
            combo.ItemContainerStyle = CreateComboBoxItemStyle();
        }
        Style CreateComboBoxItemStyle()
        {
            var style = new Style(typeof(ComboBoxItem));
            style.Setters.Add(new Setter(Control.BackgroundProperty, BgB));
            style.Setters.Add(new Setter(Control.ForegroundProperty, TxB));
            style.Setters.Add(new Setter(Control.BorderBrushProperty, BdB));
            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(SurfLCol)));
            style.Triggers.Add(hover);
            var selected = new Trigger { Property = ComboBoxItem.IsSelectedProperty, Value = true };
            selected.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(OkCol)));
            selected.Setters.Add(new Setter(Control.ForegroundProperty, TxB));
            style.Triggers.Add(selected);
            return style;
        }

        void St(string t)
        {
            if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => { if (!_disposed) _status.Text = t; });
            else if (!_disposed) _status.Text = t;
        }

        void UpdateButtons(bool streaming)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(() => UpdateButtons(streaming));
                return;
            }
            if (_disposed) return;
            _streaming = streaming;
            _startBtn.IsEnabled = !streaming;
            _stopBtn.IsEnabled = streaming;
        }

        async void DoStart()
        {
            if (_disposed) return;

            _startBtn.IsEnabled = false;
            _stopBtn.IsEnabled = false;

            if (_devSel.SelectedIndex < 0 && _devSel.Items.Count > 0)
                _devSel.SelectedIndex = 0;

            if (_devSel.SelectedIndex >= 0)
            {
                try { await _context.SendToClient(new byte[] { 0x02, (byte)_devSel.SelectedIndex }); }
                catch
                {
                    _startBtn.IsEnabled = true;
                    St("Failed to select device");
                    return;
                }
            }

            SendQuality();

            try { await _context.SendToClient(new byte[] { 0x03 }); }
            catch
            {
                _startBtn.IsEnabled = true;
                St("Failed to send start command");
                return;
            }

            _fc = 0; _fpc = 0; _bpc = 0; _lastFps = DateTime.UtcNow;
            UpdateButtons(true);
            St("Starting webcam...");
        }

        async void DoStop()
        {
            if (_disposed) return;

            _startBtn.IsEnabled = false;
            _stopBtn.IsEnabled = false;

            try { await _context.SendToClient(new byte[] { 0x04 }); }
            catch { }

            UpdateButtons(false);
            St("Stopped.");
        }

        async void DoRefresh()
        {
            if (_disposed) return;
            try { await _context.SendToClient(new byte[] { 0x01 }); }
            catch
            {
                St("Failed to refresh devices");
                return;
            }
            St("Refreshing devices...");
        }

        async void SendQuality()
        {
            if (_disposed) return;
            int q = (int)_qSlider.Value;
            try { await _context.SendToClient(new byte[] { 0x05, (byte)q }); } catch { }
        }

        void DoSave()
        {
            if (_img.Source == null) return;
            var d = new Microsoft.Win32.SaveFileDialog
            {
                FileName = "webcam_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".png",
                Filter = "PNG|*.png|JPEG|*.jpg"
            };
            if (d.ShowDialog() != true) return;
            try
            {
                var s = _img.Source as BitmapSource;
                if (s == null) return;
                BitmapEncoder enc = d.FileName.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase)
                    ? new JpegBitmapEncoder { QualityLevel = 95 }
                    : (BitmapEncoder)new PngBitmapEncoder();
                enc.Frames.Add(BitmapFrame.Create(s));
                using var fs = new FileStream(d.FileName, FileMode.Create);
                enc.Save(fs);
                St("Saved: " + d.FileName);
            }
            catch (Exception ex) { St("Save failed: " + ex.Message); }
        }

        public void HandleServerData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;
            if (data[0] == 0x30) { HandleJpegFrame(data); return; }
            if (data[0] == 0x31) { HandleBmpFrame(data); return; }
            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return;
                try
                {
                    switch (data[0])
                    {
                        case 0x06:
                            HandleDeviceList(data);
                            break;
                        case 0xFD:
                            if (data.Length > 1) Log("[C] " + Encoding.UTF8.GetString(data, 1, data.Length - 1));
                            break;
                        case 0xFE:
                            if (data.Length > 2)
                            {
                                byte ackCmd = data[1];
                                var m = Encoding.UTF8.GetString(data, 2, data.Length - 2);
                                Log("[OK] cmd=0x" + ackCmd.ToString("X2") + " " + m);
                                St(m);
                                if (ackCmd == 0x03) UpdateButtons(true);
                                else if (ackCmd == 0x04) UpdateButtons(false);
                            }
                            break;
                        case 0xFF:
                            if (data.Length > 2)
                            {
                                byte errCmd = data[1];
                                var m = Encoding.UTF8.GetString(data, 2, data.Length - 2);
                                Log("[ERR] cmd=0x" + errCmd.ToString("X2") + " " + m);
                                St("Error: " + m);
                                if (errCmd == 0x03) UpdateButtons(false);
                            }
                            break;
                    }
                }
                catch { }
            });
        }

        void HandleJpegFrame(byte[] d)
        {
            if (d.Length < 11) return;
            int w = d[1] | (d[2] << 8), h = d[3] | (d[4] << 8);
            int jl = d[5] | (d[6] << 8) | (d[7] << 16) | (d[8] << 24);
            if (w <= 0 || w > 7680 || h <= 0 || h > 4320 || jl <= 2 || 9 + jl > d.Length) return;
            if (d[9] != 0xFF || d[10] != 0xD8) return;

            BitmapImage bmp;
            try
            {
                using var ms = new MemoryStream(d, 9, jl, false);
                bmp = new BitmapImage();
                bmp.BeginInit();
                bmp.CacheOption = BitmapCacheOption.OnLoad;
                bmp.StreamSource = ms;
                bmp.EndInit();
                bmp.Freeze();
            }
            catch { return; }

            _pendingBitmap = bmp;
            _pendingW = w;
            _pendingH = h;
            Interlocked.Add(ref _pendingBytesAccum, d.Length);
            Interlocked.Increment(ref _pendingFrameCount);
            ScheduleRender();
        }

        void HandleBmpFrame(byte[] d)
        {
            if (d.Length < 11) return;
            int w = d[1] | (d[2] << 8), h = d[3] | (d[4] << 8);
            int bl = d[5] | (d[6] << 8) | (d[7] << 16) | (d[8] << 24);
            if (w <= 0 || w > 7680 || h <= 0 || h > 4320 || bl <= 14 || 9 + bl > d.Length) return;

            BitmapImage bmp;
            try
            {
                using var ms = new MemoryStream(d, 9, bl, false);
                bmp = new BitmapImage();
                bmp.BeginInit();
                bmp.CacheOption = BitmapCacheOption.OnLoad;
                bmp.StreamSource = ms;
                bmp.EndInit();
                bmp.Freeze();
            }
            catch { return; }

            _pendingBitmap = bmp;
            _pendingW = bmp.PixelWidth;
            _pendingH = bmp.PixelHeight;
            Interlocked.Add(ref _pendingBytesAccum, d.Length);
            Interlocked.Increment(ref _pendingFrameCount);
            ScheduleRender();
        }

        void ScheduleRender()
        {
            if (_renderScheduled) return;
            _renderScheduled = true;
            Dispatcher.BeginInvoke(() =>
            {
                _renderScheduled = false;
                if (_disposed) return;
                var bmp = _pendingBitmap;
                if (bmp == null) return;
                _pendingBitmap = null;

                int frames = Interlocked.Exchange(ref _pendingFrameCount, 0);
                int bytes = Interlocked.Exchange(ref _pendingBytesAccum, 0);

                _img.Source = bmp;
                _rw = _pendingW;
                _rh = _pendingH;
                _fc += frames;
                _fpc += frames;
                _bpc += bytes;

                var now = DateTime.UtcNow;
                double elapsed = (now - _lastFps).TotalSeconds;
                if (elapsed >= 1.0)
                {
                    double fps = _fpc / elapsed;
                    double mbps = (_bpc * 8.0) / (elapsed * 1000000.0);
                    _fpsLbl.Text = ((int)Math.Round(fps)).ToString() + " fps";
                    _bpsLbl.Text = mbps.ToString("F1") + " Mbps  " + _rw.ToString() + "x" + _rh.ToString();
                    _fpc = 0; _bpc = 0; _lastFps = now;
                }
            }, System.Windows.Threading.DispatcherPriority.Render);
        }

        void HandleDeviceList(byte[] d)
        {
            var info = Encoding.UTF8.GetString(d, 1, d.Length - 1);
            _devices.Clear();
            _suppress = true;
            _devSel.Items.Clear();
            foreach (var line in info.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var p = line.Split('|');
                if (p.Length < 2) continue;
                int idx = int.TryParse(p[0], out int i) ? i : 0;
                string name = p[1];
                _devices.Add((idx, name));

                var itemBlock = new TextBlock
                {
                    Text = name,
                    Foreground = TxB,
                    FontSize = 12
                };
                _devSel.Items.Add(itemBlock);
            }
            if (_devSel.Items.Count > 0) _devSel.SelectedIndex = 0;
            _suppress = false;
            St(_devices.Count.ToString() + " webcam(s) found");
            Log("[INFO] " + _devices.Count.ToString() + " device(s) enumerated");
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_streaming)
            {
                _streaming = false;
                try { _context.SendToClient(new byte[] { 0x04 }).Wait(500); } catch { }
            }
        }
    }
}
