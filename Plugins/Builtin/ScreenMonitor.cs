// File: Plugins/Builtin/ScreenMonitorPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class ScreenMonitorPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, ScreenMonitorUI> _clientUIs = new();

        public string PluginId => "screenmon";
        public string DisplayName => "Screen Monitor";
        public string Version => "6.0.0";
        public string Description => "High-performance remote screen viewer.";

        public Task Initialize(PluginHost host)
        {
            _host = host;
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            foreach (var ui in _clientUIs.Values) ui.Dispose();
            _clientUIs.Clear();
            return Task.CompletedTask;
        }

         public string GetClientCode()
         {
             return @"
 using System;
 using System.Collections.Generic;
 using System.Diagnostics;
 using System.Drawing;
 using System.Drawing.Imaging;
 using System.IO;
 using System.Runtime.InteropServices;
 using System.Text;
 using System.Threading;
 using System.Threading.Tasks;
 
 namespace ClientPlugin_screenmon
 {
     public class Main
     {
         private Func<byte[], Task> _send;
         private CancellationTokenSource _cts;
          private bool _inputEnabled = true;
         private int _screenIndex;
         private volatile bool _streaming;
         private int _quality = 40;
         private int _fps = 60;
         private int _scaleDivisor = 1;
         private MemoryStream _jpegStream;
         private EncoderParameters _encoderParams;
         private ImageCodecInfo _jpegCodec;
         private bool _isRdpSession;
         private string _lastMethod = ""none"";
         private int _okCount, _failCount;
         private int _preferredMethod = -1;
         private volatile int _sending;
         private int _skipCount;
         private Bitmap _reuseBmp;
         private int _reuseW, _reuseH;
         private Graphics _reuseGfx;
         private Bitmap _capBmp;
         private int _capW, _capH;
         private Graphics _cursorGfx;
         private int _cursorW, _cursorH;
          private static readonly Pen _cursorPen = new Pen(Color.Red, 1);
          private byte[] _lastFrameHash;
          private DateTime _lastFullFrame = DateTime.MinValue;
 
         [DllImport(""user32.dll"")]
         static extern uint SendInput(uint n, INPUT[] inputs, int size);
         [DllImport(""user32.dll"")]
         static extern bool SetCursorPos(int x, int y);
        [DllImport(""user32.dll"")]
        static extern short VkKeyScan(char ch);
        [DllImport(""user32.dll"")]
        static extern uint MapVirtualKey(uint uCode, uint uMapType);
        [DllImport(""user32.dll"")]
        static extern bool GetCursorPos(out POINT pt);
         [DllImport(""user32.dll"")]
         static extern int GetSystemMetrics(int idx);
         [DllImport(""user32.dll"")]
         static extern bool SetProcessDPIAware();
         [DllImport(""user32.dll"")]
         static extern IntPtr SetProcessDpiAwarenessContext(IntPtr value);
         [DllImport(""user32.dll"")]
         static extern IntPtr OpenInputDesktop(int dwFlags, bool fInherit, uint dwDesiredAccess);
         [DllImport(""user32.dll"")]
         static extern bool SetThreadDesktop(IntPtr hDesktop);
         [DllImport(""user32.dll"")]
         static extern bool CloseDesktop(IntPtr hDesktop);
         [DllImport(""advapi32.dll"", SetLastError = true)]
         static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
         [DllImport(""kernel32.dll"")]
         static extern IntPtr GetCurrentProcess();
 
         static readonly IntPtr DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = new IntPtr(-4);
 
         static void EnsureDpiAwareness()
         {
             try { if (SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != IntPtr.Zero) return; } catch { }
             try { SetProcessDPIAware(); } catch { }
         }

         static void EnsureInputDesktop()
         {
             try
             {
                 IntPtr hDesk = OpenInputDesktop(0, false, 0x0100);
                 if (hDesk != IntPtr.Zero)
                 {
                     SetThreadDesktop(hDesk);
                     CloseDesktop(hDesk);
                 }
             }
             catch { }
         }
         [DllImport(""user32.dll"")]
         static extern IntPtr GetDC(IntPtr hwnd);
         [DllImport(""user32.dll"")]
         static extern int ReleaseDC(IntPtr hwnd, IntPtr hdc);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int w, int h);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr obj);
        [DllImport(""gdi32.dll"")]
        static extern bool BitBlt(IntPtr dst, int dx, int dy, int dw, int dh, IntPtr src, int sx, int sy, int rop);
        [DllImport(""gdi32.dll"")]
        static extern bool DeleteObject(IntPtr obj);
        [DllImport(""gdi32.dll"")]
        static extern bool DeleteDC(IntPtr hdc);
        [DllImport(""user32.dll"")]
        static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MonitorEnumProc proc, IntPtr data);
        [DllImport(""user32.dll"", CharSet = CharSet.Auto)]
        static extern bool GetMonitorInfo(IntPtr hmon, ref MONITORINFOEX info);

        delegate bool MonitorEnumProc(IntPtr hmon, IntPtr hdc, ref RECT rc, IntPtr data);

        const int SRCCOPY = 0x00CC0020;
        const int CAPTUREBLT = 0x40000000;
        const int INPUT_MOUSE = 0;
        const int INPUT_KEYBOARD = 1;
        const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        const uint MOUSEEVENTF_LEFTUP = 0x0004;
        const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
        const uint MOUSEEVENTF_RIGHTUP = 0x0010;
        const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
        const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
        const uint MOUSEEVENTF_WHEEL = 0x0800;
        const uint KEYEVENTF_KEYUP = 0x0002;
        const uint KEYEVENTF_EXTENDEDKEY = 0x0001;

        [StructLayout(LayoutKind.Sequential)]
        struct POINT { public int X, Y; }
        [StructLayout(LayoutKind.Sequential)]
        struct RECT { public int Left, Top, Right, Bottom; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct MONITORINFOEX
        {
            public int cbSize;
            public RECT rcMonitor, rcWork;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string szDevice;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct INPUT { public int type; public INPUTUNION u; }
        [StructLayout(LayoutKind.Explicit)]
        struct INPUTUNION
        {
            [FieldOffset(0)] public MOUSEINPUT mi;
            [FieldOffset(0)] public KEYBDINPUT ki;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct MOUSEINPUT { public int dx, dy, mouseData; public uint dwFlags, time; public IntPtr dwExtraInfo; }
        [StructLayout(LayoutKind.Sequential)]
        struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }

        class MonInfo { public int Index; public string Device; public Rectangle Bounds; public bool Primary; }
        List<MonInfo> _monitors = new List<MonInfo>();

        async Task LogA(string msg)
        {
            try
            {
                byte[] b = Encoding.UTF8.GetBytes(msg);
                byte[] m = new byte[b.Length + 1];
                m[0] = 0xFD;
                Buffer.BlockCopy(b, 0, m, 1, b.Length);
                await _send(m);
            }
            catch { }
        }

        void DetectRdp()
        {
            try
            {
                string s = Environment.GetEnvironmentVariable(""SESSIONNAME"") ?? """";
                _isRdpSession = s.IndexOf(""RDP"", StringComparison.OrdinalIgnoreCase) >= 0;
                if (!_isRdpSession)
                    try { _isRdpSession = GetSystemMetrics(0x1000) != 0; } catch { }
            }
            catch { _isRdpSession = false; }
        }

        void FindMonitors()
        {
            _monitors.Clear();
            int idx = 0;
            try
            {
                EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (IntPtr hm, IntPtr hdc, ref RECT rc, IntPtr d) =>
                {
                    MONITORINFOEX mi = new MONITORINFOEX();
                    mi.cbSize = Marshal.SizeOf(typeof(MONITORINFOEX));
                    if (GetMonitorInfo(hm, ref mi))
                    {
                        _monitors.Add(new MonInfo
                        {
                            Index = idx++,
                            Device = mi.szDevice,
                            Bounds = new Rectangle(mi.rcMonitor.Left, mi.rcMonitor.Top,
                                mi.rcMonitor.Right - mi.rcMonitor.Left,
                                mi.rcMonitor.Bottom - mi.rcMonitor.Top),
                            Primary = (mi.dwFlags & 1) != 0
                        });
                    }
                    return true;
                }, IntPtr.Zero);
            }
            catch { }
            if (_monitors.Count == 0)
            {
                int w = GetSystemMetrics(78); int h = GetSystemMetrics(79);
                if (w <= 0) w = 1920; if (h <= 0) h = 1080;
                _monitors.Add(new MonInfo { Index = 0, Device = ""DISPLAY"", Bounds = new Rectangle(0, 0, w, h), Primary = true });
            }
        }

        MonInfo GetMon()
        {
            if (_screenIndex >= 0 && _screenIndex < _monitors.Count) return _monitors[_screenIndex];
            return _monitors.Count > 0 ? _monitors[0] : null;
        }

        static ImageCodecInfo GetJpegCodec()
        {
            foreach (var c in ImageCodecInfo.GetImageEncoders())
                if (c.MimeType == ""image/jpeg"") return c;
            return null;
        }

         public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
         {
             _send = sendData;
             _cts = new CancellationTokenSource();
 
             string initError = null;
             try
             {
                 _jpegStream = new MemoryStream(512 * 1024);
                 _encoderParams = new EncoderParameters(1);
                 _encoderParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)_quality);
                 _jpegCodec = GetJpegCodec();
                 EnsureDpiAwareness();
                 DetectRdp();
                 FindMonitors();
                 await LogA(""[INIT] RDP="" + _isRdpSession + "" Mon="" + _monitors.Count);
                 for (int i = 0; i < _monitors.Count; i++)
                      await LogA(""[INIT] Mon"" + i + "": "" + _monitors[i].Bounds.Width + ""x"" + _monitors[i].Bounds.Height + (_monitors[i].Primary ? "" *"" : """"));
                 await SendScreenInfo();
                 try { await LogA(""[INIT] Admin="" + IsAdmin()); } catch { }
             }
             catch (Exception ex) { initError = ex.GetType().Name + "": "" + ex.Message; }
             if (initError != null) { await LogA(""[INIT] FATAL: "" + initError); return; }

            var rxTask = Task.Run(async () =>
            {
                try
                {
                    while (!_cts.IsCancellationRequested)
                    {
                        byte[] data = null;
                        bool fail = false;
                        try { data = await receiveData(); } catch { fail = true; }
                        if (fail || data == null || data.Length == 0) break;
                        string err = null;
                        try { await HandleCmd(data); } catch (Exception ex) { err = ex.Message; }
                        if (err != null) await LogA(""[ERR] "" + err);
                    }
                }
                catch { }
            });

            var txTask = Task.Run(() =>
            {
                try
                {
                    int sent = 0;
                    long lastLog = Tick();
                    while (!_cts.IsCancellationRequested)
                    {
                        if (!_streaming) { Thread.Sleep(50); continue; }

                        long interval = _fps > 0 ? 1000L / _fps : 33L;
                        long before = Tick();

                        // Force a full frame every 2s so the display never gets stuck
                        if ((DateTime.UtcNow - _lastFullFrame).TotalSeconds >= 2)
                            _lastFrameHash = null;

                        try { CaptureAndSendFast(); sent++; }
                        catch { }

                        long elapsed = Tick() - before;
                        long sleep = interval - elapsed;
                        if (sleep > 3)
                            Thread.Sleep((int)(sleep - 1));

                        long now = Tick();
                        if (now - lastLog > 10000)
                        {
                            string msg = ""[TX] "" + sent + ""f/10s m="" + _lastMethod + "" ok="" + _okCount + "" f="" + _failCount;
                            sent = 0; lastLog = now;
                            try { var b = Encoding.UTF8.GetBytes(msg); var m = new byte[b.Length + 1]; m[0] = 0xFD; Buffer.BlockCopy(b, 0, m, 1, b.Length); _send(m).Wait(500); } catch { }
                        }
                    }
                }
                catch { }
            });

            await Task.WhenAny(rxTask, txTask);
            _cts.Cancel();
            DisposeReuse();
            DisposeCap();
            if (_jpegStream != null) { _jpegStream.Dispose(); _jpegStream = null; }
        }

        static long Tick() { return (Stopwatch.GetTimestamp() * 1000L) / Stopwatch.Frequency; }
        static bool IsAdmin()
        {
            try { using (var id = System.Security.Principal.WindowsIdentity.GetCurrent()) { var p = new System.Security.Principal.WindowsPrincipal(id); return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); } }
            catch { return false; }
        }

         void DisposeReuse()
         {
             if (_cursorGfx != null) { _cursorGfx.Dispose(); _cursorGfx = null; }
             if (_reuseGfx != null) { _reuseGfx.Dispose(); _reuseGfx = null; }
             if (_reuseBmp != null) { _reuseBmp.Dispose(); _reuseBmp = null; }
             _reuseW = 0; _reuseH = 0;
             _cursorW = 0; _cursorH = 0;
         }
 
         void DisposeCap()
         {
             if (_capBmp != null) { _capBmp.Dispose(); _capBmp = null; }
             _capW = 0; _capH = 0;
         }

         Bitmap GetReuseBmp(int w, int h)
         {
             if (_reuseBmp != null && _reuseW == w && _reuseH == h) return _reuseBmp;
             DisposeReuse();
             _reuseBmp = new Bitmap(w, h, PixelFormat.Format24bppRgb);
             _reuseW = w; _reuseH = h;
             return _reuseBmp;
         }
 
         Bitmap GetCapBmp(int w, int h)
         {
             if (_capBmp != null && _capW == w && _capH == h) return _capBmp;
             if (_capBmp != null) { try { _capBmp.Dispose(); } catch { } _capBmp = null; }
             _capBmp = new Bitmap(w, h, PixelFormat.Format24bppRgb);
             _capW = w; _capH = h;
             return _capBmp;
         }

        async Task HandleCmd(byte[] data)
        {
            byte cmd = data[0];
            byte[] p = new byte[data.Length - 1];
            if (p.Length > 0) Buffer.BlockCopy(data, 1, p, 0, p.Length);

            switch (cmd)
            {
                case 0x01:
                        if (p.Length >= 4)
                        {
                            _quality = p[0]; _fps = p[1];
                            if (_fps < 1) _fps = 1; if (_fps > 60) _fps = 60;
                            _screenIndex = p[2]; _scaleDivisor = p[3];
                            if (_scaleDivisor < 1) _scaleDivisor = 1; if (_scaleDivisor > 4) _scaleDivisor = 4;
                            _encoderParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)_quality);
                            _okCount = 0; _failCount = 0; _skipCount = 0;
                            _preferredMethod = -1;
                            DetectRdp();
                            FindMonitors();
                            await DetectBestMethod();
                            await SendScreenInfo();
                            _streaming = true;
                            await SendAck(0x01, ""Streaming q="" + _quality + "" fps="" + _fps + "" m="" + _lastMethod);
                        }
                    break;
                case 0x02:
                    _streaming = false;
                    await SendAck(0x02, ""Stopped"");
                    break;
                case 0x03:
                    if (p.Length >= 2) { _quality = p[0]; _fps = p[1]; if (_fps < 1) _fps = 1; if (_fps > 60) _fps = 60; _encoderParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)_quality); }
                    if (p.Length >= 3) { _scaleDivisor = p[2]; if (_scaleDivisor < 1) _scaleDivisor = 1; if (_scaleDivisor > 4) _scaleDivisor = 4; }
                    break;
                case 0x04:
                    if (p.Length >= 1) _screenIndex = p[0];
                    _preferredMethod = -1; DetectRdp(); FindMonitors(); await SendScreenInfo();
                    break;
                case 0x05:
                    try { CaptureAndSendFast(); } catch { }
                    break;
                case 0x06: FindMonitors(); await SendScreenInfo(); break;
                case 0x10: if (_inputEnabled && p.Length >= 8) DoMouseMove(p); break;
                case 0x11: if (_inputEnabled && p.Length >= 9) DoMouseClick(p); break;
                case 0x12: if (_inputEnabled && p.Length >= 4) DoScroll(p); break;
                case 0x13: if (_inputEnabled && p.Length >= 2) DoKey(p); break;
                 case 0x14: if (_inputEnabled && p.Length > 0) DoType(p); break;
                 case 0x15: if (_inputEnabled && p.Length >= 9) DoMouseUp(p); break;
                case 0x20: _inputEnabled = true; await SendAck(0x20, ""Input ON""); break;
                case 0x21: _inputEnabled = false; await SendAck(0x21, ""Input OFF""); break;
            }
        }

         async Task DetectBestMethod()
         {
             EnsureInputDesktop();
             var mon = GetMon();
            if (mon == null) return;
            var r = mon.Bounds;
            await LogA(""[DET] Testing "" + r.Width + ""x"" + r.Height);

            long t0 = Tick();
            Bitmap b0 = CapCopyScreen(r);
            long d0 = Tick() - t0;
            bool ok0 = b0 != null && b0.Width == r.Width;
            await LogA(""[DET] CopyScr: "" + (b0 == null ? ""NULL"" : b0.Width + ""x"" + b0.Height) + "" "" + d0 + ""ms"");
            if (b0 != null) b0.Dispose();

            long t1 = Tick();
            Bitmap b1 = CapBitBlt(r);
            long d1 = Tick() - t1;
            bool ok1 = b1 != null && b1.Width == r.Width;
            await LogA(""[DET] BitBlt: "" + (b1 == null ? ""NULL"" : b1.Width + ""x"" + b1.Height) + "" "" + d1 + ""ms"");
            if (b1 != null) b1.Dispose();

            // Pick fastest working method
            if (ok0 && ok1)
                _preferredMethod = d0 <= d1 ? 0 : 1;
            else if (ok0) _preferredMethod = 0;
            else if (ok1) _preferredMethod = 1;
            else _preferredMethod = 0;

            _lastMethod = _preferredMethod == 0 ? ""CopyScr"" : ""BitBlt"";
            await LogA(""[DET] Selected: "" + _lastMethod);
        }

        bool CapCopyScreenInto(Bitmap bmp, Rectangle r)
        {
            try
            {
                using (var g = Graphics.FromImage(bmp))
                    g.CopyFromScreen(r.X, r.Y, 0, 0, r.Size, CopyPixelOperation.SourceCopy);
                return true;
            }
            catch { return false; }
        }

        Bitmap CapCopyScreen(Rectangle r)
        {
            try
            {
                var bmp = new Bitmap(r.Width, r.Height, PixelFormat.Format24bppRgb);
                using (var g = Graphics.FromImage(bmp))
                    g.CopyFromScreen(r.X, r.Y, 0, 0, r.Size, CopyPixelOperation.SourceCopy);
                return bmp;
            }
            catch { return null; }
        }

        bool CapBitBltInto(Bitmap bmp, Rectangle r)
        {
            IntPtr hs = IntPtr.Zero, hm = IntPtr.Zero, hb = IntPtr.Zero, ho = IntPtr.Zero;
            try
            {
                hs = GetDC(IntPtr.Zero); if (hs == IntPtr.Zero) return false;
                hm = CreateCompatibleDC(hs); if (hm == IntPtr.Zero) return false;
                hb = CreateCompatibleBitmap(hs, r.Width, r.Height); if (hb == IntPtr.Zero) return false;
                ho = SelectObject(hm, hb);
                bool ok = BitBlt(hm, 0, 0, r.Width, r.Height, hs, r.X, r.Y, SRCCOPY | CAPTUREBLT);
                if (!ok) ok = BitBlt(hm, 0, 0, r.Width, r.Height, hs, r.X, r.Y, SRCCOPY);
                SelectObject(hm, ho);
                if (!ok) return false;
                using (var tmp = Image.FromHbitmap(hb))
                using (var g = Graphics.FromImage(bmp))
                {
                    g.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
                    g.DrawImage(tmp, 0, 0, r.Width, r.Height);
                }
                return true;
            }
            catch { return false; }
            finally
            {
                if (hb != IntPtr.Zero) DeleteObject(hb);
                if (hm != IntPtr.Zero) DeleteDC(hm);
                if (hs != IntPtr.Zero) ReleaseDC(IntPtr.Zero, hs);
            }
        }

        Bitmap CapBitBlt(Rectangle r)
        {
            IntPtr hs = IntPtr.Zero, hm = IntPtr.Zero, hb = IntPtr.Zero, ho = IntPtr.Zero;
            try
            {
                hs = GetDC(IntPtr.Zero); if (hs == IntPtr.Zero) return null;
                hm = CreateCompatibleDC(hs); if (hm == IntPtr.Zero) return null;
                hb = CreateCompatibleBitmap(hs, r.Width, r.Height); if (hb == IntPtr.Zero) return null;
                ho = SelectObject(hm, hb);
                bool ok = BitBlt(hm, 0, 0, r.Width, r.Height, hs, r.X, r.Y, SRCCOPY | CAPTUREBLT);
                if (!ok) ok = BitBlt(hm, 0, 0, r.Width, r.Height, hs, r.X, r.Y, SRCCOPY);
                SelectObject(hm, ho);
                return ok ? Image.FromHbitmap(hb) : null;
            }
            catch { return null; }
            finally
            {
                if (hb != IntPtr.Zero) DeleteObject(hb);
                if (hm != IntPtr.Zero) DeleteDC(hm);
                if (hs != IntPtr.Zero) ReleaseDC(IntPtr.Zero, hs);
            }
        }

         void CaptureAndSendFast()
         {
             EnsureInputDesktop();
             var mon = GetMon(); if (mon == null) return;
             var r = mon.Bounds;
             int tw = r.Width, th = r.Height;
             if (_scaleDivisor > 1) { tw = Math.Max(64, tw / _scaleDivisor); th = Math.Max(64, th / _scaleDivisor); }
 
             bool captured = false;
             bool needScale = _scaleDivisor > 1;
 
             if (!needScale)
             {
                 var bmp = GetReuseBmp(tw, th);
                if (_preferredMethod == 0) captured = CapCopyScreenInto(bmp, r);
                else captured = CapBitBltInto(bmp, r);

                if (!captured)
                {
                    if (_preferredMethod == 0) captured = CapBitBltInto(bmp, r);
                    else captured = CapCopyScreenInto(bmp, r);
                }

                if (!captured) { _failCount++; return; }
                 _okCount++;
                 DrawCursorFast(bmp, r);
                 EncodeAndSend(bmp, r.Width, r.Height);
             }
             else
             {
                 var cap = GetCapBmp(r.Width, r.Height);
                 if (_preferredMethod == 0) captured = CapCopyScreenInto(cap, r);
                 else captured = CapBitBltInto(cap, r);
 
                 if (!captured)
                 {
                     if (_preferredMethod == 0) captured = CapBitBltInto(cap, r);
                     else captured = CapCopyScreenInto(cap, r);
                 }
 
                 if (!captured) { _failCount++; return; }
                 _okCount++;
 
                 DrawCursorFast(cap, r);
                 var scaledBmp = GetReuseBmp(tw, th);
                 if (_reuseGfx == null)
                 {
                     _reuseGfx = Graphics.FromImage(scaledBmp);
                     _reuseGfx.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
                     _reuseGfx.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
                     _reuseGfx.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
                     _reuseGfx.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighSpeed;
                 }
                 _reuseGfx.DrawImage(cap, 0, 0, tw, th);
                 EncodeAndSend(scaledBmp, r.Width, r.Height);
             }
         }

         void EncodeAndSend(Bitmap bmp, int realW, int realH)
         {
             _jpegStream.SetLength(0);
             if (_jpegCodec != null) bmp.Save(_jpegStream, _jpegCodec, _encoderParams);
             else bmp.Save(_jpegStream, ImageFormat.Jpeg);
             int jlen = (int)_jpegStream.Length;
             if (jlen <= 0) return;

             byte[] jpegBytes = _jpegStream.GetBuffer();

             // Delta skip: skip sending identical frames
             byte[] hash;
             using (var md5 = System.Security.Cryptography.MD5.Create())
                 hash = md5.ComputeHash(jpegBytes, 0, jlen);
             bool forceFull = (DateTime.UtcNow - _lastFullFrame).TotalSeconds >= 2;
             if (!forceFull && _lastFrameHash != null && HashEqual(_lastFrameHash, hash))
             {
                 Interlocked.Increment(ref _sending);
                 _send(new byte[] { 0x31 }).ContinueWith(_ => Interlocked.Decrement(ref _sending));
                 return;
             }
             _lastFrameHash = hash;
             if (forceFull) _lastFullFrame = DateTime.UtcNow;

             byte[] msg = new byte[9 + jlen];
             msg[0] = 0x30;
             msg[1] = (byte)(realW & 0xFF); msg[2] = (byte)((realW >> 8) & 0xFF);
             msg[3] = (byte)(realH & 0xFF); msg[4] = (byte)((realH >> 8) & 0xFF);
             msg[5] = (byte)(jlen & 0xFF); msg[6] = (byte)((jlen >> 8) & 0xFF);
             msg[7] = (byte)((jlen >> 16) & 0xFF); msg[8] = (byte)((jlen >> 24) & 0xFF);
             Buffer.BlockCopy(jpegBytes, 0, msg, 9, jlen);

             Interlocked.Increment(ref _sending);
             _send(msg).ContinueWith(_ => Interlocked.Decrement(ref _sending));
         }

         static bool HashEqual(byte[] a, byte[] b)
         {
             if (a == null || b == null) return false;
             if (a.Length != b.Length) return false;
             for (int i = 0; i < a.Length; i++)
                 if (a[i] != b[i]) return false;
             return true;
         }

         void DrawCursorFast(Bitmap bmp, Rectangle r)
         {
             try
             {
                 POINT cp; if (!GetCursorPos(out cp)) return;
                 int cx = cp.X - r.X, cy = cp.Y - r.Y;
                 if (cx < 2 || cy < 2 || cx >= bmp.Width - 2 || cy >= bmp.Height - 2) return;
 
                 Graphics g = null;
                 bool dispose = false;
                 try
                 {
                     if (object.ReferenceEquals(bmp, _reuseBmp))
                     {
                         if (_cursorGfx == null || _cursorW != bmp.Width || _cursorH != bmp.Height)
                         {
                             if (_cursorGfx != null) { _cursorGfx.Dispose(); _cursorGfx = null; }
                             _cursorGfx = Graphics.FromImage(bmp);
                             _cursorGfx.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
                             _cursorGfx.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
                             _cursorGfx.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
                             _cursorGfx.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighSpeed;
                             _cursorW = bmp.Width; _cursorH = bmp.Height;
                         }
                         g = _cursorGfx;
                     }
                     else
                     {
                         g = Graphics.FromImage(bmp);
                         dispose = true;
                         g.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
                         g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
                         g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
                         g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighSpeed;
                     }
 
                     int s = 6;
                     g.DrawLine(_cursorPen, cx - s, cy, cx + s, cy);
                     g.DrawLine(_cursorPen, cx, cy - s, cx, cy + s);
                 }
                 finally
                 {
                     if (dispose && g != null) g.Dispose();
                 }
             }
             catch { }
         }

        async Task SendScreenInfo()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < _monitors.Count; i++)
            {
                var m = _monitors[i];
                sb.Append(m.Index).Append(""|"").Append(m.Device).Append(""|"");
                sb.Append(m.Bounds.Width).Append(""|"").Append(m.Bounds.Height).Append(""|"");
                sb.Append(m.Bounds.X).Append(""|"").Append(m.Bounds.Y).Append(""|"");
                sb.Append(m.Primary ? ""1"" : ""0"").Append(""|"");
                sb.Append(_isRdpSession ? ""RDP"" : ""Local"");
                if (i < _monitors.Count - 1) sb.Append(""\n"");
            }
            byte[] ib = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] msg = new byte[ib.Length + 1];
            msg[0] = 0x06;
            Buffer.BlockCopy(ib, 0, msg, 1, ib.Length);
            await _send(msg);
        }

        async Task SendAck(byte c, string m)
        {
            byte[] mb = Encoding.UTF8.GetBytes(m);
            byte[] msg = new byte[mb.Length + 2];
            msg[0] = 0xFE; msg[1] = c;
            Buffer.BlockCopy(mb, 0, msg, 2, mb.Length);
            await _send(msg);
        }

        void DoMouseMove(byte[] p) { int x = BitConverter.ToInt32(p, 0); int y = BitConverter.ToInt32(p, 4); var m = GetMon(); if (m == null) return; SetCursorPos(m.Bounds.X + x, m.Bounds.Y + y); }
        void DoMouseClick(byte[] p)
        {
            int x = BitConverter.ToInt32(p, 0); int y = BitConverter.ToInt32(p, 4); byte btn = p[8];
            var m = GetMon(); if (m == null) return; SetCursorPos(m.Bounds.X + x, m.Bounds.Y + y);
            switch (btn)
            {
                case 0: MI(MOUSEEVENTF_LEFTDOWN); break;
                case 1: MI(MOUSEEVENTF_RIGHTDOWN); break;
                case 2: MI(MOUSEEVENTF_MIDDLEDOWN); break;
                case 3: MI(MOUSEEVENTF_LEFTDOWN); MI(MOUSEEVENTF_LEFTUP); Thread.Sleep(50); MI(MOUSEEVENTF_LEFTDOWN); break;
            }
        }
        void DoMouseUp(byte[] p)
        {
            int x = BitConverter.ToInt32(p, 0); int y = BitConverter.ToInt32(p, 4); byte btn = p[8];
            var m = GetMon(); if (m == null) return; SetCursorPos(m.Bounds.X + x, m.Bounds.Y + y);
            switch (btn)
            {
                case 0: MI(MOUSEEVENTF_LEFTUP); break;
                case 1: MI(MOUSEEVENTF_RIGHTUP); break;
                case 2: MI(MOUSEEVENTF_MIDDLEUP); break;
            }
        }
        void DoScroll(byte[] p) { int d = BitConverter.ToInt32(p, 0); var i = new INPUT[1]; i[0].type = INPUT_MOUSE; i[0].u.mi.dwFlags = MOUSEEVENTF_WHEEL; i[0].u.mi.mouseData = d; SendInput(1, i, Marshal.SizeOf(typeof(INPUT))); }
        void DoKey(byte[] p) { byte vk = p[0], act = p[1]; uint sc = MapVirtualKey(vk, 0); uint f = IsExt(vk) ? KEYEVENTF_EXTENDEDKEY : 0u; switch (act) { case 0: KI(vk, sc, f); KI(vk, sc, f | KEYEVENTF_KEYUP); break; case 1: KI(vk, sc, f); break; case 2: KI(vk, sc, f | KEYEVENTF_KEYUP); break; } }
        void DoType(byte[] p) { string t = Encoding.UTF8.GetString(p); foreach (char c in t) { short vk = VkKeyScan(c); byte lo = (byte)(vk & 0xFF); bool sh = (vk & 0x100) != 0; uint sc = MapVirtualKey(lo, 0); if (sh) KI(0x10, MapVirtualKey(0x10, 0), 0); KI(lo, sc, 0); KI(lo, sc, KEYEVENTF_KEYUP); if (sh) KI(0x10, MapVirtualKey(0x10, 0), KEYEVENTF_KEYUP); } }
         void MI(uint f) { var i = new INPUT[1]; i[0].type = INPUT_MOUSE; i[0].u.mi.dwFlags = f; uint r = SendInput(1, i, Marshal.SizeOf(typeof(INPUT))); if (r == 0) TryLog(""!SendInput mouse="" + f + "" returned 0 (UIPI?)""); }
         void KI(byte vk, uint sc, uint f) { var i = new INPUT[1]; i[0].type = INPUT_KEYBOARD; i[0].u.ki.wVk = vk; i[0].u.ki.wScan = (ushort)sc; i[0].u.ki.dwFlags = f; uint r = SendInput(1, i, Marshal.SizeOf(typeof(INPUT))); if (r == 0) TryLog(""!SendInput key="" + vk + "" sc="" + sc + "" f="" + f + "" returned 0""); }
         void TryLog(string m) { try { var b = Encoding.UTF8.GetBytes(m); var d = new byte[b.Length + 1]; d[0] = 0xFD; Buffer.BlockCopy(b, 0, d, 1, b.Length); _send(d); } catch { } }
        bool IsExt(byte vk) { return (vk >= 0x21 && vk <= 0x28) || vk == 0x2D || vk == 0x2E || vk == 0x5B || vk == 0x5C; }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            bool isActive = _host.IsPluginActive(context.ClientId, PluginId);
            if (!isActive)
            {
                _ = Task.Run(async () =>
                {
                    try { await _host.StartPluginForClient(context.ClientId, PluginId); }
                    catch { }
                });
            }
            var ui = new ScreenMonitorUI(context, _host, this);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;
            if (_clientUIs.TryGetValue(clientId, out var ui))
                ui.HandleServerData(data);
            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            if (_clientUIs.TryRemove(clientId, out var ui)) ui.Dispose();
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values) ui.Dispose();
            _clientUIs.Clear();
        }
    }

    public class ScreenInfo
    {
        public int Index { get; set; }
        public string Name { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public int X { get; set; }
        public int Y { get; set; }
        public bool IsPrimary { get; set; }
        public string SessionType { get; set; }
        public override string ToString()
        {
            string p = IsPrimary ? " ?" : "";
            string s = !string.IsNullOrEmpty(SessionType) ? $" [{SessionType}]" : "";
            return $"Screen {Index}{p} ({Width}x{Height}){s}";
        }
    }

    [SupportedOSPlatform("windows")]
    public class ScreenMonitorUI : UserControl, IDisposable
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

        private PluginContext _context;
        private PluginHost _host;
        private ScreenMonitorPlugin _plugin;

        private readonly Image _img;
        private readonly TextBlock _status;
        private readonly TextBlock _fpsLbl;
        private readonly TextBlock _bpsLbl;
        private readonly ComboBox _scrSel;
        private readonly Slider _qSlider;
        private readonly Slider _fSlider;
        private readonly ComboBox _scSel;
        private readonly TextBlock _qLbl;
        private readonly TextBlock _fLbl;
        private readonly Button _startBtn;
        private readonly Button _stopBtn;
        private readonly ToggleSwitch _inputTgl;
        private readonly TextBox _typeBox;
        private readonly TextBox _logBox;
        private readonly Border _logBrd;

        private bool _streaming;
        private bool _inputOn;
        private int _rw = 1920, _rh = 1080;
        private int _fc;
        private DateTime _lastFps = DateTime.UtcNow;
        private int _fpc;
        private long _bpc;
        private readonly List<ScreenInfo> _scrs = new();
        private bool _disposed;
        private DateTime _lastMouse = DateTime.MinValue;
        private bool _suppress;
        private int _logLines;

        public ScreenMonitorUI(PluginContext ctx, PluginHost host, ScreenMonitorPlugin plugin)
        {
            _context = ctx; _host = host; _plugin = plugin;

            var g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Toolbar
            var tb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 3, 4, 3) };
            var tw = new StackPanel { Orientation = Orientation.Horizontal };
            _startBtn = Btn("Start", OkCol, OkHov, null); _startBtn.Click += (s, e) => DoStart();
            _stopBtn = Btn("Stop", DanCol, DanHov, null); _stopBtn.IsEnabled = false; _stopBtn.Click += (s, e) => DoStop();
            var ssb = Btn("Shot", ButtonBgClr, ButtonBgHoverClr); ssb.Click += (s, e) => DoShot();
            var svb = Btn("Save", ButtonBgClr, ButtonBgHoverClr); svb.Click += (s, e) => DoSave();
            tw.Children.Add(_startBtn); tw.Children.Add(_stopBtn); tw.Children.Add(Sep());
            tw.Children.Add(ssb); tw.Children.Add(svb); tw.Children.Add(Sep());
            _inputTgl = new ToggleSwitch("Input"); _inputTgl.IsOn = true; _inputTgl.Toggled += DoInput;
            var lt = new ToggleSwitch("Log"); lt.IsOn = false; lt.Toggled += on => _logBrd.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            var cb = Btn("Clear", ButtonBgClr, ButtonBgHoverClr); cb.Click += (s, e) => { _logBox.Text = ""; _logLines = 0; };
            tw.Children.Add(_inputTgl); tw.Children.Add(Sep()); tw.Children.Add(lt); tw.Children.Add(cb);
            tb.Child = tw; Grid.SetRow(tb, 0); g.Children.Add(tb);

            // Settings
            var sb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 2, 4, 2) };
            var sw = new WrapPanel();
            sw.Children.Add(Lbl("Screen:"));
            _scrSel = new ComboBox { Width = 220, Margin = new Thickness(4, 2, 8, 2), Background = BgB, Foreground = TxB, BorderBrush = BdB, FontSize = 12, Style = null };
            ApplyComboTheme(_scrSel);
            _scrSel.SelectionChanged += (s, e) => DoScrChg();
            sw.Children.Add(_scrSel);
            sw.Children.Add(Lbl("Q:"));
            _qSlider = new Slider { Width = 80, Minimum = 10, Maximum = 100, Value = 40, TickFrequency = 5, IsSnapToTickEnabled = true, Margin = new Thickness(4, 2, 4, 2), VerticalAlignment = VerticalAlignment.Center };
            _qSlider.ValueChanged += (s, e) => { _qLbl.Text = $"{(int)_qSlider.Value}%"; if (_streaming) Snd(); };
            sw.Children.Add(_qSlider);
            _qLbl = Lbl("40%"); sw.Children.Add(_qLbl);
            sw.Children.Add(Lbl(" FPS:"));
            _fSlider = new Slider { Width = 80, Minimum = 1, Maximum = 60, Value = 60, TickFrequency = 1, IsSnapToTickEnabled = true, Margin = new Thickness(4, 2, 4, 2), VerticalAlignment = VerticalAlignment.Center };
            _fSlider.ValueChanged += (s, e) => { _fLbl.Text = $"{(int)_fSlider.Value}"; if (_streaming) Snd(); };
            sw.Children.Add(_fSlider);
            _fLbl = Lbl("60"); sw.Children.Add(_fLbl);
            sw.Children.Add(Lbl(" Scale:"));
            _scSel = new ComboBox { Width = 70, Margin = new Thickness(4, 2, 8, 2), Background = BgB, Foreground = TxB, BorderBrush = BdB, FontSize = 12, Style = null };
            ApplyComboTheme(_scSel);
            _scSel.Items.Add("Full"); _scSel.Items.Add("1/2"); _scSel.Items.Add("1/3"); _scSel.Items.Add("1/4");
            _scSel.SelectedIndex = 0; _scSel.SelectionChanged += (s, e) => { if (_streaming) Snd(); };
            sw.Children.Add(_scSel);
            _fpsLbl = new TextBlock { Text = "0 fps", Foreground = GnB, FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 2, 4, 2) };
            sw.Children.Add(_fpsLbl);
            _bpsLbl = new TextBlock { Text = "", Foreground = DmB, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 2, 4, 2) };
            sw.Children.Add(_bpsLbl);
            sb.Child = sw; Grid.SetRow(sb, 1); g.Children.Add(sb);

            // Image
            var ib = new Border { Background = BgB, ClipToBounds = true };
            _img = new Image { Stretch = Stretch.Fill, Cursor = Cursors.None, Focusable = true };
            RenderOptions.SetBitmapScalingMode(_img, BitmapScalingMode.LowQuality);
            _img.MouseMove += ImgMove; _img.MouseDown += ImgDown; _img.MouseUp += ImgUp; _img.MouseWheel += ImgWheel;
            ib.Child = _img; Grid.SetRow(ib, 2); g.Children.Add(ib);

            // Log
            _logBrd = new Border { Background = BgB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Height = 140, Visibility = Visibility.Collapsed };
            _logBox = new TextBox { Background = BgB, Foreground = GnB, BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"), FontSize = 11, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(4), CaretBrush = Brushes.Transparent, AcceptsReturn = true, Style = null };
            _logBrd.Child = _logBox; Grid.SetRow(_logBrd, 3); g.Children.Add(_logBrd);

            // Type
            var tbd = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(6, 4, 6, 4) };
            var tp = new DockPanel();
            var sndb = Btn("Send", PriCol, PriHov, null); sndb.Click += (s, e) => DoType();
            DockPanel.SetDock(sndb, Dock.Right);
            var tl = Lbl("Type: "); DockPanel.SetDock(tl, Dock.Left);
            _typeBox = new TextBox { Background = BgB, Foreground = TxB, BorderBrush = BdB, BorderThickness = new Thickness(1), Padding = new Thickness(6, 4, 6, 4), FontFamily = new FontFamily("Consolas"), FontSize = 13, CaretBrush = TxB, VerticalContentAlignment = VerticalAlignment.Center, Style = null };
            _typeBox.KeyDown += (s, e) => { if (e.Key == Key.Enter) { DoType(); e.Handled = true; } };
            tp.Children.Add(sndb); tp.Children.Add(tl); tp.Children.Add(_typeBox);
            tbd.Child = tp; Grid.SetRow(tbd, 4); g.Children.Add(tbd);

            // Status
            var stb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(10, 5, 10, 5) };
            _status = new TextBlock { Text = "Ready", Foreground = DmB, FontSize = 12 };
            stb.Child = _status; Grid.SetRow(stb, 5); g.Children.Add(stb);

            Content = g; Background = BgB; Focusable = true; MinWidth = 640; MinHeight = 440;
            KeyDown += KD; KeyUp += KU;
        }

        void Log(string m)
        {
            if (_disposed) return;
            var l = $"[{DateTime.Now:HH:mm:ss.fff}] {m}\n";
            if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => LogI(l)); else LogI(l);
        }
        void LogI(string l)
        {
            if (_disposed) return;
            _logBox.AppendText(l); _logLines++;
            if (_logLines > 300) { var t = _logBox.Text; int c = 0; for (int i = 0; i < 50 && c < t.Length; i++) { int n = t.IndexOf('\n', c); if (n < 0) break; c = n + 1; } if (c > 0) { _logBox.Text = t.Substring(c); _logLines -= 50; } }
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
            combo.Resources[SystemColors.HighlightBrushKey] = GnB;
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
        int Sc() { int i = _scSel.SelectedIndex; return i <= 0 ? 1 : i + 1; }
        void St(string t) { if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => _status.Text = t); else _status.Text = t; }

        async void DoStart()
        {
            int q = (int)_qSlider.Value, f = (int)_fSlider.Value, s = Math.Max(0, _scrSel.SelectedIndex), sc = Sc();
            try { await _context.SendToClient(new byte[] { 0x01, (byte)q, (byte)f, (byte)s, (byte)sc }); } catch { return; }
            _streaming = true; _fc = 0; _fpc = 0; _bpc = 0; _lastFps = DateTime.UtcNow;
            _startBtn.IsEnabled = false; _stopBtn.IsEnabled = true;
            St($"Starting q={q}% fps={f} 1/{sc}");
        }
        async void DoStop()
        {
            _streaming = false;
            try { await _context.SendToClient(new byte[] { 0x02 }); } catch { }
            _startBtn.IsEnabled = true; _stopBtn.IsEnabled = false; St("Stopped.");
        }
        async void Snd()
        {
            int q = (int)_qSlider.Value, f = (int)_fSlider.Value, sc = Sc();
            try { await _context.SendToClient(new byte[] { 0x03, (byte)q, (byte)f, (byte)sc }); } catch { }
        }
        async void DoShot() { try { await _context.SendToClient(new byte[] { 0x05 }); } catch { } }
        async void DoScrChg() { if (_suppress || _scrSel.SelectedIndex < 0) return; try { await _context.SendToClient(new byte[] { 0x04, (byte)_scrSel.SelectedIndex }); } catch { } }
        async void DoInput(bool on)
        {
            _inputOn = on;
            try { await _context.SendToClient(new byte[] { on ? (byte)0x20 : (byte)0x21 }); } catch { }
            _img.Cursor = on ? Cursors.None : Cursors.Cross;
        }
        void DoSave()
        {
            if (_img.Source == null) return;
            var d = new Microsoft.Win32.SaveFileDialog { FileName = $"ss_{DateTime.Now:yyyyMMdd_HHmmss}.png", Filter = "PNG|*.png|JPEG|*.jpg" };
            if (d.ShowDialog() != true) return;
            try
            {
                var s = _img.Source as BitmapSource; if (s == null) return;
                BitmapEncoder e = d.FileName.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ? new JpegBitmapEncoder { QualityLevel = 95 } : (BitmapEncoder)new PngBitmapEncoder();
                e.Frames.Add(BitmapFrame.Create(s));
                using var fs = new FileStream(d.FileName, FileMode.Create); e.Save(fs);
            }
            catch { }
        }
        async void DoType()
        {
            if (string.IsNullOrEmpty(_typeBox.Text)) return;
            var b = Encoding.UTF8.GetBytes(_typeBox.Text);
            var m = new byte[b.Length + 1]; m[0] = 0x14; Buffer.BlockCopy(b, 0, m, 1, b.Length);
            try { await _context.SendToClient(m); } catch { }
            _typeBox.Clear();
        }

        (int x, int y)? Coord(MouseEventArgs e)
        {
            if (_img.Source == null) return null;
            var p = e.GetPosition(_img);
            double iw = _img.ActualWidth, ih = _img.ActualHeight;
            if (iw <= 0 || ih <= 0) return null;
            double rx = p.X / iw, ry = p.Y / ih;
            const double eps = 0.02;
            if (rx < -eps || rx > 1 + eps || ry < -eps || ry > 1 + eps) return null;
            int cx = (int)Math.Round(Math.Clamp(rx, 0, 1) * _rw);
            int cy = (int)Math.Round(Math.Clamp(ry, 0, 1) * _rh);
            return (cx, cy);
        }
        async void ImgMove(object s, MouseEventArgs e)
        {
            if (!_inputOn) return;
            var n = DateTime.UtcNow; if ((n - _lastMouse).TotalMilliseconds < 16) return; _lastMouse = n;
            var c = Coord(e); if (c == null) return;
            var m = new byte[9]; m[0] = 0x10;
            Buffer.BlockCopy(BitConverter.GetBytes(c.Value.x), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(c.Value.y), 0, m, 5, 4);
            try { await _context.SendToClient(m); } catch { }
        }
        async void ImgDown(object s, MouseButtonEventArgs e)
        {
            if (!_inputOn) return;
            var c = Coord(e); if (c == null) return;
            byte b = e.ChangedButton switch { MouseButton.Left => (byte)(e.ClickCount >= 2 ? 3 : 0), MouseButton.Right => 1, MouseButton.Middle => 2, _ => 255 };
            if (b == 255) return;
            var m = new byte[10]; m[0] = 0x11;
            Buffer.BlockCopy(BitConverter.GetBytes(c.Value.x), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(c.Value.y), 0, m, 5, 4); m[9] = b;
            try { await _context.SendToClient(m); } catch { }
            _img.Focus();
        }
        async void ImgUp(object s, MouseButtonEventArgs e)
        {
            if (!_inputOn) return;
            var c = Coord(e); if (c == null) return;
            byte b = e.ChangedButton switch { MouseButton.Left => (byte)0, MouseButton.Right => (byte)1, MouseButton.Middle => (byte)2, _ => (byte)255 };
            if (b == 255) return;
            var m = new byte[10]; m[0] = 0x15;
            Buffer.BlockCopy(BitConverter.GetBytes(c.Value.x), 0, m, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(c.Value.y), 0, m, 5, 4); m[9] = b;
            try { await _context.SendToClient(m); } catch { }
        }
        async void ImgWheel(object s, MouseWheelEventArgs e)
        {
            if (!_inputOn) return;
            var m = new byte[5]; m[0] = 0x12; Buffer.BlockCopy(BitConverter.GetBytes(e.Delta), 0, m, 1, 4);
            try { await _context.SendToClient(m); } catch { }
        }
        async void KD(object s, KeyEventArgs e)
        {
            if (!_inputOn) return;
            byte v = (byte)KeyInterop.VirtualKeyFromKey(e.Key); if (v == 0) return;
            try { await _context.SendToClient(new byte[] { 0x13, v, 1 }); } catch { }
            e.Handled = true;
        }
        async void KU(object s, KeyEventArgs e)
        {
            if (!_inputOn) return;
            byte v = (byte)KeyInterop.VirtualKeyFromKey(e.Key); if (v == 0) return;
            try { await _context.SendToClient(new byte[] { 0x13, v, 2 }); } catch { }
            e.Handled = true;
        }

        public void HandleServerData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;
            if (data[0] == 0x30) { HandleFrame(data); return; }
            if (data[0] == 0x31) { HandleSkip(); return; }
            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return;
                try
                {
                    switch (data[0])
                    {
                        case 0x06: HandleScr(data); break;
                        case 0xFD: if (data.Length > 1) Log($"[C] {Encoding.UTF8.GetString(data, 1, data.Length - 1)}"); break;
                        case 0xFE: if (data.Length > 2) { var m = Encoding.UTF8.GetString(data, 2, data.Length - 2); Log($"[OK] {m}"); St(m); } break;
                        case 0xFF: if (data.Length > 2) { var m = Encoding.UTF8.GetString(data, 2, data.Length - 2); Log($"[ERR] {m}"); St($"Error: {m}"); } break;
                    }
                }
                catch { }
            });
        }

        void HandleSkip()
        {
            _fc++; _fpc++;
            var now = DateTime.UtcNow;
            if ((now - _lastFps).TotalSeconds >= 1)
            {
                _fpsLbl.Text = $"{_fpc} fps";
                _bpsLbl.Text = $"{_bpc * 8.0 / 1_000_000:F1} Mbps";
                _fpc = 0; _bpc = 0; _lastFps = now;
            }
        }

        void HandleFrame(byte[] d)
        {
            if (d.Length < 11) return;
            int w = d[1] | (d[2] << 8), h = d[3] | (d[4] << 8);
            int jl = d[5] | (d[6] << 8) | (d[7] << 16) | (d[8] << 24);
            if (w <= 0 || w > 15360 || h <= 0 || h > 8640 || jl <= 2 || 9 + jl > d.Length) return;
            if (d[9] != 0xFF || d[10] != 0xD8) return;

            BitmapImage bmp;
            try
            {
                using var ms = new MemoryStream(d, 9, jl, false);
                bmp = new BitmapImage();
                bmp.BeginInit(); bmp.CacheOption = BitmapCacheOption.OnLoad; bmp.StreamSource = ms; bmp.EndInit(); bmp.Freeze();
            }
            catch { return; }

            int bytes = d.Length, fw = w, fh = h;
            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return;
                _rw = fw; _rh = fh; _img.Source = bmp;
                _fc++; _fpc++; _bpc += bytes;
                var now = DateTime.UtcNow;
                if ((now - _lastFps).TotalSeconds >= 1)
                {
                    _fpsLbl.Text = $"{_fpc} fps";
                    _bpsLbl.Text = $"{_bpc * 8.0 / 1_000_000:F1} Mbps";
                    _fpc = 0; _bpc = 0; _lastFps = now;
                }
            }, System.Windows.Threading.DispatcherPriority.Render);
        }

        void HandleScr(byte[] d)
        {
            var info = Encoding.UTF8.GetString(d, 1, d.Length - 1);
            _scrs.Clear(); _suppress = true; _scrSel.Items.Clear();
            int pi = 0;
            foreach (var line in info.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var p = line.Split('|'); if (p.Length < 7) continue;
                var s = new ScreenInfo
                {
                    Index = int.TryParse(p[0], out int i) ? i : 0,
                    Name = p[1],
                    Width = int.TryParse(p[2], out int sw) ? sw : 0,
                    Height = int.TryParse(p[3], out int sh) ? sh : 0,
                    X = int.TryParse(p[4], out int sx) ? sx : 0,
                    Y = int.TryParse(p[5], out int sy) ? sy : 0,
                    IsPrimary = p[6] == "1",
                    SessionType = p.Length > 7 ? p[7] : ""
                };
                _scrs.Add(s); _scrSel.Items.Add(s.ToString());
                if (s.IsPrimary) pi = s.Index;
            }
            if (_scrSel.Items.Count > 0) _scrSel.SelectedIndex = pi < _scrSel.Items.Count ? pi : 0;
            _suppress = false;
            if (_scrs.Count > 0) { var pr = _scrs.FirstOrDefault(x => x.IsPrimary) ?? _scrs[0]; _rw = pr.Width; _rh = pr.Height; }
            St($"{_scrs.Count} screen(s) {_rw}x{_rh}" + (_scrs.Any(x => x.SessionType == "RDP") ? " [RDP]" : ""));
        }

        public void Dispose()
        {
            _disposed = true;
            if (_streaming) try { _context.SendToClient(new byte[] { 0x02 }).Wait(500); } catch { }
        }
    }

    [SupportedOSPlatform("windows")]
    public class ToggleSwitch : Border
    {
        private bool _isOn;
        private readonly Border _thumb, _track;
        public event Action<bool> Toggled;
        public bool IsOn { get => _isOn; set { _isOn = value; Upd(); } }

        public ToggleSwitch(string label)
        {
            Margin = new Thickness(4, 2, 4, 2); Cursor = Cursors.Hand;
            Background = new SolidColorBrush(Tc("SurfaceLightColor"));
            CornerRadius = new CornerRadius(5); Padding = new Thickness(10, 4, 10, 4);
            BorderBrush = new SolidColorBrush(Tc("BorderColor")); BorderThickness = new Thickness(1);
            var p = new StackPanel { Orientation = Orientation.Horizontal };
            p.Children.Add(new TextBlock { Text = label, Foreground = new SolidColorBrush(Tc("TextPrimaryColor")), FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            _track = new Border { Width = 36, Height = 18, CornerRadius = new CornerRadius(9), Background = new SolidColorBrush(Tc("ButtonBgColor")), VerticalAlignment = VerticalAlignment.Center };
            _thumb = new Border { Width = 14, Height = 14, CornerRadius = new CornerRadius(7), Background = new SolidColorBrush(Tc("TextPrimaryColor")), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(2, 0, 0, 0) };
            _track.Child = _thumb; p.Children.Add(_track); Child = p;
            MouseLeftButtonDown += (s, e) => { _isOn = !_isOn; Upd(); Toggled?.Invoke(_isOn); };
            Upd();
        }

        void Upd()
        {
            if (_isOn) { _thumb.HorizontalAlignment = HorizontalAlignment.Right; _thumb.Margin = new Thickness(0, 0, 2, 0); _track.Background = new SolidColorBrush(Tc("SuccessColor")); }
            else { _thumb.HorizontalAlignment = HorizontalAlignment.Left; _thumb.Margin = new Thickness(2, 0, 0, 0); _track.Background = new SolidColorBrush(Tc("ButtonBgColor")); }
        }
        private static Color Tc(string key) => (Color)Application.Current.Resources[key];
    }
}
