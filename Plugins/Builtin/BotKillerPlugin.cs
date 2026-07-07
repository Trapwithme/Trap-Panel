// File: BotKillerPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class BotKillerPlugin : IServerPlugin, IMultiClientPlugin
    {
        private PluginHost _host;
        private BotKillerPluginUI _sharedUI;
        private readonly object _uiLock = new object();
        private readonly ConcurrentDictionary<string, PluginContext> _managedClients = new();

        public string PluginId => "botkiller";
        public string DisplayName => "Bot Killer";
        public string Version => "4.0.0";
        public string Description => "Automated malware detection and removal with multi-client batch control. Self-aware - will never kill its own process chain.";

        private const byte OP_START_SCAN = 0x01;
        private const byte OP_KILL_PROCESS = 0x02;
        private const byte OP_REMOVE_THREAT = 0x03;
        private const byte OP_GET_PROCESS_LIST = 0x05;
        private const byte OP_GET_STARTUP_LIST = 0x06;
        private const byte OP_GET_SCHEDULED_TASKS = 0x07;
        private const byte OP_REMOVE_STARTUP_ENTRY = 0x08;
        private const byte OP_QUARANTINE_FILE = 0x09;
        private const byte OP_CHECK_HOSTS_FILE = 0x0A;
        private const byte OP_REPAIR_HOSTS_FILE = 0x0B;
        private const byte OP_CHECK_DNS = 0x0C;
        private const byte OP_SCAN_SERVICES = 0x0D;
        private const byte OP_STOP_SERVICE = 0x0E;
        private const byte OP_DELETE_SERVICE = 0x0F;
        private const byte OP_DELETE_FILE = 0x10;
        private const byte OP_KILL_AND_DELETE = 0x11;
        private const byte OP_FULL_REMOVE = 0x12;
        private const byte OP_AUTO_CLEAN = 0x13;
        private const byte OP_ANTI_ANALYSIS = 0x04;

        private const byte CLIENT_READY = 0xFE;
        private const byte CLIENT_ACK = 0x01;
        private const byte CLIENT_ERROR = 0x02;
        private const byte CLIENT_SCAN_RESULT = 0x10;
        private const byte CLIENT_PROCESS_LIST = 0x11;
        private const byte CLIENT_STARTUP_LIST = 0x12;
        private const byte CLIENT_THREAT_REMOVED = 0x13;
        private const byte CLIENT_SCAN_PROGRESS = 0x14;
        private const byte CLIENT_SCAN_COMPLETE = 0x15;
        private const byte CLIENT_SCHEDULED_TASKS = 0x16;
        private const byte CLIENT_HOSTS_FILE_RESULT = 0x17;
        private const byte CLIENT_DNS_RESULT = 0x18;
        private const byte CLIENT_SERVICE_LIST = 0x19;
        private const byte CLIENT_FILE_DELETED = 0x1A;
        private const byte CLIENT_AUTO_CLEAN_RESULT = 0x1B;
        private const byte CLIENT_ANTI_ANALYSIS_RESULT = 0x1C;

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _host.Log("[BOTKILLER] Plugin initialized v4.0 - self-aware multi-client");
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            lock (_uiLock) { _sharedUI?.Dispose(); _sharedUI = null; }
            _managedClients.Clear();
            return Task.CompletedTask;
        }

        public UserControl CreateSharedUI()
        {
            lock (_uiLock)
            {
                if (_sharedUI == null)
                    _sharedUI = new BotKillerPluginUI(this);
                return _sharedUI;
            }
        }

        public void AddClient(string clientId, PluginContext context)
        {
            _managedClients[clientId] = context;
            lock (_uiLock) { _sharedUI?.AddClient(clientId, context); }
        }

        public void RemoveClient(string clientId)
        {
            _managedClients.TryRemove(clientId, out _);
            lock (_uiLock) { _sharedUI?.RemoveClient(clientId); }
            _host.Log("[BOTKILLER] " + clientId + " disconnected");
        }

        public void RemoveAllClients()
        {
            var ids = _managedClients.Keys.ToList();
            foreach (var id in ids) RemoveClient(id);
        }

        public List<string> GetManagedClientIds() => _managedClients.Keys.ToList();

        public UserControl CreateUI(PluginContext context)
        {
            AddClient(context.ClientId, context);
            return CreateSharedUI();
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;
            BotKillerPluginUI ui;
            lock (_uiLock) { ui = _sharedUI; }
            if (ui == null) return Task.CompletedTask;

            byte ind = data[0];
            byte[] payload = data.Length > 1 ? data.AsSpan(1).ToArray() : Array.Empty<byte>();

            switch (ind)
            {
                case CLIENT_READY:
                    ui.OnClientReady(clientId);
                    _host.Log("[BOTKILLER] " + clientId + " ready");
                    break;
                case CLIENT_ACK:
                    if (data.Length >= 2)
                    {
                        string msg = data.Length > 2 ? Encoding.UTF8.GetString(data, 2, data.Length - 2) : "";
                        ui.OnCommandAck(clientId, data[1], msg);
                    }
                    break;
                case CLIENT_ERROR:
                    if (data.Length >= 2)
                    {
                        string err = data.Length > 2 ? Encoding.UTF8.GetString(data, 2, data.Length - 2) : "Unknown";
                        ui.OnCommandError(clientId, data[1], err);
                    }
                    break;
                case CLIENT_SCAN_RESULT:
                    ui.OnScanResult(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_PROCESS_LIST:
                    ui.OnProcessList(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_STARTUP_LIST:
                    ui.OnStartupList(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_THREAT_REMOVED:
                    ui.OnThreatRemoved(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_SCAN_PROGRESS:
                    if (data.Length >= 2) ui.OnScanProgress(clientId, data[1]);
                    break;
                case CLIENT_SCAN_COMPLETE:
                    ui.OnScanComplete(clientId, data.Length >= 2 ? data[1] : 0);
                    break;
                case CLIENT_SCHEDULED_TASKS:
                    ui.OnScheduledTasks(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_HOSTS_FILE_RESULT:
                    ui.OnHostsFileResult(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_DNS_RESULT:
                    ui.OnDNSResult(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_SERVICE_LIST:
                    ui.OnServiceList(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_FILE_DELETED:
                    ui.OnFileDeleted(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_AUTO_CLEAN_RESULT:
                    ui.OnAutoCleanResult(clientId, Encoding.UTF8.GetString(payload));
                    break;
                case CLIENT_ANTI_ANALYSIS_RESULT:
                    ui.OnAntiAnalysisResult(clientId, Encoding.UTF8.GetString(payload));
                    break;
            }
            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            RemoveClient(clientId);
            return Task.CompletedTask;
        }

        public void RequestScan(string cid) => Send(cid, OP_START_SCAN, null);
        public void RequestAutoClean(string cid) => Send(cid, OP_AUTO_CLEAN, null);
        public void RequestAntiAnalysis(string cid) => Send(cid, OP_ANTI_ANALYSIS, null);
        public void RequestKillProcess(string cid, int pid) => Send(cid, OP_KILL_PROCESS, BitConverter.GetBytes(pid));
        public void RequestRemoveThreat(string cid, string path) => Send(cid, OP_REMOVE_THREAT, Encoding.UTF8.GetBytes(path));
        public void RequestProcessList(string cid) => Send(cid, OP_GET_PROCESS_LIST, null);
        public void RequestStartupList(string cid) => Send(cid, OP_GET_STARTUP_LIST, null);
        public void RequestScheduledTasks(string cid) => Send(cid, OP_GET_SCHEDULED_TASKS, null);
        public void RequestRemoveStartupEntry(string cid, string entry) => Send(cid, OP_REMOVE_STARTUP_ENTRY, Encoding.UTF8.GetBytes(entry));
        public void RequestQuarantineFile(string cid, string path) => Send(cid, OP_QUARANTINE_FILE, Encoding.UTF8.GetBytes(path));
        public void RequestCheckHostsFile(string cid) => Send(cid, OP_CHECK_HOSTS_FILE, null);
        public void RequestRepairHostsFile(string cid) => Send(cid, OP_REPAIR_HOSTS_FILE, null);
        public void RequestCheckDNS(string cid) => Send(cid, OP_CHECK_DNS, null);
        public void RequestScanServices(string cid) => Send(cid, OP_SCAN_SERVICES, null);
        public void RequestStopService(string cid, string name) => Send(cid, OP_STOP_SERVICE, Encoding.UTF8.GetBytes(name));
        public void RequestDeleteService(string cid, string name) => Send(cid, OP_DELETE_SERVICE, Encoding.UTF8.GetBytes(name));
        public void RequestDeleteFile(string cid, string path) => Send(cid, OP_DELETE_FILE, Encoding.UTF8.GetBytes(path));

        public void RequestKillAndDelete(string cid, int pid, string path)
        {
            byte[] pidBytes = BitConverter.GetBytes(pid);
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            byte[] payload = new byte[pidBytes.Length + pathBytes.Length];
            Buffer.BlockCopy(pidBytes, 0, payload, 0, pidBytes.Length);
            Buffer.BlockCopy(pathBytes, 0, payload, pidBytes.Length, pathBytes.Length);
            Send(cid, OP_KILL_AND_DELETE, payload);
        }

        public void RequestFullRemove(string cid, string path) => Send(cid, OP_FULL_REMOVE, Encoding.UTF8.GetBytes(path));

        private void Send(string cid, byte op, byte[] payload)
        {
            int len = payload?.Length ?? 0;
            byte[] data = new byte[1 + len];
            data[0] = op;
            if (payload != null) Buffer.BlockCopy(payload, 0, data, 1, len);
            _host.SendPluginDataToClient(cid, PluginId, data);
        }

        public void Dispose()
        {
            lock (_uiLock) { _sharedUI?.Dispose(); _sharedUI = null; }
            _managedClients.Clear();
        }

        public string GetClientCode()
        {
            return """
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ClientPlugin_botkiller
{
    public class Main
    {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

        private Func<byte[], Task> _send;
        private Func<Task<byte[]>> _receive;

        private int _ownPid;
        private string _ownPath = "";
        private string _ownName = "";
        private string _ownDir = "";
        private HashSet<string> _protectedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<int> _protectedPids = new HashSet<int>();
        private HashSet<string> _protectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _protectedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _protectedServiceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static HashSet<string> KnownWindowsProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "svchost","csrss","winlogon","lsass","services","smss","wininit","dwm",
            "explorer","taskhostw","taskhost","sihost","fontdrvhost","ctfmon","conhost",
            "RuntimeBroker","SearchHost","StartMenuExperienceHost","ShellExperienceHost",
            "TextInputHost","SystemSettings","SecurityHealthSystray","SecurityHealthService",
            "MsMpEng","NisSrv","WmiPrvSE","dllhost","audiodg","spoolsv","SearchIndexer",
            "SearchProtocolHost","SearchFilterHost","dasHost","MusNotifyIcon","MusNotification",
            "CompPkgSrv","backgroundTaskHost","WindowsTerminal","OpenWith","smartscreen",
            "TabTip","TabTip32","LockApp","LogonUI","CredentialUIBroker","consent",
            "msiexec","TiWorker","TrustedInstaller","WerFault","wermgr","rundll32",
            "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp",
            "ApplicationFrameHost","SystemSettingsBroker","UserOOBEBroker","SettingSyncHost",
            "OneDrive","PhoneExperienceHost","WidgetService","Widgets"
        };

        private static HashSet<string> KnownMalwareNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "xmrig","xmrig32","xmrig64","xmrig-daemon","xmrig-proxy",
            "cpuminer","cpuminer-multi","cpuminer-avx","cpuminer-opt",
            "ccminer","ccminer-x64","ethminer","sgminer","sgminer-gm",
            "nheqminer","prospector","bfgminer","bfgminer-sf","cgminer",
            "minerd","minerd32","minerd64","easy-miner","nanominer",
            "lolminer","teamredminer","trex","gminer","nbminer","wildrig",
            "kernelminer","polyccminer","fibominer",
            "winring0","winring0x64","inpout32","inpoutx64",
            "asyncrat","asyncrat_server","quasar","quasarclient","dcrat",
            "xenorat","orcusclient","nanocore","netwire","remcos","darkcomet",
            "warzone","njrat","bladabindi","njwrm","darkkomet","pandora",
            "dijikstra","venomrat","drsnake","turkojan","hwait","hvhook",
            "uncoderat","nanocoreclient","orcust","xworm","formatloader",
            "agenttesla","snakekeylogger","hawkeye","hawkrat",
            "recl,foxrat","cyberrat","bitrat","levelrat",
            "nano","spynote","sublime","prorat","poison","poisonivy"
        };

        private static HashSet<string> KnownMinerNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "xmrig","xmrig32","xmrig64","cpuminer","cpuminer-multi","ccminer",
            "ethminer","sgminer","nheqminer","bfgminer","cgminer","minerd",
            "nanominer","lolminer","teamredminer","trex","gminer","nbminer",
            "wildrig","kernelminer"
        };

        private static HashSet<string> KnownMalwareRegistryKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"Software\Microsoft\Windows NT\CurrentVersion\Windows\Load",
            @"Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
            @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
            @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
            @"Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableShellExecuteHooks",
            @"SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell",
            @"Software\Microsoft\Active Setup\Installed Components",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        };

        private static HashSet<string> KnownMalwareMutexes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "nmcl","nmcl_crypt","nmcl_alive","asyncrat","quasar","dcrat",
            "xenorat","nanocore","netwire","remcos","darkcomet"
        };

        private static string _windowsDir = "";
        private static string _programFiles = "";
        private static string _programFilesX86 = "";
        private static string _system32 = "";
        private static string _sysWow64 = "";

        private static string[] RegistryRunPaths = new string[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\RunServices",
            @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
        };

        private static string[] RegistryRunPathsMachine = new string[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        };

        public async Task Run(Func<byte[], Task> send, Func<Task<byte[]>> receive)
        {
            _send = send;
            _receive = receive;

            InitSelfAwareness();
            await _send(new byte[] { 0xFE });

            while (true)
            {
                byte[] data = await _receive();
                if (data == null || data.Length == 0) break;

                byte opcode = data[0];
                byte[] payload = data.Length > 1 ? data.Skip(1).ToArray() : null;

                try
                {
                    switch (opcode)
                    {
                        case 0x01: await PerformScan(); break;
                        case 0x02: await KillProcess(payload); break;
                        case 0x03: await RemoveThreat(payload); break;
                        case 0x05: await SendProcessList(); break;
                        case 0x06: await SendStartupList(); break;
                        case 0x07: await SendScheduledTasks(); break;
                        case 0x08: await RemoveStartupEntry(payload); break;
                        case 0x09: await QuarantineFile(payload); break;
                        case 0x0A: await CheckHostsFile(); break;
                        case 0x0B: await RepairHostsFile(); break;
                        case 0x0C: await CheckDNS(); break;
                        case 0x0D: await ScanServices(); break;
                        case 0x0E: await StopService(payload); break;
                        case 0x0F: await DeleteService(payload); break;
                        case 0x10: await DeleteFile(payload); break;
                        case 0x11: await KillAndDelete(payload); break;
                        case 0x12: await FullRemove(payload); break;
                        case 0x13: await AutoClean(); break;
                        case 0x04: await RunAntiAnalysis(); break;
                        default: await SendAck(opcode); break;
                    }
                }
                catch (Exception ex)
                {
                    await SendError(opcode, ex.Message);
                }
            }
        }

        private void InitSelfAwareness()
        {
            _windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            _programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            _programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            _system32 = Environment.SystemDirectory;
            _sysWow64 = Path.Combine(_windowsDir, "SysWOW64");

            Process currentProc = Process.GetCurrentProcess();
            _ownPid = currentProc.Id;
            _ownName = currentProc.ProcessName;
            _protectedPids.Add(_ownPid);
            _protectedNames.Add(_ownName);

            try
            {
                if (currentProc.MainModule != null)
                {
                    _ownPath = currentProc.MainModule.FileName;
                    _ownDir = Path.GetDirectoryName(_ownPath) ?? "";
                    _protectedPaths.Add(_ownPath);
                    if (!string.IsNullOrEmpty(_ownDir)) _protectedDirs.Add(_ownDir);
                }
            }
            catch { }

            WalkParentChain(_ownPid, 0);
            DiscoverOwnServiceName();
            DiscoverOwnStartupEntries();

            _protectedNames.Add("System");
            _protectedNames.Add("Idle");
            _protectedNames.Add("Registry");
            _protectedNames.Add("Memory Compression");
            _protectedNames.Add("vmmem");
        }

        private void WalkParentChain(int pid, int depth)
        {
            if (depth > 20) return;
            try
            {
                int parentId = GetParentPid(pid);
                if (parentId <= 0 || parentId == pid) return;
                _protectedPids.Add(parentId);
                try
                {
                    Process parent = Process.GetProcessById(parentId);
                    _protectedNames.Add(parent.ProcessName);
                    try
                    {
                        if (parent.MainModule != null)
                        {
                            string pp = parent.MainModule.FileName;
                            if (!string.IsNullOrEmpty(pp))
                            {
                                _protectedPaths.Add(pp);
                                string dir = Path.GetDirectoryName(pp);
                                if (!string.IsNullOrEmpty(dir)) _protectedDirs.Add(dir);
                            }
                        }
                    }
                    catch { }
                    WalkParentChain(parentId, depth + 1);
                }
                catch { }
            }
            catch { }
        }

        private void DiscoverOwnServiceName()
        {
            try
            {
                RegistryKey servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
                if (servicesKey == null) return;
                foreach (string svcName in servicesKey.GetSubKeyNames())
                {
                    try
                    {
                        RegistryKey svcKey = servicesKey.OpenSubKey(svcName, false);
                        if (svcKey == null) continue;
                        object imgObj = svcKey.GetValue("ImagePath");
                        svcKey.Close();
                        if (imgObj == null) continue;
                        string imagePath = imgObj.ToString();
                        if (string.IsNullOrEmpty(_ownPath)) continue;
                        if (imagePath.IndexOf(_ownPath, StringComparison.OrdinalIgnoreCase) >= 0 ||
                            imagePath.IndexOf(_ownName, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            _protectedServiceNames.Add(svcName);
                        }
                    }
                    catch { }
                }
                servicesKey.Close();
            }
            catch { }
        }

        private void DiscoverOwnStartupEntries()
        {
            foreach (string regPath in RegistryRunPaths)
                MarkOwnStartupInKey(Registry.CurrentUser, regPath);
            foreach (string regPath in RegistryRunPathsMachine)
                MarkOwnStartupInKey(Registry.LocalMachine, regPath);
        }

        private void MarkOwnStartupInKey(RegistryKey root, string regPath)
        {
            try
            {
                RegistryKey key = root.OpenSubKey(regPath, false);
                if (key == null) return;
                foreach (string name in key.GetValueNames())
                {
                    object valObj = key.GetValue(name);
                    string val = valObj != null ? valObj.ToString() : "";
                    if (!string.IsNullOrEmpty(_ownPath) && val.IndexOf(_ownPath, StringComparison.OrdinalIgnoreCase) >= 0)
                        _protectedPaths.Add(val);
                    if (!string.IsNullOrEmpty(_ownName) && val.IndexOf(_ownName, StringComparison.OrdinalIgnoreCase) >= 0)
                        _protectedPaths.Add(val);
                }
                key.Close();
            }
            catch { }
        }

        private int GetParentPid(int pid)
        {
            try
            {
                System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = " + pid.ToString());
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    int ppid = Convert.ToInt32(obj["ParentProcessId"]);
                    obj.Dispose();
                    searcher.Dispose();
                    return ppid;
                }
                searcher.Dispose();
            }
            catch { }
            return -1;
        }

        private bool IsProtectedProcess(Process p)
        {
            if (_protectedPids.Contains(p.Id)) return true;
            if (_protectedNames.Contains(p.ProcessName)) return true;
            try
            {
                if (p.MainModule != null)
                {
                    string path = p.MainModule.FileName;
                    if (!string.IsNullOrEmpty(path))
                    {
                        if (_protectedPaths.Contains(path)) return true;
                        string dir = Path.GetDirectoryName(path);
                        if (!string.IsNullOrEmpty(dir) && _protectedDirs.Contains(dir)) return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private bool IsProtectedPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            if (_protectedPaths.Contains(path)) return true;
            if (!string.IsNullOrEmpty(_ownPath) && path.Equals(_ownPath, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(_ownName) && Path.GetFileNameWithoutExtension(path).Equals(_ownName, StringComparison.OrdinalIgnoreCase)) return true;
            string dir = null;
            try { dir = Path.GetDirectoryName(path); } catch { }
            if (!string.IsNullOrEmpty(dir) && _protectedDirs.Contains(dir)) return true;
            return false;
        }

        private bool IsProtectedServiceName(string name)
        {
            return _protectedServiceNames.Contains(name);
        }

        private bool IsLegitimateWindowsProcess(Process p, string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            string name = Path.GetFileNameWithoutExtension(filePath);
            if (KnownWindowsProcesses.Contains(name))
            {
                if (IsInLegitimateDirectory(filePath)) return true;
            }
            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                string subject = cert.Subject;
                if (subject != null && (
                    subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    subject.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    if (IsInLegitimateDirectory(filePath)) return true;
                }
            }
            catch { }
            return false;
        }

        private bool IsInLegitimateDirectory(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            if (!string.IsNullOrEmpty(_system32) && filePath.StartsWith(_system32, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(_sysWow64) && filePath.StartsWith(_sysWow64, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(_windowsDir) && filePath.StartsWith(_windowsDir, StringComparison.OrdinalIgnoreCase))
            {
                string rel = filePath.Substring(_windowsDir.Length).TrimStart('\\');
                string[] legitSubs = new[] { "System32", "SysWOW64", "WinSxS", "SystemApps", "ImmersiveControlPanel" };
                foreach (string sub in legitSubs)
                {
                    if (rel.StartsWith(sub, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            if (!string.IsNullOrEmpty(_programFiles) && filePath.StartsWith(_programFiles, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(_programFilesX86) && filePath.StartsWith(_programFilesX86, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private bool IsSuspiciousLocation(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            if (IsInLegitimateDirectory(filePath)) return false;

            string temp = Path.GetTempPath();
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string downloads = Path.Combine(userProfile, "Downloads");
            string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);

            if (!string.IsNullOrEmpty(temp) && filePath.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(startup) && filePath.StartsWith(startup, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(commonStartup) && filePath.StartsWith(commonStartup, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(desktop) && filePath.StartsWith(desktop, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(downloads) && filePath.StartsWith(downloads, StringComparison.OrdinalIgnoreCase)) return true;

            if (!string.IsNullOrEmpty(appData) && filePath.StartsWith(appData, StringComparison.OrdinalIgnoreCase))
            {
                string rel = filePath.Substring(appData.Length).TrimStart('\\');
                if (!rel.Contains('\\')) return true;
                string firstDir = rel.Split('\\')[0];
                string[] legitimateAppDirs = new[] { "Microsoft", "Mozilla", "Google", "Adobe", "Apple", "Intel", "NVIDIA", "Steam", "discord", "Code", "VSCode", "JetBrains", "NuGet", "npm", "Python", "Local" };
                bool knownDir = false;
                foreach (string ld in legitimateAppDirs)
                {
                    if (firstDir.Equals(ld, StringComparison.OrdinalIgnoreCase)) { knownDir = true; break; }
                }
                if (!knownDir) return true;
            }

            if (!string.IsNullOrEmpty(commonAppData) && filePath.StartsWith(commonAppData, StringComparison.OrdinalIgnoreCase))
            {
                string ext = Path.GetExtension(filePath).ToLower();
                if (ext == ".exe" || ext == ".scr" || ext == ".bat" || ext == ".cmd" || ext == ".vbs" || ext == ".ps1")
                {
                    string rel = filePath.Substring(commonAppData.Length).TrimStart('\\');
                    if (!rel.Contains('\\')) return true;
                }
            }

            string root = Path.GetPathRoot(filePath);
            if (!string.IsNullOrEmpty(root))
            {
                string dir = Path.GetDirectoryName(filePath);
                if (dir != null && dir.Equals(root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        private bool IsHiddenProcess(Process p)
        {
            try
            {
                if (p.MainWindowHandle == IntPtr.Zero) return true;
                if (!IsWindowVisible(p.MainWindowHandle)) return true;
            }
            catch { return true; }
            return false;
        }

        private string SafeGetProcessPath(Process p)
        {
            try { if (p.MainModule != null) return p.MainModule.FileName; } catch { }
            return null;
        }

        private bool HasValidSignature(string filePath)
        {
            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                X509Certificate2 cert2 = new X509Certificate2(cert);
                X509Chain chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                bool valid = chain.Build(cert2);
                chain.Dispose(); cert2.Dispose();
                return valid;
            }
            catch { return false; }
        }

        private bool HasRegistryPersistence(string filePath)
        {
            foreach (string regPath in RegistryRunPaths)
            {
                if (CheckRegForPath(Registry.CurrentUser, regPath, filePath)) return true;
            }
            foreach (string regPath in RegistryRunPathsMachine)
            {
                if (CheckRegForPath(Registry.LocalMachine, regPath, filePath)) return true;
            }
            return false;
        }

        private bool CheckRegForPath(RegistryKey root, string regPath, string filePath)
        {
            try
            {
                RegistryKey key = root.OpenSubKey(regPath, false);
                if (key == null) return false;
                foreach (string name in key.GetValueNames())
                {
                    object valObj = key.GetValue(name);
                    string val = valObj != null ? valObj.ToString() : "";
                    if (val.IndexOf(filePath, StringComparison.OrdinalIgnoreCase) >= 0)
                    { key.Close(); return true; }
                }
                key.Close();
            }
            catch { }
            return false;
        }

        private string GetProcessCommandLine(int pid)
        {
            try
            {
                System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + pid.ToString());
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    object cmd = obj["CommandLine"];
                    obj.Dispose();
                    searcher.Dispose();
                    return cmd != null ? cmd.ToString() : "";
                }
                searcher.Dispose();
            }
            catch { }
            return "";
        }

        private Dictionary<string, object> ScanProcessCommandLine(int pid, string filePath)
        {
            string cmd = GetProcessCommandLine(pid);
            if (string.IsNullOrEmpty(cmd)) return null;

            List<string> reasons = new List<string>();
            int level = 0;
            string cmdLower = cmd.ToLower();

            if (cmdLower.Contains("--donate-level=") || cmdLower.Contains("--donate-level "))
            {
                level += 8;
                reasons.Add("MINER: process has --donate-level flag");
            }
            if (cmdLower.Contains("--pool=") || cmdLower.Contains("--pool "))
            {
                level += 7;
                reasons.Add("MINER: process has --pool flag (mining pool)");
            }
            if (cmdLower.Contains("--algo=") || cmdLower.Contains("--algo "))
            {
                level += 5;
                reasons.Add("MINER: process has --algo flag");
            }
            if (cmdLower.Contains("--wallet=") || cmdLower.Contains("--wallet "))
            {
                level += 8;
                reasons.Add("MINER: process has --wallet (crypto wallet address)");
            }
            if (cmdLower.Contains("--rig-id="))
            {
                level += 4;
                reasons.Add("MINER: process has --rig-id flag");
            }

            if (cmdLower.Contains("-encodedcommand") || cmdLower.Contains("-e ") && cmdLower.Contains("base64") || cmdLower.Contains("iex(") || cmdLower.Contains("invoke-expression") || cmdLower.Contains("invoke-webrequest") || cmdLower.Contains("net.webclient"))
            {
                level += 5;
                reasons.Add("SUSPICIOUS: process has encoded PowerShell or download cradle in command line");
            }

            if (cmdLower.Contains("-windowstyle hidden") || cmdLower.Contains("-w hidden"))
            {
                level += 2;
                reasons.Add("SUSPICIOUS: process launched with hidden window flag");
            }

            int bsCount = 0;
            for (int i = 0; i < cmdLower.Length; i++)
                if ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=".IndexOf(cmdLower[i]) >= 0) bsCount++;
            if (cmdLower.Length > 200 && bsCount > cmdLower.Length * 0.8)
            {
                level += 3;
                reasons.Add("SUSPICIOUS: command line contains large base64-encoded block");
            }

            if (level == 0) return null;

            Dictionary<string, object> result = new Dictionary<string, object>();
            result["level"] = level;
            result["reasons"] = reasons;
            return result;
        }

        private bool HasKnownMalwareName(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            return KnownMalwareNames.Contains(processName);
        }

        private bool HasKnownMinerName(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            return KnownMinerNames.Contains(processName);
        }

        private bool IsAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        private Dictionary<int, List<string[]>> BuildConnectionMap()
        {
            Dictionary<int, List<string[]>> map = new Dictionary<int, List<string[]>>();
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netstat.exe", "-ano");
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);
                foreach (string line in output.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.Length < 20) continue;
                    if (!t.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                        !t.StartsWith("UDP", StringComparison.OrdinalIgnoreCase)) continue;
                    string[] parts = t.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 4) continue;
                    int pid;
                    if (!int.TryParse(parts[parts.Length - 1], out pid)) continue;
                    if (pid <= 0) continue;
                    if (!map.ContainsKey(pid)) map[pid] = new List<string[]>();
                    map[pid].Add(parts);
                }
            }
            catch { }
            return map;
        }

        private List<string> CheckSuspiciousConnections(int pid, Dictionary<int, List<string[]>> connMap)
        {
            List<string> findings = new List<string>();
            if (!connMap.ContainsKey(pid)) return findings;
            foreach (string[] conn in connMap[pid])
            {
                string remoteStr = conn[2];
                int colon = remoteStr.LastIndexOf(':');
                string remoteIp = colon > 0 ? remoteStr.Substring(0, colon) : remoteStr;
                string portStr = colon > 0 ? remoteStr.Substring(colon + 1) : "";
                int port = 0;
                int.TryParse(portStr, out port);
                bool isLoopback = remoteIp == "127.0.0.1" || remoteIp == "::1" || remoteIp.StartsWith("127.");
                int[] minerPorts = new int[] { 3333, 4444, 5555, 7777, 8888, 14444, 33333, 55555, 57828, 18081, 14444, 3340, 3357 };
                int[] remoteAdminPorts = new int[] { 22, 23, 3389, 5900, 5901, 5800, 5801 };
                foreach (int mp in minerPorts)
                {
                    if (port == mp && !isLoopback)
                    { findings.Add("Connection to known miner pool port " + port + " (" + remoteIp + ")"); break; }
                }
                foreach (int rp in remoteAdminPorts)
                {
                    if (port == rp && !isLoopback)
                    { findings.Add("Connection to remote admin port " + port + " (" + remoteIp + ")"); break; }
                }
                if (port > 10000 && port < 65535 && !isLoopback)
                {
                    if (conn[0].Equals("TCP", StringComparison.OrdinalIgnoreCase) &&
                        conn.Length > 3 && conn[3].IndexOf("ESTAB", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        findings.Add("Established TCP connection to high port " + port + " (" + remoteIp + ")");
                    }
                }
            }
            return findings;
        }

        private async Task PerformScan()
        {
            List<Dictionary<string, object>> threats = new List<Dictionary<string, object>>();
            Process[] processes = Process.GetProcesses();
            int total = processes.Length;
            int scanned = 0;

            Dictionary<int, List<string[]>> connMap = BuildConnectionMap();

            foreach (Process p in processes)
            {
                try
                {
                    if (IsProtectedProcess(p)) { scanned++; continue; }
                    string filePath = SafeGetProcessPath(p);
                    if (string.IsNullOrEmpty(filePath)) { scanned++; continue; }
                    if (IsProtectedPath(filePath)) { scanned++; continue; }
                    if (IsLegitimateWindowsProcess(p, filePath)) { scanned++; continue; }

                    Dictionary<string, object> result = AnalyzeProcess(p, filePath, connMap);
                    if (result != null) threats.Add(result);

                    scanned++;
                    if (scanned % 10 == 0)
                        await _send(new byte[] { 0x14, (byte)Math.Min(((scanned * 100) / total), 99) });
                }
                catch { scanned++; }
            }

            List<Dictionary<string, object>> startupThreats = ScanStartupEntries();
            threats.AddRange(startupThreats);

            List<Dictionary<string, object>> wmiThreats = ScanWMIPersistence();
            threats.AddRange(wmiThreats);

            List<Dictionary<string, object>> browserThreats = ScanBrowserHijackers();
            threats.AddRange(browserThreats);

            string json = SerializeThreats(threats);
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
            byte[] result2 = new byte[1 + jsonBytes.Length];
            result2[0] = 0x10;
            Buffer.BlockCopy(jsonBytes, 0, result2, 1, jsonBytes.Length);
            await _send(result2);
            await _send(new byte[] { 0x15, (byte)Math.Min(threats.Count, 255) });
        }

        private Dictionary<string, object> AnalyzeProcess(Process p, string filePath, Dictionary<int, List<string[]>> connMap = null)
        {
            int level = 0;
            List<string> reasons = new List<string>();

            bool suspicious = IsSuspiciousLocation(filePath);
            bool hidden = IsHiddenProcess(p);

            if (!suspicious && !hidden)
            {
                if (connMap != null)
                {
                    List<string> netFindings = CheckSuspiciousConnections(p.Id, connMap);
                    if (netFindings.Count > 0)
                    {
                        level += 4;
                        reasons.AddRange(netFindings);
                    }
                    else
                    {
                        if (!HasKnownMalwareName(Path.GetFileNameWithoutExtension(filePath).ToLower()))
                            return null;
                    }
                }
                else
                {
                    return null;
                }
            }

            string fileNameNoExt = Path.GetFileNameWithoutExtension(filePath).ToLower();
            string ext = Path.GetExtension(filePath).ToLower();

            string[] impersonationTargets = new[] { "svchost", "csrss", "winlogon", "lsass", "services", "smss", "wininit", "dwm" };
            foreach (string sn in impersonationTargets)
            {
                if (fileNameNoExt == sn && !IsInLegitimateDirectory(filePath))
                {
                    level += 10;
                    reasons.Add("IMPERSONATION: Fake '" + sn + "' not in System32");
                    break;
                }
            }

            if (suspicious && hidden)
            {
                level += 7;
                reasons.Add("Hidden process running from suspicious location");
            }
            else if (suspicious)
            {
                level += 3;
                reasons.Add("Running from suspicious location: " + Path.GetDirectoryName(filePath));
            }
            else if (hidden)
            {
                level += 1;
            }

            string[] dangerousExts = new[] { ".scr", ".pif", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".hta", ".cmd", ".bat" };
            foreach (string de in dangerousExts)
            {
                if (ext == de)
                {
                    level += 4;
                    reasons.Add("Dangerous file extension: " + ext);
                    break;
                }
            }

            if ((fileNameNoExt == "wscript" || fileNameNoExt == "cscript" || fileNameNoExt == "mshta") && hidden)
            {
                level += 5;
                reasons.Add("Hidden script host: " + fileNameNoExt);
            }

            if ((fileNameNoExt == "powershell" || fileNameNoExt == "pwsh") && hidden)
            {
                level += 5;
                reasons.Add("Hidden PowerShell instance");
            }

            if (suspicious)
            {
                try
                {
                    if (!HasValidSignature(filePath))
                    {
                        level += 3;
                        reasons.Add("Unsigned executable");
                    }
                }
                catch { }
            }

            try
            {
                FileAttributes attrs = File.GetAttributes(filePath);
                if ((attrs & FileAttributes.Hidden) != 0)
                {
                    level += 2;
                    reasons.Add("File has hidden attribute");
                }
            }
            catch { }

            if (HasRegistryPersistence(filePath))
            {
                level += 2;
                reasons.Add("Has registry startup persistence");
            }

            if (suspicious)
            {
                try
                {
                    FileInfo fi = new FileInfo(filePath);
                    if (fi.Length < 50000 && ext == ".exe")
                    {
                        level += 1;
                        reasons.Add("Very small executable (" + fi.Length + " bytes)");
                    }
                    if ((DateTime.Now - fi.CreationTime).TotalHours < 24)
                    {
                        level += 2;
                        reasons.Add("Created within last 24 hours");
                    }
                }
                catch { }
            }

            if (suspicious && IsRandomLookingName(fileNameNoExt))
            {
                level += 2;
                reasons.Add("Random-looking filename");
            }

            if (HasKnownMalwareName(fileNameNoExt))
            {
                level += 10;
                reasons.Add("KNOWN MALWARE: process name matches known RAT/malware signature");
            }

            if (HasKnownMinerName(fileNameNoExt))
            {
                level += 12;
                reasons.Add("KNOWN MINER: process name matches known cryptominer");
            }

            if (suspicious && KnownMalwareNames.Contains(fileNameNoExt))
            {
                level += 5;
                reasons.Add("Suspicious name + known signature match");
            }

            try
            {
                Dictionary<string, object> cliResult = ScanProcessCommandLine(p.Id, filePath);
                if (cliResult != null)
                {
                    level += (int)cliResult["level"];
                    reasons.AddRange((List<string>)cliResult["reasons"]);
                }
            }
            catch { }

            if (connMap != null)
            {
                try
                {
                    List<string> netFindings = CheckSuspiciousConnections(p.Id, connMap);
                    if (netFindings.Count > 0)
                    {
                        level += 4;
                        reasons.AddRange(netFindings);
                    }
                }
                catch { }
            }

            if (level < 5) return null;

            string hash = "";
            try
            {
                using (SHA256 sha = SHA256.Create())
                using (FileStream fs = File.OpenRead(filePath))
                    hash = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
            }
            catch { hash = "ERROR"; }

            long fileSize = 0;
            try { fileSize = new FileInfo(filePath).Length; } catch { }

            string created = "";
            try { created = File.GetCreationTime(filePath).ToString("yyyy-MM-dd HH:mm:ss"); } catch { }

            Dictionary<string, object> dict = new Dictionary<string, object>();
            dict["pid"] = p.Id;
            dict["name"] = p.ProcessName;
            dict["path"] = filePath;
            dict["level"] = level;
            dict["hash"] = hash;
            dict["size"] = fileSize;
            dict["created"] = created;
            dict["reasons"] = reasons;
            dict["type"] = "process";
            dict["hidden"] = hidden;
            dict["autoRemovable"] = (suspicious && hidden && level >= 7);
            return dict;
        }

        private bool IsRandomLookingName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length < 6) return false;
            int consonantRun = 0;
            int maxConsonantRun = 0;
            int digitCount = 0;
            string vowels = "aeiou";
            foreach (char c in name.ToLower())
            {
                if (char.IsDigit(c)) { digitCount++; consonantRun = 0; }
                else if (char.IsLetter(c))
                {
                    if (vowels.IndexOf(c) < 0) consonantRun++;
                    else consonantRun = 0;
                    if (consonantRun > maxConsonantRun) maxConsonantRun = consonantRun;
                }
                else consonantRun = 0;
            }
            if (maxConsonantRun >= 4) return true;
            if (name.Length > 6 && digitCount > name.Length / 2) return true;
            return false;
        }

        private List<Dictionary<string, object>> ScanStartupEntries()
        {
            List<Dictionary<string, object>> threats = new List<Dictionary<string, object>>();
            foreach (string regPath in RegistryRunPaths)
                ScanRegKey(Registry.CurrentUser, "HKCU", regPath, threats);
            foreach (string regPath in RegistryRunPathsMachine)
                ScanRegKey(Registry.LocalMachine, "HKLM", regPath, threats);
            ScanStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), threats);
            ScanStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), threats);
            return threats;
        }

        private void ScanRegKey(RegistryKey root, string rootName, string regPath, List<Dictionary<string, object>> threats)
        {
            try
            {
                RegistryKey key = root.OpenSubKey(regPath, false);
                if (key == null) return;
                foreach (string name in key.GetValueNames())
                {
                    object valObj = key.GetValue(name);
                    string val = valObj != null ? valObj.ToString() : "";
                    string extractedPath = ExtractPath(val);
                    if (string.IsNullOrEmpty(extractedPath)) continue;
                    if (IsProtectedPath(extractedPath)) continue;
                    if (IsInLegitimateDirectory(extractedPath)) continue;
                    if (!IsSuspiciousLocation(extractedPath)) continue;

                    int level = 5;
                    List<string> reasons = new List<string>();
                    reasons.Add("Startup persistence pointing to suspicious location");

                    bool exists = File.Exists(extractedPath);
                    if (!exists)
                    {
                        level += 2;
                        reasons.Add("Target file missing (orphaned entry)");
                    }
                    else
                    {
                        try
                        {
                            if (!HasValidSignature(extractedPath))
                            {
                                level += 2;
                                reasons.Add("Unsigned target");
                            }
                        }
                        catch { }

                        try
                        {
                            FileAttributes attrs = File.GetAttributes(extractedPath);
                            if ((attrs & FileAttributes.Hidden) != 0)
                            {
                                level += 3;
                                reasons.Add("Hidden target file");
                            }
                        }
                        catch { }

                        string ext = Path.GetExtension(extractedPath).ToLower();
                        string[] dangerExts = new[] { ".scr", ".pif", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".hta" };
                        foreach (string de in dangerExts)
                        {
                            if (ext == de) { level += 3; reasons.Add("Dangerous extension: " + ext); break; }
                        }
                    }

                    Dictionary<string, object> dict = new Dictionary<string, object>();
                    dict["pid"] = -1;
                    dict["name"] = name;
                    dict["path"] = extractedPath;
                    dict["level"] = level;
                    dict["hash"] = "";
                    dict["size"] = (long)0;
                    dict["created"] = "";
                    dict["reasons"] = reasons;
                    dict["type"] = "startup";
                    dict["registry"] = rootName + "\\" + regPath + "\\" + name;
                    dict["regValue"] = val;
                    dict["hidden"] = false;
                    dict["autoRemovable"] = true;
                    threats.Add(dict);
                }
                key.Close();
            }
            catch { }
        }

        private void ScanStartupFolder(string folderPath, List<Dictionary<string, object>> threats)
        {
            try
            {
                if (!Directory.Exists(folderPath)) return;
                foreach (string file in Directory.GetFiles(folderPath))
                {
                    if (IsProtectedPath(file)) continue;
                    string ext = Path.GetExtension(file).ToLower();
                    if (ext == ".lnk" || ext == ".ini" || ext == ".desktop") continue;

                    int level = 6;
                    List<string> reasons = new List<string>();
                    reasons.Add("Executable file directly in Startup folder");

                    if (ext == ".vbs" || ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".hta")
                    {
                        level += 3;
                        reasons.Add("Script file in Startup: " + ext);
                    }

                    try
                    {
                        if (!HasValidSignature(file))
                        {
                            level += 2;
                            reasons.Add("Unsigned");
                        }
                    }
                    catch { }

                    Dictionary<string, object> dict = new Dictionary<string, object>();
                    dict["pid"] = -1;
                    dict["name"] = Path.GetFileName(file);
                    dict["path"] = file;
                    dict["level"] = level;
                    dict["hash"] = "";
                    dict["size"] = (long)0;
                    try { dict["size"] = new FileInfo(file).Length; } catch { }
                    dict["created"] = "";
                    try { dict["created"] = File.GetCreationTime(file).ToString("yyyy-MM-dd HH:mm:ss"); } catch { }
                    dict["reasons"] = reasons;
                    dict["type"] = "startup_file";
                    dict["registry"] = "Startup Folder";
                    dict["regValue"] = file;
                    dict["hidden"] = false;
                    dict["autoRemovable"] = true;
                    threats.Add(dict);
                }
            }
            catch { }
        }

        private List<Dictionary<string, object>> ScanWMIPersistence()
        {
            List<Dictionary<string, object>> threats = new List<Dictionary<string, object>>();
            try
            {
                System.Management.ManagementObjectSearcher filterSearcher = new System.Management.ManagementObjectSearcher(
                    @"root\subscription", "SELECT * FROM __EventFilter");
                foreach (System.Management.ManagementObject filter in filterSearcher.Get())
                {
                    try
                    {
                        string name = filter["Name"]?.ToString() ?? "";
                        string query = filter["Query"]?.ToString() ?? "";
                        if (string.IsNullOrEmpty(query)) continue;
                        string queryLower = query.ToLower();
                        if (queryLower.Contains("shell") || queryLower.Contains("cmd") || queryLower.Contains("powershell") ||
                            queryLower.Contains("wscript") || queryLower.Contains("cscript") || queryLower.Contains("mshta") ||
                            queryLower.Contains("rundll32") || queryLower.Contains("regsvr32") ||
                            queryLower.Contains("bitsadmin") || queryLower.Contains("certutil"))
                        {
                            int level = 7;
                            List<string> reasons = new List<string>();
                            reasons.Add("WMI persistence: EventFilter with suspicious query: " + name);
                            reasons.Add("  Query: " + TruncateStr(query, 150));
                            Dictionary<string, object> dict = new Dictionary<string, object>();
                            dict["pid"] = -1;
                            dict["name"] = name;
                            dict["path"] = "WMI:" + name;
                            dict["level"] = level;
                            dict["hash"] = "";
                            dict["size"] = (long)0;
                            dict["created"] = "";
                            dict["reasons"] = reasons;
                            dict["type"] = "wmi";
                            dict["registry"] = "root\\subscription\\__EventFilter";
                            dict["regValue"] = query;
                            dict["hidden"] = false;
                            dict["autoRemovable"] = false;
                            threats.Add(dict);
                        }
                    }
                    catch { }
                    filter.Dispose();
                }
                filterSearcher.Dispose();
            }
            catch { }
            try
            {
                System.Management.ManagementObjectSearcher consumerSearcher = new System.Management.ManagementObjectSearcher(
                    @"root\subscription", "SELECT * FROM CommandLineEventConsumer");
                foreach (System.Management.ManagementObject consumer in consumerSearcher.Get())
                {
                    try
                    {
                        string name = consumer["Name"]?.ToString() ?? "";
                        string cmd = consumer["CommandLineTemplate"]?.ToString() ?? "";
                        if (string.IsNullOrEmpty(cmd)) continue;
                        string cmdLower = cmd.ToLower();
                        if (cmdLower.Contains("powershell") || cmdLower.Contains("cmd") || cmdLower.Contains("wscript") ||
                            cmdLower.Contains("cscript") || cmdLower.Contains("mshta") || cmdLower.Contains("rundll32") ||
                            cmdLower.Contains("regsvr32") || cmdLower.Contains("bitsadmin") || cmdLower.Contains("certutil") ||
                            cmdLower.Contains("--donate-level") || cmdLower.Contains("encodedcommand"))
                        {
                            int level = 7;
                            List<string> reasons = new List<string>();
                            reasons.Add("WMI persistence: CommandLineEventConsumer with suspicious template: " + name);
                            reasons.Add("  Template: " + TruncateStr(cmd, 150));
                            Dictionary<string, object> dict = new Dictionary<string, object>();
                            dict["pid"] = -1;
                            dict["name"] = name;
                            dict["path"] = "WMI:" + name;
                            dict["level"] = level;
                            dict["hash"] = "";
                            dict["size"] = (long)0;
                            dict["created"] = "";
                            dict["reasons"] = reasons;
                            dict["type"] = "wmi";
                            dict["registry"] = "root\\subscription\\CommandLineEventConsumer";
                            dict["regValue"] = cmd;
                            dict["hidden"] = false;
                            dict["autoRemovable"] = false;
                            threats.Add(dict);
                        }
                    }
                    catch { }
                    consumer.Dispose();
                }
                consumerSearcher.Dispose();
            }
            catch { }
            return threats;
        }

        private string TruncateStr(string s, int max)
        {
            if (s == null) return "";
            return s.Length <= max ? s : s.Substring(0, max) + "...";
        }

        private string ExtractPath(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            value = value.Trim();
            if (value.StartsWith("\""))
            {
                int end = value.IndexOf('"', 1);
                if (end > 1) return value.Substring(1, end - 1);
            }
            if (File.Exists(value)) return value;
            string building = "";
            foreach (string part in value.Split(' '))
            {
                building = string.IsNullOrEmpty(building) ? part : building + " " + part;
                if (File.Exists(building)) return building;
            }
            if (value.IndexOf('\\') >= 0 || value.IndexOf('/') >= 0)
            {
                int spaceIdx = value.IndexOf(' ');
                if (spaceIdx > 0)
                {
                    string candidate = value.Substring(0, spaceIdx);
                    if (File.Exists(candidate)) return candidate;
                }
                return value;
            }
            return null;
        }

        private List<Dictionary<string, object>> ScanBrowserHijackers()
        {
            List<Dictionary<string, object>> threats = new List<Dictionary<string, object>>();

            try
            {
                RegistryKey ieMain = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Internet Explorer\Main", false);
                if (ieMain != null)
                {
                    string startPage = ieMain.GetValue("Start Page")?.ToString() ?? "";
                    string defaultPage = ieMain.GetValue("Default_Page_URL")?.ToString() ?? "";
                    ieMain.Close();
                    if (!string.IsNullOrEmpty(startPage) && !startPage.Equals("about:blank", StringComparison.OrdinalIgnoreCase))
                    {
                        string lowerStart = startPage.ToLower();
                        if (!lowerStart.StartsWith("https://www.google") && !lowerStart.StartsWith("http://www.google") &&
                            !lowerStart.StartsWith("https://www.bing") && !lowerStart.StartsWith("http://www.bing") &&
                            !lowerStart.StartsWith("https://search.yahoo") && !lowerStart.StartsWith("http://search.yahoo") &&
                            !lowerStart.StartsWith("https://duckduckgo") && !lowerStart.StartsWith("http://duckduckgo") &&
                            !lowerStart.StartsWith("https://start.duckduckgo") && !lowerStart.StartsWith("https://www.ecosia"))
                        {
                            List<string> reasons = new List<string>();
                            reasons.Add("Browser hijacker: IE start page set to non-default: " + startPage);
                            Dictionary<string, object> dict = new Dictionary<string, object>();
                            dict["pid"] = -1;
                            dict["name"] = "IE Start Page";
                            dict["path"] = "Registry: IE Start Page";
                            dict["level"] = 5;
                            dict["hash"] = "";
                            dict["size"] = (long)0;
                            dict["created"] = "";
                            dict["reasons"] = reasons;
                            dict["type"] = "startup";
                            dict["registry"] = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main";
                            dict["regValue"] = startPage;
                            dict["hidden"] = false;
                            dict["autoRemovable"] = true;
                            threats.Add(dict);
                        }
                    }
                }
            }
            catch { }

            try
            {
                RegistryKey proxyKey = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
                if (proxyKey != null)
                {
                    object proxyObj = proxyKey.GetValue("ProxyServer");
                    object enableObj = proxyKey.GetValue("ProxyEnable");
                    bool proxyEnabled = enableObj != null && enableObj.ToString() == "1";
                    string proxyStr = proxyObj?.ToString() ?? "";
                    proxyKey.Close();
                    if (proxyEnabled && !string.IsNullOrEmpty(proxyStr))
                    {
                        if (!proxyStr.ToLower().Contains("localhost") && !proxyStr.ToLower().Contains("127.0.0.1") &&
                            !proxyStr.ToLower().Contains("::1") && !proxyStr.StartsWith("http://127.") &&
                            !proxyStr.ToLower().Contains("none"))
                        {
                            List<string> reasons = new List<string>();
                            reasons.Add("Browser hijacker: system proxy enabled and pointing to: " + proxyStr);
                            Dictionary<string, object> dict = new Dictionary<string, object>();
                            dict["pid"] = -1;
                            dict["name"] = "Proxy Server";
                            dict["path"] = proxyStr;
                            dict["level"] = 6;
                            dict["hash"] = "";
                            dict["size"] = (long)0;
                            dict["created"] = "";
                            dict["reasons"] = reasons;
                            dict["type"] = "startup";
                            dict["registry"] = "HKCU\\Internet Settings\\ProxyServer";
                            dict["regValue"] = proxyStr;
                            dict["hidden"] = false;
                            dict["autoRemovable"] = true;
                            threats.Add(dict);
                        }
                    }
                }
            }
            catch { }

            return threats;
        }

        private async Task AutoClean()
        {
            List<Dictionary<string, object>> removed = new List<Dictionary<string, object>>();
            Process[] processes = Process.GetProcesses();
            int total = processes.Length;
            int scanned = 0;

            foreach (Process p in processes)
            {
                try
                {
                    if (IsProtectedProcess(p)) { scanned++; continue; }
                    string filePath = SafeGetProcessPath(p);
                    if (string.IsNullOrEmpty(filePath)) { scanned++; continue; }
                    if (IsProtectedPath(filePath)) { scanned++; continue; }
                    if (IsLegitimateWindowsProcess(p, filePath)) { scanned++; continue; }

                    bool suspicious = IsSuspiciousLocation(filePath);
                    bool hidden = IsHiddenProcess(p);

                    if (suspicious && hidden)
                    {
                        string nameNoExt = Path.GetFileNameWithoutExtension(filePath);
                        if (KnownWindowsProcesses.Contains(nameNoExt)) { scanned++; continue; }

                        string processName = p.ProcessName;
                        int pid = p.Id;

                        try { p.Kill(); p.WaitForExit(5000); } catch { }

                        foreach (string regPath in RegistryRunPaths)
                            RegistryClean(Registry.CurrentUser, regPath, filePath);
                        if (IsAdmin())
                        {
                            foreach (string regPath in RegistryRunPathsMachine)
                                RegistryClean(Registry.LocalMachine, regPath, filePath);
                        }

                        Thread.Sleep(200);

                        try
                        {
                            if (File.Exists(filePath))
                            {
                                File.SetAttributes(filePath, FileAttributes.Normal);
                                File.Delete(filePath);
                            }
                        }
                        catch
                        {
                            try { MoveFileEx(filePath, null, 0x4); } catch { }
                        }

                        RemoveFromStartupFolders(filePath);

                        Dictionary<string, object> entry = new Dictionary<string, object>();
                        entry["pid"] = pid;
                        entry["name"] = processName;
                        entry["path"] = filePath;
                        removed.Add(entry);
                    }

                    scanned++;
                    if (scanned % 10 == 0)
                        await _send(new byte[] { 0x14, (byte)Math.Min(((scanned * 100) / total), 99) });
                }
                catch { scanned++; }
            }

            string json = SerializeRemovedList(removed);
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
            byte[] result = new byte[1 + jsonBytes.Length];
            result[0] = 0x1B;
            Buffer.BlockCopy(jsonBytes, 0, result, 1, jsonBytes.Length);
            await _send(result);
            await _send(new byte[] { 0x15, (byte)Math.Min(removed.Count, 255) });
        }

        private void RemoveFromStartupFolders(string filePath)
        {
            string fileName = Path.GetFileName(filePath);
            string[] startupDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };
            foreach (string dir in startupDirs)
            {
                if (string.IsNullOrEmpty(dir)) continue;
                try
                {
                    string copy = Path.Combine(dir, fileName);
                    if (File.Exists(copy))
                    {
                        File.SetAttributes(copy, FileAttributes.Normal);
                        File.Delete(copy);
                    }
                }
                catch { }
            }
        }

        private async Task KillProcess(byte[] payload)
        {
            if (payload == null || payload.Length < 4) { await SendError(0x02, "Invalid PID"); return; }
            int pid = BitConverter.ToInt32(payload, 0);
            if (_protectedPids.Contains(pid)) { await SendError(0x02, "Protected: own process chain"); return; }

            try
            {
                Process p = Process.GetProcessById(pid);
                if (IsProtectedProcess(p)) { await SendError(0x02, "Protected process"); return; }
                string name = p.ProcessName;
                p.Kill();
                p.WaitForExit(5000);
                byte[] nb = Encoding.UTF8.GetBytes("Killed: " + name + " (PID " + pid + ")");
                byte[] r = new byte[1 + nb.Length]; r[0] = 0x01;
                Buffer.BlockCopy(nb, 0, r, 1, nb.Length);
                await _send(r);
            }
            catch (Exception ex) { await SendError(0x02, ex.Message); }
        }

        private async Task DeleteFile(byte[] payload)
        {
            if (payload == null) { await SendError(0x10, "No path"); return; }
            string path = Encoding.UTF8.GetString(payload);
            if (IsProtectedPath(path)) { await SendError(0x10, "Protected path"); return; }

            try
            {
                if (File.Exists(path))
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                }
                byte[] pb = Encoding.UTF8.GetBytes(path);
                byte[] r = new byte[1 + pb.Length]; r[0] = 0x1A;
                Buffer.BlockCopy(pb, 0, r, 1, pb.Length);
                await _send(r);
            }
            catch (Exception ex)
            {
                try { MoveFileEx(path, null, 0x4); } catch { }
                await SendError(0x10, ex.Message);
            }
        }

        private async Task KillAndDelete(byte[] payload)
        {
            if (payload == null || payload.Length < 5) { await SendError(0x11, "Bad format"); return; }
            int pid = BitConverter.ToInt32(payload, 0);
            string path = Encoding.UTF8.GetString(payload, 4, payload.Length - 4);
            if (IsProtectedPath(path) || _protectedPids.Contains(pid)) { await SendError(0x11, "Protected"); return; }

            try
            {
                try
                {
                    Process p = Process.GetProcessById(pid);
                    if (!IsProtectedProcess(p)) { p.Kill(); p.WaitForExit(5000); }
                }
                catch { }

                Thread.Sleep(300);

                foreach (string regPath in RegistryRunPaths)
                    RegistryClean(Registry.CurrentUser, regPath, path);
                if (IsAdmin())
                {
                    foreach (string regPath in RegistryRunPathsMachine)
                        RegistryClean(Registry.LocalMachine, regPath, path);
                }

                if (File.Exists(path))
                {
                    try { File.SetAttributes(path, FileAttributes.Normal); File.Delete(path); }
                    catch { MoveFileEx(path, null, 0x4); }
                }

                RemoveFromStartupFolders(path);

                byte[] pb = Encoding.UTF8.GetBytes(path);
                byte[] r = new byte[1 + pb.Length]; r[0] = 0x13;
                Buffer.BlockCopy(pb, 0, r, 1, pb.Length);
                await _send(r);
            }
            catch (Exception ex) { await SendError(0x11, ex.Message); }
        }

        private async Task FullRemove(byte[] payload)
        {
            if (payload == null) { await SendError(0x12, "No data"); return; }
            string path = Encoding.UTF8.GetString(payload);
            if (IsProtectedPath(path)) { await SendError(0x12, "Protected"); return; }

            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        if (IsProtectedProcess(p)) continue;
                        string procPath = SafeGetProcessPath(p);
                        if (procPath != null && procPath.Equals(path, StringComparison.OrdinalIgnoreCase))
                        { p.Kill(); p.WaitForExit(5000); }
                    }
                    catch { }
                }
                Thread.Sleep(300);

                foreach (string regPath in RegistryRunPaths)
                    RegistryClean(Registry.CurrentUser, regPath, path);
                if (IsAdmin())
                {
                    foreach (string regPath in RegistryRunPathsMachine)
                        RegistryClean(Registry.LocalMachine, regPath, path);
                }

                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", "/query /fo CSV /v");
                    psi.RedirectStandardOutput = true; psi.UseShellExecute = false; psi.CreateNoWindow = true;
                    Process proc = Process.Start(psi);
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(15000);
                    foreach (string line in output.Split('\n'))
                    {
                        if (line.IndexOf(path, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            string[] parts = line.Split(',');
                            if (parts.Length > 0)
                            {
                                string taskName = parts[0].Trim('"', ' ');
                                if (!string.IsNullOrEmpty(taskName))
                                {
                                    ProcessStartInfo delPsi = new ProcessStartInfo("schtasks.exe", "/delete /tn \"" + taskName + "\" /f");
                                    delPsi.UseShellExecute = false; delPsi.CreateNoWindow = true;
                                    Process delProc = Process.Start(delPsi);
                                    if (delProc != null) delProc.WaitForExit(5000);
                                }
                            }
                        }
                    }
                }
                catch { }

                if (File.Exists(path))
                {
                    try { File.SetAttributes(path, FileAttributes.Normal); File.Delete(path); }
                    catch { MoveFileEx(path, null, 0x4); }
                }

                RemoveFromStartupFolders(path);

                byte[] pb = Encoding.UTF8.GetBytes(path);
                byte[] r = new byte[1 + pb.Length]; r[0] = 0x13;
                Buffer.BlockCopy(pb, 0, r, 1, pb.Length);
                await _send(r);
            }
            catch (Exception ex) { await SendError(0x12, ex.Message); }
        }

        private async Task RunAntiAnalysis()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== Anti-Analysis Check ===");
            sb.AppendLine("Time: " + DateTime.UtcNow.ToString("O"));

            CheckVMAnalysis(sb);
            CheckDebuggerAnalysis(sb);
            CheckSandboxAnalysis(sb);
            CheckDiskAnalysis(sb);

            string result = sb.ToString();
            byte[] data = Encoding.UTF8.GetBytes(result);
            byte[] r = new byte[1 + data.Length];
            r[0] = 0x1C;
            Buffer.BlockCopy(data, 0, r, 1, data.Length);
            await _send(r);
        }

        private void CheckVMAnalysis(StringBuilder sb)
        {
            bool detected = false;
            try
            {
                System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(
                    "Select * from Win32_ComputerSystem");
                foreach (System.Management.ManagementObject item in searcher.Get())
                {
                    string manufacturer = item["Manufacturer"]?.ToString()?.ToLower() ?? "";
                    string model = item["Model"]?.ToString() ?? "";
                    if ((manufacturer == "microsoft corporation" && model.ToUpperInvariant().Contains("VIRTUAL")) ||
                        manufacturer.Contains("vmware") || model == "VirtualBox")
                    {
                        detected = true;
                        sb.AppendLine("[VM DETECTED] Manufacturer=" + manufacturer + " Model=" + model);
                        break;
                    }
                    item.Dispose();
                }
                searcher.Dispose();
            }
            catch { }
            if (!detected) sb.AppendLine("[VM] No VM indicators detected");
        }

        private void CheckDebuggerAnalysis(StringBuilder sb)
        {
            bool detected = false;
            try
            {
                if (System.Diagnostics.Debugger.IsAttached) detected = true;
            }
            catch { }
            sb.AppendLine(detected ? "[DEBUGGER] Debugger detected!" : "[DEBUGGER] No debugger detected");
        }

        private void CheckSandboxAnalysis(StringBuilder sb)
        {
            bool detected = false;
            try
            {
                try
                {
                    if (Process.GetProcessesByName("vmtoolsd").Length > 0 ||
                        Process.GetProcessesByName("vboxservice").Length > 0 ||
                        Process.GetProcessesByName("vboxtray").Length > 0)
                    {
                        detected = true;
                        sb.AppendLine("[SANDBOX] VM guest tools process found");
                    }
                }
                catch { }
            }
            catch { }
            if (!detected) sb.AppendLine("[SANDBOX] No sandbox indicators detected");
        }

        private void CheckDiskAnalysis(StringBuilder sb)
        {
            try
            {
                long GB_60 = 61000000000L;
                long totalSize = 0;
                try
                {
                    System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(
                        "SELECT Size FROM Win32_DiskDrive");
                    foreach (System.Management.ManagementObject obj in searcher.Get())
                    {
                        object sizeObj = obj["Size"];
                        if (sizeObj != null) totalSize += Convert.ToInt64(sizeObj);
                        obj.Dispose();
                    }
                    searcher.Dispose();
                }
                catch
                {
                    DriveInfo d = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory));
                    totalSize = d.TotalSize;
                }
                if (totalSize <= GB_60)
                {
                    sb.AppendLine("[DISK] Small disk detected (" + (totalSize / 1000000000.0).ToString("F1") + " GB) - possible VM/sandbox");
                }
                else
                {
                    sb.AppendLine("[DISK] Disk size normal (" + (totalSize / 1000000000.0).ToString("F1") + " GB)");
                }
            }
            catch { sb.AppendLine("[DISK] Could not determine disk size"); }
        }

        private async Task RemoveThreat(byte[] payload)
        {
            if (payload == null) return;
            await FullRemove(payload);
        }

        private async Task SendProcessList()
        {
            StringBuilder sb = new StringBuilder();
            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    string path = SafeGetProcessPath(p) ?? "";
                    long mem = 0; string started = "";
                    try { mem = p.WorkingSet64; } catch { }
                    try { started = p.StartTime.ToString("yyyy-MM-dd HH:mm:ss"); } catch { }
                    bool prot = IsProtectedProcess(p);
                    bool vis = false;
                    try { vis = p.MainWindowHandle != IntPtr.Zero && IsWindowVisible(p.MainWindowHandle); } catch { }
                    sb.AppendLine(p.Id + "|" + p.ProcessName + "|" + path + "|" + prot + "|" + vis + "|" + mem + "|" + started);
                }
                catch { }
            }
            byte[] data = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] r = new byte[1 + data.Length]; r[0] = 0x11;
            Buffer.BlockCopy(data, 0, r, 1, data.Length);
            await _send(r);
        }

        private async Task SendStartupList()
        {
            StringBuilder sb = new StringBuilder();
            foreach (string regPath in RegistryRunPaths)
                AppendStartupEntries(sb, Registry.CurrentUser, "HKCU", regPath);
            foreach (string regPath in RegistryRunPathsMachine)
                AppendStartupEntries(sb, Registry.LocalMachine, "HKLM", regPath);
            byte[] data = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] r = new byte[1 + data.Length]; r[0] = 0x12;
            Buffer.BlockCopy(data, 0, r, 1, data.Length);
            await _send(r);
        }

        private void AppendStartupEntries(StringBuilder sb, RegistryKey root, string rootName, string regPath)
        {
            try
            {
                RegistryKey key = root.OpenSubKey(regPath, false);
                if (key == null) return;
                foreach (string name in key.GetValueNames())
                {
                    object valObj = key.GetValue(name);
                    string val = valObj != null ? valObj.ToString() : "";
                    sb.AppendLine(rootName + "|" + regPath + "|" + name + "|" + val);
                }
                key.Close();
            }
            catch { }
        }

        private async Task SendScheduledTasks()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", "/query /fo CSV /v");
                psi.RedirectStandardOutput = true; psi.UseShellExecute = false; psi.CreateNoWindow = true;
                Process proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(15000);
                byte[] data = Encoding.UTF8.GetBytes(output);
                byte[] r = new byte[1 + data.Length]; r[0] = 0x16;
                Buffer.BlockCopy(data, 0, r, 1, data.Length);
                await _send(r);
            }
            catch (Exception ex) { await SendError(0x07, ex.Message); }
        }

        private async Task RemoveStartupEntry(byte[] payload)
        {
            if (payload == null) return;
            string entry = Encoding.UTF8.GetString(payload);
            string[] parts = entry.Split('|');
            if (parts.Length < 3) { await SendError(0x08, "Invalid format"); return; }

            try
            {
                RegistryKey checkRoot = parts[0] == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                RegistryKey checkKey = checkRoot.OpenSubKey(parts[1], false);
                if (checkKey != null)
                {
                    object val = checkKey.GetValue(parts[2]);
                    if (val != null)
                    {
                        string valStr = val.ToString();
                        if (!string.IsNullOrEmpty(_ownPath) && valStr.IndexOf(_ownPath, StringComparison.OrdinalIgnoreCase) >= 0)
                        { checkKey.Close(); await SendError(0x08, "Protected: own startup entry"); return; }
                        if (!string.IsNullOrEmpty(_ownName) && valStr.IndexOf(_ownName, StringComparison.OrdinalIgnoreCase) >= 0)
                        { checkKey.Close(); await SendError(0x08, "Protected: own startup entry"); return; }
                    }
                    checkKey.Close();
                }
            }
            catch { }

            try
            {
                RegistryKey root = parts[0] == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                RegistryKey key = root.OpenSubKey(parts[1], true);
                if (key != null) { key.DeleteValue(parts[2], false); key.Close(); }
                await SendAck(0x08);
            }
            catch (Exception ex) { await SendError(0x08, ex.Message); }
        }

        private async Task QuarantineFile(byte[] payload)
        {
            if (payload == null) return;
            string filePath = Encoding.UTF8.GetString(payload);
            if (IsProtectedPath(filePath)) { await SendError(0x09, "Protected"); return; }

            try
            {
                string qDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BotKillerQuarantine");
                Directory.CreateDirectory(qDir);
                string safeName = Convert.ToBase64String(Encoding.UTF8.GetBytes(filePath)).Replace('/', '_').Replace('+', '-');
                string dest = Path.Combine(qDir, safeName + ".quarantined");

                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        if (IsProtectedProcess(p)) continue;
                        string procPath = SafeGetProcessPath(p);
                        if (procPath != null && procPath.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                        { p.Kill(); p.WaitForExit(5000); }
                    }
                    catch { }
                }
                Thread.Sleep(200);

                File.SetAttributes(filePath, FileAttributes.Normal);
                File.Move(filePath, dest);
                File.WriteAllText(dest + ".meta", "OriginalPath: " + filePath + "\nDate: " + DateTime.UtcNow.ToString("O") + "\n");
                await SendAck(0x09);
            }
            catch (Exception ex) { await SendError(0x09, ex.Message); }
        }

        private async Task CheckHostsFile()
        {
            try
            {
                string path = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
                string content = File.ReadAllText(path);
                byte[] data = Encoding.UTF8.GetBytes(content);
                byte[] r = new byte[1 + data.Length]; r[0] = 0x17;
                Buffer.BlockCopy(data, 0, r, 1, data.Length);
                await _send(r);
            }
            catch (Exception ex) { await SendError(0x0A, ex.Message); }
        }

        private async Task RepairHostsFile()
        {
            try
            {
                string path = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
                string defaultContent = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file.\r\n#\r\n# 127.0.0.1       localhost\r\n# ::1             localhost\r\n";
                File.WriteAllText(path, defaultContent);
                await SendAck(0x0B);
            }
            catch (Exception ex) { await SendError(0x0B, ex.Message); }
        }

        private async Task CheckDNS()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", false);
                if (key != null)
                {
                    foreach (string sub in key.GetSubKeyNames())
                    {
                        try
                        {
                            RegistryKey sk = key.OpenSubKey(sub, false);
                            if (sk == null) continue;
                            string dns = sk.GetValue("NameServer")?.ToString() ?? "";
                            string dhcp = sk.GetValue("DhcpNameServer")?.ToString() ?? "";
                            sk.Close();
                            if (!string.IsNullOrEmpty(dns) || !string.IsNullOrEmpty(dhcp))
                                sb.AppendLine(sub + "|DNS=" + dns + "|DHCP=" + dhcp);
                        }
                        catch { }
                    }
                    key.Close();
                }
                byte[] data = Encoding.UTF8.GetBytes(sb.ToString());
                byte[] r = new byte[1 + data.Length]; r[0] = 0x18;
                Buffer.BlockCopy(data, 0, r, 1, data.Length);
                await _send(r);
            }
            catch (Exception ex) { await SendError(0x0C, ex.Message); }
        }

        private async Task ScanServices()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT Name, DisplayName, State, PathName, StartMode FROM Win32_Service"))
                using (var services = searcher.Get())
                {
                    foreach (System.Management.ManagementObject svc in services)
                    {
                        try
                        {
                            string name = svc["Name"]?.ToString() ?? "";
                            string displayName = svc["DisplayName"]?.ToString() ?? "";
                            string status = svc["State"]?.ToString() ?? "";
                            string imagePath = svc["PathName"]?.ToString() ?? "";
                            string startType = svc["StartMode"]?.ToString() ?? "";
                            sb.AppendLine(name + "|" + displayName + "|" + status + "|" + imagePath + "|" + startType);
                        }
                        catch { }
                    }
                }
                byte[] data = Encoding.UTF8.GetBytes(sb.ToString());
                byte[] r = new byte[1 + data.Length]; r[0] = 0x19;
                Buffer.BlockCopy(data, 0, r, 1, data.Length);
                await _send(r);
            }
            catch (Exception ex) { await SendError(0x0D, ex.Message); }
        }

        private async Task StopService(byte[] payload)
        {
            if (payload == null) return;
            string name = Encoding.UTF8.GetString(payload);
            if (IsProtectedServiceName(name)) { await SendError(0x0E, "Protected: own service"); return; }

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("sc.exe", "stop \"" + name + "\"");
                psi.UseShellExecute = false; psi.CreateNoWindow = true;
                Process proc = Process.Start(psi);
                if (proc != null) { proc.WaitForExit(15000); proc.Dispose(); }
                await SendAck(0x0E);
            }
            catch (Exception ex) { await SendError(0x0E, ex.Message); }
        }

        private async Task DeleteService(byte[] payload)
        {
            if (payload == null) return;
            string name = Encoding.UTF8.GetString(payload);
            if (IsProtectedServiceName(name)) { await SendError(0x0F, "Protected: own service"); return; }

            try
            {
                ProcessStartInfo psiStop = new ProcessStartInfo("sc.exe", "stop \"" + name + "\"");
                psiStop.UseShellExecute = false; psiStop.CreateNoWindow = true;
                Process procStop = Process.Start(psiStop);
                if (procStop != null) { procStop.WaitForExit(10000); procStop.Dispose(); }

                ProcessStartInfo psiDel = new ProcessStartInfo("sc.exe", "delete \"" + name + "\"");
                psiDel.UseShellExecute = false; psiDel.CreateNoWindow = true;
                Process procDel = Process.Start(psiDel);
                if (procDel != null) procDel.WaitForExit(10000);
                await SendAck(0x0F);
            }
            catch (Exception ex) { await SendError(0x0F, ex.Message); }
        }

        private void RegistryClean(RegistryKey root, string regPath, string filePath)
        {
            try
            {
                RegistryKey key = root.OpenSubKey(regPath, true);
                if (key == null) return;
                foreach (string name in key.GetValueNames())
                {
                    object valObj = key.GetValue(name);
                    string val = valObj != null ? valObj.ToString() : "";
                    if (!string.IsNullOrEmpty(_ownPath) && val.IndexOf(_ownPath, StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    if (!string.IsNullOrEmpty(_ownName) && val.IndexOf(_ownName, StringComparison.OrdinalIgnoreCase) >= 0) continue;

                    if (val.IndexOf(filePath, StringComparison.OrdinalIgnoreCase) >= 0)
                        key.DeleteValue(name, false);
                }
                key.Close();
            }
            catch { }
        }

        private async Task SendAck(byte op)
        {
            await _send(new byte[] { 0x01, op });
        }

        private async Task SendError(byte op, string msg)
        {
            byte[] mb = Encoding.UTF8.GetBytes(msg ?? "Unknown error");
            byte[] r = new byte[2 + mb.Length]; r[0] = 0x02; r[1] = op;
            Buffer.BlockCopy(mb, 0, r, 2, mb.Length);
            try { await _send(r); } catch { }
        }

        private string SerializeThreats(List<Dictionary<string, object>> threats)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append('[');
            for (int i = 0; i < threats.Count; i++)
            {
                Dictionary<string, object> t = threats[i];
                if (i > 0) sb.Append(',');
                sb.Append('{');
                sb.Append("\"pid\":"); sb.Append(t["pid"]); sb.Append(',');
                sb.Append("\"name\":\""); sb.Append(Esc(t["name"].ToString())); sb.Append("\",");
                sb.Append("\"path\":\""); sb.Append(Esc(t["path"].ToString())); sb.Append("\",");
                sb.Append("\"level\":"); sb.Append(t["level"]); sb.Append(',');
                sb.Append("\"hash\":\""); sb.Append(Esc(t["hash"].ToString())); sb.Append("\",");
                sb.Append("\"size\":"); sb.Append(t["size"]); sb.Append(',');
                sb.Append("\"created\":\""); sb.Append(Esc(t["created"].ToString())); sb.Append("\",");
                sb.Append("\"type\":\""); sb.Append(Esc(t["type"].ToString())); sb.Append("\",");
                sb.Append("\"hidden\":"); sb.Append(((bool)t["hidden"]) ? "true" : "false"); sb.Append(',');
                sb.Append("\"autoRemovable\":"); sb.Append(((bool)t["autoRemovable"]) ? "true" : "false"); sb.Append(',');
                if (t.ContainsKey("registry"))
                { sb.Append("\"registry\":\""); sb.Append(Esc(t["registry"].ToString())); sb.Append("\","); }
                if (t.ContainsKey("regValue"))
                { sb.Append("\"regValue\":\""); sb.Append(Esc(t["regValue"].ToString())); sb.Append("\","); }
                sb.Append("\"reasons\":[");
                List<string> reasons = (List<string>)t["reasons"];
                for (int j = 0; j < reasons.Count; j++)
                {
                    if (j > 0) sb.Append(',');
                    sb.Append('"'); sb.Append(Esc(reasons[j])); sb.Append('"');
                }
                sb.Append("]}");
            }
            sb.Append(']');
            return sb.ToString();
        }

        private string SerializeRemovedList(List<Dictionary<string, object>> items)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append('[');
            for (int i = 0; i < items.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append('{');
                sb.Append("\"pid\":"); sb.Append(items[i]["pid"]); sb.Append(',');
                sb.Append("\"name\":\""); sb.Append(Esc(items[i]["name"].ToString())); sb.Append("\",");
                sb.Append("\"path\":\""); sb.Append(Esc(items[i]["path"].ToString())); sb.Append("\"");
                sb.Append('}');
            }
            sb.Append(']');
            return sb.ToString();
        }

        private string Esc(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
        }
    }
}
""";
        }
    }

    public class ThreatEntry
    {
        public string ClientId { get; set; } = "";
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public int ThreatLevel { get; set; }
        public string FileHash { get; set; } = "";
        public long FileSize { get; set; }
        public string Created { get; set; } = "";
        public string Type { get; set; } = "process";
        public string RegistryPath { get; set; } = "";
        public string RegistryValue { get; set; } = "";
        public bool IsHidden { get; set; }
        public bool AutoRemovable { get; set; }
        public List<string> Reasons { get; set; } = new();

        public string ThreatLevelLabel => ThreatLevel >= 8 ? "CRITICAL" : ThreatLevel >= 5 ? "HIGH" : ThreatLevel >= 4 ? "MEDIUM" : "LOW";

        public Color ThreatColor => ThreatLevel >= 8 ? Color.FromRgb(218, 54, 51)
            : ThreatLevel >= 5 ? Color.FromRgb(255, 140, 0)
            : ThreatLevel >= 4 ? Color.FromRgb(210, 153, 34)
            : Color.FromRgb(139, 148, 158);

        public string TypeIcon => Type == "process" ? "?" : Type == "startup" || Type == "startup_file" ? "??" : "?";

        public string SizeDisplay
        {
            get
            {
                if (FileSize <= 0) return "?";
                if (FileSize < 1024) return FileSize + " B";
                if (FileSize < 1048576) return (FileSize / 1024.0).ToString("F1") + " KB";
                return (FileSize / 1048576.0).ToString("F1") + " MB";
            }
        }
    }

    public class ProcessEntry
    {
        public string ClientId { get; set; } = "";
        public int Pid { get; set; }
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public bool IsProtected { get; set; }
        public bool IsVisible { get; set; }
        public long Memory { get; set; }
        public string Started { get; set; } = "";

        public string MemoryDisplay
        {
            get
            {
                if (Memory <= 0) return "?";
                if (Memory < 1048576) return (Memory / 1024.0).ToString("F0") + " KB";
                return (Memory / 1048576.0).ToString("F1") + " MB";
            }
        }
    }

    public class StartupEntry
    {
        public string ClientId { get; set; } = "";
        public string Root { get; set; } = "";
        public string RegPath { get; set; } = "";
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string FullKey => Root + "|" + RegPath + "|" + Name;
    }

    public class ServiceEntry
    {
        public string ClientId { get; set; } = "";
        public string ServiceName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Status { get; set; } = "";
        public string ImagePath { get; set; } = "";
        public string StartType { get; set; } = "";
    }

    public class AutoCleanEntry
    {
        public string ClientId { get; set; } = "";
        public int Pid { get; set; }
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
    }

    [SupportedOSPlatform("windows")]
    public class BotKillerPluginUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BgColor => C("BackgroundColor");
        private Color SurfaceColor => C("SurfaceColor");
        private Color SurfaceLightColor => C("SurfaceLightColor");
        private Color BorderClr => C("BorderColor");
        private Color TextPrimary => C("TextPrimaryColor");
        private Color TextSecondary => C("TextSecondaryColor");
        private Color AccentBlue => C("PrimaryColor");
        private Color AccentBlueHover => C("PrimaryHoverColor");
        private Color DangerRed => C("DangerColor");
        private Color DangerRedHover => C("DangerHoverColor");
        private Color SuccessGreen => C("SuccessColor");
        private Color WarningYellow => C("WarningColor");
        private Color OrangeColor => C("WarningColor");
        private Color DisabledBg => C("ButtonBgColor");
        private Color ButtonBorderClr => C("ButtonBorderColor");
        private Color ButtonBgClr => C("ButtonBgColor");
        private Color ButtonBgHoverClr => C("ButtonBgHoverColor");
        private Color TabActiveBg => C("PrimaryColor");
        private Color TabInactiveBg => C("SurfaceLightColor");
        private Color TabHoverBg => C("ButtonBgHoverColor");

        private readonly BotKillerPlugin _plugin;
        private readonly ConcurrentDictionary<string, PluginContext> _clients = new();
        private readonly ConcurrentDictionary<string, bool> _readyClients = new();
        private readonly ConcurrentDictionary<string, bool> _selectedClients = new();
        private readonly ConcurrentDictionary<string, bool> _scanningClients = new();

        private readonly ConcurrentDictionary<string, List<ThreatEntry>> _clientThreats = new();
        private readonly ConcurrentDictionary<string, List<AutoCleanEntry>> _clientAutoCleanResults = new();
        private readonly ConcurrentDictionary<string, List<ProcessEntry>> _clientProcesses = new();
        private readonly ConcurrentDictionary<string, List<StartupEntry>> _clientStartups = new();
        private readonly ConcurrentDictionary<string, List<ServiceEntry>> _clientServices = new();

        private readonly TextBlock _statusLabel;
        private readonly ProgressBar _progressBar;
        private readonly TextBlock _progressText;
        private readonly TextBox _logTextBox;
        private readonly StackPanel _clientListPanel;

        private StackPanel _threatListPanel;
        private StackPanel _processListPanel;
        private StackPanel _startupListPanel;
        private StackPanel _serviceListPanel;
        private TextBox _hostsBox;
        private TextBox _analysisResultsBox;
        private TextBlock _dnsText;
        private StackPanel _detailContent;

        private readonly TextBlock _statTotal;
        private readonly TextBlock _statCritical;
        private readonly TextBlock _statHigh;
        private readonly TextBlock _statMedium;
        private readonly TextBlock _statClients;

        private string _threatFilter = "all";
        private string _activeTab = "threats";

        private readonly StackPanel _tabBar;
        private readonly Border _tabContentArea;
        private readonly Dictionary<string, Border> _tabContents = new();
        private readonly Dictionary<string, Button> _tabButtons = new();
        private readonly List<Button> _filterButtons = new();

        private const int MaxLogLength = 20000;
        private const int LogTrimTarget = 15000;

        public BotKillerPluginUI(BotKillerPlugin plugin)
        {
            _plugin = plugin;
            Background = new SolidColorBrush(BgColor);

            var root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(210) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var sidebar = new Border { Background = new SolidColorBrush(SurfaceColor), BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(0, 0, 1, 0) };
            var sideGrid = new Grid();
            sideGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            sideGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            sideGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var sideHeader = new Border { Background = new SolidColorBrush(BgColor), Padding = new Thickness(10, 8, 10, 8) };
            var shStack = new StackPanel { Orientation = Orientation.Horizontal };
            _statClients = Txt("0 clients", 12, TextSecondary, FontWeights.Normal);
            sideHeader.Child = shStack;
            Grid.SetRow(sideHeader, 0); sideGrid.Children.Add(sideHeader);

            var selectPanel = new Border { Padding = new Thickness(8, 4, 8, 4), Background = new SolidColorBrush(SurfaceColor), BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(0, 0, 0, 1) };
            var saRow = new StackPanel { Orientation = Orientation.Horizontal };
            var selectAllBtn = MakeThemedButton("Select All", ButtonBgClr, ButtonBgHoverClr);
            selectAllBtn.Click += (s, e) => SelectAllClients(true);
            saRow.Children.Add(selectAllBtn);
            var deselectAllBtn = MakeThemedButton("None", ButtonBgClr, ButtonBgHoverClr);
            deselectAllBtn.Click += (s, e) => SelectAllClients(false);
            saRow.Children.Add(deselectAllBtn);
            selectPanel.Child = saRow;
            Grid.SetRow(selectPanel, 1); sideGrid.Children.Add(selectPanel);

            var clientScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _clientListPanel = new StackPanel();
            clientScroll.Content = _clientListPanel;
            Grid.SetRow(clientScroll, 2); sideGrid.Children.Add(clientScroll);

            sidebar.Child = sideGrid;
            Grid.SetColumn(sidebar, 0); root.Children.Add(sidebar);

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(130) });

            var toolbar = new Border { Background = new SolidColorBrush(SurfaceColor), BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(10, 6, 10, 6) };
            var tbStack = new StackPanel { Orientation = Orientation.Horizontal };
            _statusLabel = Txt("Select clients ?", 12, TextSecondary, FontWeights.Normal);
            _statusLabel.VerticalAlignment = VerticalAlignment.Center;
            tbStack.Children.Add(_statusLabel); tbStack.Children.Add(Spc(12));

            var autoCleanBtn = MakeThemedButton("Auto Clean", DangerRed, DangerRedHover);
            autoCleanBtn.Click += (s, e) => DoAutoCleanSelected();
            tbStack.Children.Add(autoCleanBtn);

            var scanBtn = MakeThemedButton("Scan", AccentBlue, AccentBlueHover);
            scanBtn.Click += (s, e) => DoScanSelected();
            tbStack.Children.Add(scanBtn);

            var antiBtn = MakeThemedButton("Anti-Analysis", AccentBlue, AccentBlueHover);
            antiBtn.Click += (s, e) => DoAntiAnalysisSelected();
            tbStack.Children.Add(antiBtn);

            tbStack.Children.Add(MakeSeparator());

            var procBtn = MakeThemedButton("Processes", SurfaceLightColor, C("ButtonBgHoverColor"));
            procBtn.Click += (s, e) => SelectTab("processes"); procBtn.Margin = new Thickness(2, 0, 2, 0);
            tbStack.Children.Add(procBtn);

            var startBtn = MakeThemedButton("Startup", SurfaceLightColor, C("ButtonBgHoverColor"));
            startBtn.Click += (s, e) => SelectTab("startup"); startBtn.Margin = new Thickness(2, 0, 2, 0);
            tbStack.Children.Add(startBtn);

            var svcBtn = MakeThemedButton("Services", SurfaceLightColor, C("ButtonBgHoverColor"));
            svcBtn.Click += (s, e) => SelectTab("services"); svcBtn.Margin = new Thickness(2, 0, 2, 0);
            tbStack.Children.Add(svcBtn);

            var netBtn = MakeThemedButton("Network", SurfaceLightColor, C("ButtonBgHoverColor"));
            netBtn.Click += (s, e) => ForEachSelected(cid => { _plugin.RequestCheckHostsFile(cid); _plugin.RequestCheckDNS(cid); Log(cid, "Checking network..."); });
            tbStack.Children.Add(netBtn);

            toolbar.Child = tbStack;
            Grid.SetRow(toolbar, 0); mainGrid.Children.Add(toolbar);

            var statsBorder = new Border { Background = new SolidColorBrush(BgColor), BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(10, 4, 10, 4) };
            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            _statTotal = Txt("Total: 0", 11, TextSecondary, FontWeights.Normal); sp.Children.Add(_statTotal); sp.Children.Add(Spc(14));
            sp.Children.Add(MakeFilterBtn("All", "all"));
            sp.Children.Add(MakeFilterBtn("Critical", "critical"));
            sp.Children.Add(MakeFilterBtn("High", "high"));
            sp.Children.Add(MakeFilterBtn("Medium", "medium"));
            sp.Children.Add(Spc(16));
            _statCritical = Txt("", 11, DangerRed, FontWeights.SemiBold); sp.Children.Add(_statCritical); sp.Children.Add(Spc(10));
            _statHigh = Txt("", 11, OrangeColor, FontWeights.SemiBold); sp.Children.Add(_statHigh); sp.Children.Add(Spc(10));
            _statMedium = Txt("", 11, WarningYellow, FontWeights.SemiBold); sp.Children.Add(_statMedium);
            statsBorder.Child = sp;
            Grid.SetRow(statsBorder, 1); mainGrid.Children.Add(statsBorder);

            var progPanel = new StackPanel { Margin = new Thickness(10, 2, 10, 2) };
            _progressText = Txt("", 11, TextSecondary, FontWeights.Normal); _progressText.Visibility = Visibility.Collapsed;
            progPanel.Children.Add(_progressText);
            _progressBar = new ProgressBar { Height = 3, Minimum = 0, Maximum = 100, Background = new SolidColorBrush(SurfaceLightColor), Foreground = new SolidColorBrush(AccentBlue), Visibility = Visibility.Collapsed, Margin = new Thickness(0, 2, 0, 0) };
            progPanel.Children.Add(_progressBar);
            Grid.SetRow(progPanel, 2); mainGrid.Children.Add(progPanel);

            _tabBar = new StackPanel { Orientation = Orientation.Horizontal, Background = new SolidColorBrush(BgColor), Height = 36 };
            AddTab("threats", "Threats"); AddTab("processes", "Processes"); AddTab("startup", "Startup"); AddTab("services", "Services"); AddTab("network", "Network"); AddTab("analysis", "Analysis");
            var tabBarBorder = new Border { BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(0, 0, 0, 1), Child = _tabBar };
            Grid.SetRow(tabBarBorder, 3); mainGrid.Children.Add(tabBarBorder);

            _tabContentArea = new Border { Background = new SolidColorBrush(BgColor) };
            BuildTabContents();
            _tabContentArea.Child = _tabContents["threats"];
            Grid.SetRow(_tabContentArea, 4); mainGrid.Children.Add(_tabContentArea);

            var logBorder = new Border { Background = new SolidColorBrush(SurfaceColor), BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(0, 1, 0, 0) };
            var logGrid = new Grid();
            logGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            logGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            var logHdr = Txt("Activity Log", 11, TextSecondary, FontWeights.SemiBold);
            logHdr.Margin = new Thickness(10, 3, 10, 2);
            Grid.SetRow(logHdr, 0); logGrid.Children.Add(logHdr);
            _logTextBox = new TextBox
            {
                IsReadOnly = true,
                Background = new SolidColorBrush(SurfaceColor),
                Foreground = new SolidColorBrush(TextSecondary),
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono,Consolas,monospace"),
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(10, 0, 10, 4),
                CaretBrush = Brushes.Transparent
            };
            Grid.SetRow(_logTextBox, 1); logGrid.Children.Add(_logTextBox);
            logBorder.Child = logGrid;
            Grid.SetRow(logBorder, 5); mainGrid.Children.Add(logBorder);

            Grid.SetColumn(mainGrid, 1); root.Children.Add(mainGrid);
            Content = root;
            SelectTab("threats");
        }

        private void BuildTabContents()
        {
            var threatsSplit = new Grid();
            threatsSplit.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            threatsSplit.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(330) });
            var threatScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _threatListPanel = new StackPanel { Margin = new Thickness(6) };
            _threatListPanel.Children.Add(Txt("Select clients and run a scan.", 12, TextSecondary, FontWeights.Normal));
            threatScroll.Content = _threatListPanel;
            Grid.SetColumn(threatScroll, 0); threatsSplit.Children.Add(threatScroll);
            var detailBorder = new Border { Background = new SolidColorBrush(SurfaceColor), BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(1, 0, 0, 0), Padding = new Thickness(10) };
            _detailContent = new StackPanel();
            _detailContent.Children.Add(Txt("Select a threat to inspect", 12, TextSecondary, FontWeights.Normal));
            detailBorder.Child = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _detailContent };
            Grid.SetColumn(detailBorder, 1); threatsSplit.Children.Add(detailBorder);
            _tabContents["threats"] = new Border { Child = threatsSplit };

            var procScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _processListPanel = new StackPanel { Margin = new Thickness(6) };
            _processListPanel.Children.Add(Txt("Click 'Processes' to load.", 12, TextSecondary, FontWeights.Normal));
            procScroll.Content = _processListPanel;
            _tabContents["processes"] = new Border { Child = procScroll };

            var startupScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _startupListPanel = new StackPanel { Margin = new Thickness(6) };
            _startupListPanel.Children.Add(Txt("Click 'Startup' to load.", 12, TextSecondary, FontWeights.Normal));
            startupScroll.Content = _startupListPanel;
            _tabContents["startup"] = new Border { Child = startupScroll };

            var svcScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _serviceListPanel = new StackPanel { Margin = new Thickness(6) };
            _serviceListPanel.Children.Add(Txt("Click 'Services' to load.", 12, TextSecondary, FontWeights.Normal));
            svcScroll.Content = _serviceListPanel;
            _tabContents["services"] = new Border { Child = svcScroll };

            var netPanel = new StackPanel { Margin = new Thickness(10) };
            netPanel.Children.Add(Txt("Hosts File", 13, TextPrimary, FontWeights.SemiBold));
            _hostsBox = new TextBox
            {
                Background = new SolidColorBrush(BgColor),
                Foreground = new SolidColorBrush(TextPrimary),
                BorderBrush = new SolidColorBrush(BorderClr),
                FontFamily = new FontFamily("Cascadia Mono,Consolas,monospace"),
                FontSize = 11,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                AcceptsReturn = true,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                MinHeight = 180,
                Margin = new Thickness(0, 4, 0, 8),
                Text = "Click 'Network' to load.",
                CaretBrush = Brushes.Transparent
            };
            netPanel.Children.Add(_hostsBox);
            var repairBtn = MakeThemedButton("Reset Hosts", WarningYellow, WarningYellow);
            repairBtn.Click += (s, e) =>
            {
                if (MessageBox.Show("Reset hosts file on selected clients?", "Confirm", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                    ForEachSelected(cid => { _plugin.RequestRepairHostsFile(cid); Log(cid, "Repairing hosts..."); });
            };
            netPanel.Children.Add(repairBtn);
            netPanel.Children.Add(Spc(0, 10));
            netPanel.Children.Add(Txt("DNS Settings", 13, TextPrimary, FontWeights.SemiBold));
            _dnsText = Txt("Click 'Network' to load.", 11, TextSecondary, FontWeights.Normal);
            _dnsText.TextWrapping = TextWrapping.Wrap;
            _dnsText.FontFamily = new FontFamily("Cascadia Mono,Consolas,monospace");
            netPanel.Children.Add(_dnsText);
            var netScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = netPanel };
            _tabContents["network"] = new Border { Child = netScroll };

            var analysisPanel = new StackPanel { Margin = new Thickness(10) };
            analysisPanel.Children.Add(Txt("Anti-Analysis Check", 14, TextPrimary, FontWeights.Bold));
            analysisPanel.Children.Add(Spc(0, 6));
            analysisPanel.Children.Add(Txt("Select clients and click 'Anti-Analysis' to run.", 12, TextSecondary, FontWeights.Normal));
            analysisPanel.Children.Add(Spc(0, 6));
            _analysisResultsBox = new TextBox
            {
                Background = new SolidColorBrush(BgColor),
                Foreground = new SolidColorBrush(TextPrimary),
                BorderBrush = new SolidColorBrush(BorderClr),
                FontFamily = new FontFamily("Cascadia Mono,Consolas,monospace"),
                FontSize = 11,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                AcceptsReturn = true,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                MinHeight = 300,
                Margin = new Thickness(0, 4, 0, 8),
                Text = "No results yet.",
                CaretBrush = Brushes.Transparent
            };
            analysisPanel.Children.Add(_analysisResultsBox);
            var analysisScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = analysisPanel };
            _tabContents["analysis"] = new Border { Child = analysisScroll };
        }

        private void AddTab(string id, string label)
        {
            var btn = MakeThemedButton(label, id == _activeTab ? TabActiveBg : TabInactiveBg, TabHoverBg);
            btn.Tag = id;
            btn.Margin = new Thickness(2, 4, 2, 4);
            btn.Padding = new Thickness(14, 4, 14, 4);
            btn.Foreground = new SolidColorBrush(id == _activeTab ? Colors.White : TextSecondary);
            btn.Click += (s, e) => SelectTab(id);
            _tabBar.Children.Add(btn);
            _tabButtons[id] = btn;
        }

        private void SelectTab(string id)
        {
            _activeTab = id;
            foreach (var kvp in _tabButtons)
            {
                bool active = kvp.Key == id;
                kvp.Value.Background = new SolidColorBrush(active ? TabActiveBg : TabInactiveBg);
                kvp.Value.Foreground = new SolidColorBrush(active ? Colors.White : TextSecondary);
            }
            if (_tabContents.TryGetValue(id, out var content)) _tabContentArea.Child = content;
        }

        public void AddClient(string clientId, PluginContext ctx)
        {
            _clients[clientId] = ctx;
            _selectedClients[clientId] = true;
            Dispatcher.BeginInvoke(new Action(RefreshAll));
        }

        public void RemoveClient(string clientId)
        {
            _clients.TryRemove(clientId, out _);
            _readyClients.TryRemove(clientId, out _);
            _selectedClients.TryRemove(clientId, out _);
            _scanningClients.TryRemove(clientId, out _);
            _clientThreats.TryRemove(clientId, out _);
            _clientAutoCleanResults.TryRemove(clientId, out _);
            _clientProcesses.TryRemove(clientId, out _);
            _clientStartups.TryRemove(clientId, out _);
            _clientServices.TryRemove(clientId, out _);
            Dispatcher.BeginInvoke(new Action(() => { RefreshAll(); Log(clientId, "Disconnected"); }));
        }

        private void SelectAllClients(bool select)
        {
            foreach (var cid in _clients.Keys)
            {
                _selectedClients[cid] = select;
            }
            RefreshAll();
        }

        private void RefreshAll()
        {
            RebuildClientList();
            UpdateStatusBar();
            RenderThreats();
            RenderProcesses();
            RenderStartups();
            RenderServices();
            UpdateStats();
        }

        private void RebuildClientList()
        {
            _clientListPanel.Children.Clear();
            foreach (var kvp in _clients)
            {
                string cid = kvp.Key;
                bool ready = _readyClients.ContainsKey(cid);
                bool selected = _selectedClients.TryGetValue(cid, out var sel) && sel;
                bool scanning = _scanningClients.TryGetValue(cid, out var sc) && sc;
                int threatCount = _clientThreats.TryGetValue(cid, out var tl) ? tl.Count : 0;

                var row = new Border
                {
                    Padding = new Thickness(8, 5, 8, 5),
                    Cursor = Cursors.Hand,
                    Background = new SolidColorBrush(selected ? BorderClr : SurfaceColor),
                    BorderBrush = new SolidColorBrush(BorderClr),
                    BorderThickness = new Thickness(0, 0, 0, 1)
                };

                string capturedCid = cid;
                row.MouseEnter += (s, e) => { if (!(_selectedClients.TryGetValue(capturedCid, out var ss) && ss)) row.Background = new SolidColorBrush(SurfaceLightColor); };
                row.MouseLeave += (s, e) => { bool ss2 = _selectedClients.TryGetValue(capturedCid, out var sv) && sv; row.Background = new SolidColorBrush(ss2 ? BorderClr : SurfaceColor); };
                row.MouseLeftButtonDown += (s, e) =>
                {
                    bool cur = _selectedClients.TryGetValue(capturedCid, out var cv) && cv;
                    _selectedClients[capturedCid] = !cur;
                    RefreshAll();
                };

                var stack = new StackPanel();
                var nameRow = new StackPanel { Orientation = Orientation.Horizontal };

                var cb = new CheckBox { IsChecked = selected, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };
                string cbCid = cid;
                cb.Checked += (s, e) => { e.Handled = true; _selectedClients[cbCid] = true; RefreshAll(); };
                cb.Unchecked += (s, e) => { e.Handled = true; _selectedClients[cbCid] = false; RefreshAll(); };
                nameRow.Children.Add(cb);

                nameRow.Children.Add(Txt(ready ? "?" : "?", 10, ready ? SuccessGreen : TextSecondary, FontWeights.Normal));
                nameRow.Children.Add(Spc(4));
                nameRow.Children.Add(Txt(Trunc(cid, 18), 11, TextPrimary, FontWeights.SemiBold));
                stack.Children.Add(nameRow);

                string statusText = scanning ? "Scanning..." : ready ? (threatCount > 0 ? threatCount + " threat(s)" : "Clean") : "Connecting...";
                var statusColor = scanning ? WarningYellow : (threatCount > 0 ? DangerRed : (ready ? SuccessGreen : TextSecondary));
                stack.Children.Add(Txt(statusText, 10, statusColor, FontWeights.Normal));

                row.Child = stack;
                _clientListPanel.Children.Add(row);
            }
        }

        private List<string> GetSelectedReadyClients()
        {
            var list = new List<string>();
            foreach (var kvp in _selectedClients)
            {
                if (kvp.Value && _readyClients.ContainsKey(kvp.Key))
                    list.Add(kvp.Key);
            }
            return list;
        }

        private void ForEachSelected(Action<string> action)
        {
            var clients = GetSelectedReadyClients();
            if (clients.Count == 0) { Log("", "No clients selected"); return; }
            foreach (var cid in clients) action(cid);
        }

        private void UpdateStatusBar()
        {
            var selected = GetSelectedReadyClients();
            _statClients.Text = _clients.Count + " client(s), " + _readyClients.Count + " ready";
            _statusLabel.Text = selected.Count + " selected";
            _statusLabel.Foreground = new SolidColorBrush(selected.Count > 0 ? SuccessGreen : TextSecondary);
        }

        private void DoScanSelected()
        {
            var clients = GetSelectedReadyClients();
            if (clients.Count == 0) { Log("", "No clients selected"); return; }
            ShowProgress("Scanning " + clients.Count + " client(s)...");
            foreach (var cid in clients)
            {
                _scanningClients[cid] = true;
                _clientThreats[cid] = new List<ThreatEntry>();
                _plugin.RequestScan(cid);
                Log(cid, "Scan started");
            }
            RebuildClientList(); RenderThreats(); UpdateStats(); ShowDetail(null);
        }

        private void DoAutoCleanSelected()
        {
            var clients = GetSelectedReadyClients();
            if (clients.Count == 0) { Log("", "No clients selected"); return; }
            if (MessageBox.Show(
                "Auto-clean " + clients.Count + " client(s)?\n\n" +
                "This will automatically kill hidden processes running from suspicious locations, " +
                "remove their registry entries, and delete the files.\n\n" +
                "The bot killer will NEVER touch its own process chain, legitimate Windows processes, " +
                "or files in Program Files / System32.",
                "Auto Clean", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                return;

            ShowProgress("Auto-cleaning " + clients.Count + " client(s)...");
            foreach (var cid in clients)
            {
                _scanningClients[cid] = true;
                _plugin.RequestAutoClean(cid);
                Log(cid, "? Auto-clean started");
            }
            RebuildClientList();
        }

        private void ShowProgress(string text)
        {
            _progressBar.Value = 0;
            _progressBar.Visibility = Visibility.Visible;
            _progressText.Visibility = Visibility.Visible;
            _progressText.Text = text;
        }

        private void HideProgressDelayed()
        {
            _ = Task.Delay(3000).ContinueWith(t => Dispatcher.BeginInvoke(new Action(() =>
            {
                _progressBar.Visibility = Visibility.Collapsed;
                _progressText.Visibility = Visibility.Collapsed;
            })));
        }

        public void OnClientReady(string cid)
        {
            _readyClients[cid] = true;
            Dispatcher.BeginInvoke(new Action(() => { RebuildClientList(); UpdateStatusBar(); Log(cid, "Client ready (self-aware mode)"); }));
        }

        public void OnCommandAck(string cid, byte op, string msg)
        {
            Dispatcher.BeginInvoke(new Action(() => Log(cid, "? " + OpName(op) + (string.IsNullOrEmpty(msg) ? "" : ": " + msg))));
        }

        public void OnCommandError(string cid, byte op, string err)
        {
            Dispatcher.BeginInvoke(new Action(() => Log(cid, "? " + OpName(op) + ": " + err)));
        }

        public void OnScanProgress(string cid, byte pct)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (_selectedClients.TryGetValue(cid, out var sel) && sel)
                {
                    _progressBar.Value = pct;
                    _progressText.Text = "Scanning " + Trunc(cid, 12) + "... " + pct + "%";
                }
            }));
        }

        public void OnScanResult(string cid, string json)
        {
            var threats = ParseThreats(json);
            foreach (var t in threats) t.ClientId = cid;
            _clientThreats[cid] = threats;
            Dispatcher.BeginInvoke(new Action(() =>
            {
                RenderThreats(); UpdateStats(); ShowDetail(null);
                RebuildClientList(); SelectTab("threats");
                Log(cid, "Scan complete: " + threats.Count + " threat(s) found");
            }));
        }

        public void OnScanComplete(string cid, int count)
        {
            _scanningClients.TryRemove(cid, out _);
            Dispatcher.BeginInvoke(new Action(() =>
            {
                RebuildClientList();
                if (!_scanningClients.Any(x => x.Value))
                {
                    _progressBar.Value = 100;
                    _progressText.Text = "Scan complete";
                    HideProgressDelayed();
                }
            }));
        }

        public void OnAutoCleanResult(string cid, string json)
        {
            _scanningClients.TryRemove(cid, out _);
            var removed = ParseAutoCleanResults(json);
            foreach (var r in removed) r.ClientId = cid;
            _clientAutoCleanResults[cid] = removed;
            _clientThreats[cid] = new List<ThreatEntry>();
            Dispatcher.BeginInvoke(new Action(() =>
            {
                RebuildClientList();
                Log(cid, "? Auto-clean complete: removed " + removed.Count + " threat(s)");
                foreach (var r in removed) Log(cid, "  ? Killed & deleted: " + r.Name + " ? " + r.Path);
                if (!_scanningClients.Any(x => x.Value))
                {
                    _progressBar.Value = 100;
                    _progressText.Text = "Auto-clean complete";
                    HideProgressDelayed();
                }
                RenderThreats(); UpdateStats();
            }));
        }

        public void OnThreatRemoved(string cid, string path)
        {
            if (_clientThreats.TryGetValue(cid, out var list))
                list.RemoveAll(t => t.FilePath.Equals(path, StringComparison.OrdinalIgnoreCase));
            Dispatcher.BeginInvoke(new Action(() => { Log(cid, "? Removed: " + path); RefreshAll(); ShowDetail(null); }));
        }

        public void OnFileDeleted(string cid, string path)
        {
            if (_clientThreats.TryGetValue(cid, out var list))
                list.RemoveAll(t => t.FilePath.Equals(path, StringComparison.OrdinalIgnoreCase));
            Dispatcher.BeginInvoke(new Action(() => { Log(cid, "? Deleted: " + path); RefreshAll(); }));
        }

        public void OnProcessList(string cid, string data)
        {
            var entries = new List<ProcessEntry>();
            foreach (var line in data.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var p = line.Trim().Split('|');
                if (p.Length < 7) continue;
                entries.Add(new ProcessEntry
                {
                    ClientId = cid,
                    Pid = int.TryParse(p[0], out var pid) ? pid : 0,
                    Name = p[1],
                    Path = p[2],
                    IsProtected = p[3].Equals("True", StringComparison.OrdinalIgnoreCase),
                    IsVisible = p[4].Equals("True", StringComparison.OrdinalIgnoreCase),
                    Memory = long.TryParse(p[5], out var mem) ? mem : 0,
                    Started = p[6]
                });
            }
            _clientProcesses[cid] = entries;
            Dispatcher.BeginInvoke(new Action(() => { RenderProcesses(); SelectTab("processes"); Log(cid, "Loaded " + entries.Count + " processes"); }));
        }

        public void OnStartupList(string cid, string data)
        {
            var entries = new List<StartupEntry>();
            foreach (var line in data.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var p = line.Trim().Split('|');
                if (p.Length < 4) continue;
                entries.Add(new StartupEntry { ClientId = cid, Root = p[0], RegPath = p[1], Name = p[2], Value = p[3] });
            }
            _clientStartups[cid] = entries;
            Dispatcher.BeginInvoke(new Action(() => { RenderStartups(); SelectTab("startup"); Log(cid, "Loaded " + entries.Count + " startup entries"); }));
        }

        public void OnServiceList(string cid, string data)
        {
            var entries = new List<ServiceEntry>();
            foreach (var line in data.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var p = line.Trim().Split('|');
                if (p.Length < 4) continue;
                entries.Add(new ServiceEntry
                {
                    ClientId = cid,
                    ServiceName = p[0],
                    DisplayName = p[1],
                    Status = p[2],
                    ImagePath = p[3],
                    StartType = p.Length > 4 ? p[4] : ""
                });
            }
            _clientServices[cid] = entries;
            Dispatcher.BeginInvoke(new Action(() => { RenderServices(); SelectTab("services"); Log(cid, "Loaded " + entries.Count + " services"); }));
        }

        public void OnScheduledTasks(string cid, string data)
        {
            Dispatcher.BeginInvoke(new Action(() => Log(cid, "Scheduled tasks received (" + data.Length + " bytes)")));
        }

        public void OnHostsFileResult(string cid, string content)
        {
            Dispatcher.BeginInvoke(new Action(() => { _hostsBox.Text = "[" + Trunc(cid, 12) + "]\n" + content; SelectTab("network"); Log(cid, "Hosts file loaded"); }));
        }

        public void OnDNSResult(string cid, string data)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                var sb = new StringBuilder();
                sb.AppendLine("[" + Trunc(cid, 12) + "]");
                foreach (var line in data.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    sb.AppendLine(line.Trim());
                _dnsText.Text = sb.Length > 0 ? sb.ToString() : "No DNS overrides found.";
                SelectTab("network"); Log(cid, "DNS settings loaded");
            }));
        }

        public void OnAntiAnalysisResult(string cid, string data)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                string existing = _analysisResultsBox.Text;
                if (existing == "No results yet.") existing = "";
                _analysisResultsBox.Text = "[" + Trunc(cid, 12) + "] " + DateTime.Now.ToString("HH:mm:ss") + "\n" + data + "\n" + new string('-', 40) + "\n" + existing;
                SelectTab("analysis");
                Log(cid, "Anti-analysis check complete");
            }));
        }

        private void DoAntiAnalysisSelected()
        {
            var clients = GetSelectedReadyClients();
            if (clients.Count == 0) { Log("", "No clients selected"); return; }
            ShowProgress("Running anti-analysis on " + clients.Count + " client(s)...");
            foreach (var cid in clients)
            {
                _plugin.RequestAntiAnalysis(cid);
                Log(cid, "Anti-analysis requested");
            }
        }

        private void RenderThreats()
        {
            _threatListPanel.Children.Clear();
            var selected = GetSelectedReadyClients();

            var allThreats = new List<ThreatEntry>();
            foreach (var cid in selected)
            {
                if (_clientThreats.TryGetValue(cid, out var list) && list != null)
                    allThreats.AddRange(list);
            }

            if (allThreats.Count == 0)
            {
                var empty = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 40, 0, 0) };
                empty.Children.Add(Txt("?", 36, SuccessGreen, FontWeights.Normal));
                empty.Children.Add(Txt("No threats detected", 16, SuccessGreen, FontWeights.SemiBold));
                empty.Children.Add(Txt(selected.Count == 0 ? "Select clients and run a scan." : "All selected clients are clean.", 12, TextSecondary, FontWeights.Normal));
                _threatListPanel.Children.Add(empty);
                return;
            }

            List<ThreatEntry> filtered;
            if (_threatFilter == "critical") filtered = allThreats.Where(t => t.ThreatLevel >= 8).ToList();
            else if (_threatFilter == "high") filtered = allThreats.Where(t => t.ThreatLevel >= 5 && t.ThreatLevel < 8).ToList();
            else if (_threatFilter == "medium") filtered = allThreats.Where(t => t.ThreatLevel >= 4 && t.ThreatLevel < 5).ToList();
            else filtered = allThreats;

            if (filtered.Count == 0) { _threatListPanel.Children.Add(Txt("No matches for selected filter.", 12, TextSecondary, FontWeights.Normal)); return; }

            if (selected.Count > 1)
            {
                var crossNames = filtered.GroupBy(t => t.ProcessName, StringComparer.OrdinalIgnoreCase)
                    .Where(g => g.Select(x => x.ClientId).Distinct().Count() > 1)
                    .OrderByDescending(g => g.Count()).ToList();

                if (crossNames.Count > 0)
                {
                    var crossBar = new Border { Background = new SolidColorBrush(Color.FromArgb(25, OrangeColor.R, OrangeColor.G, OrangeColor.B)), BorderBrush = new SolidColorBrush(Color.FromArgb(80, OrangeColor.R, OrangeColor.G, OrangeColor.B)), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 0, 6) };
                    var crossStack = new StackPanel();
                    crossStack.Children.Add(Txt("? " + crossNames.Count + " threat(s) found on multiple clients:", 11, OrangeColor, FontWeights.SemiBold));
                    foreach (var cn in crossNames.Take(5))
                    {
                        int cc = cn.Select(x => x.ClientId).Distinct().Count();
                        var cnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(16, 1, 0, 0) };
                        cnRow.Children.Add(Txt("* " + cn.Key + " (" + cc + " clients)", 10, OrangeColor, FontWeights.Normal));
                        var nukeBtn = MakeThemedButton("Nuke All", DangerRed, DangerRedHover);
                        var entries = cn.ToList();
                        nukeBtn.Click += (s, e) =>
                        {
                            if (MessageBox.Show("Full remove '" + cn.Key + "' from " + cc + " client(s)?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                                foreach (var mt in entries) { _plugin.RequestFullRemove(mt.ClientId, mt.FilePath); Log(mt.ClientId, "Nuke ? " + mt.FilePath); }
                        };
                        cnRow.Children.Add(Spc(6)); cnRow.Children.Add(nukeBtn);
                        crossStack.Children.Add(cnRow);
                    }
                    crossBar.Child = crossStack;
                    _threatListPanel.Children.Add(crossBar);
                }
            }

            foreach (var group in filtered.GroupBy(t => t.ClientId).OrderBy(g => g.Key))
            {
                if (selected.Count > 1)
                {
                    var hdr = new Border { Background = new SolidColorBrush(SurfaceLightColor), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 3, 8, 3), Margin = new Thickness(0, 4, 0, 2) };
                    hdr.Child = Txt(Trunc(group.Key, 24) + " - " + group.Count() + " threat(s)", 11, AccentBlue, FontWeights.SemiBold);
                    _threatListPanel.Children.Add(hdr);
                }
                foreach (var t in group.OrderByDescending(x => x.ThreatLevel))
                    _threatListPanel.Children.Add(CreateThreatRow(t));
            }
        }

        private Border CreateThreatRow(ThreatEntry t)
        {
            var row = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(Color.FromArgb(50, t.ThreatColor.R, t.ThreatColor.G, t.ThreatColor.B)),
                BorderThickness = new Thickness(2, 0, 0, 0),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(8, 6, 8, 6),
                Margin = new Thickness(0, 0, 0, 2),
                Cursor = Cursors.Hand
            };
            row.MouseEnter += (s, e) => row.Background = new SolidColorBrush(SurfaceLightColor);
            row.MouseLeave += (s, e) => row.Background = new SolidColorBrush(SurfaceColor);
            row.MouseLeftButtonDown += (s, e) => ShowDetail(t);

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(26) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(65) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            SetC(grid, Txt(t.TypeIcon, 14, TextPrimary, FontWeights.Normal), 0);

            var badge = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(25, t.ThreatColor.R, t.ThreatColor.G, t.ThreatColor.B)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(80, t.ThreatColor.R, t.ThreatColor.G, t.ThreatColor.B)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(4, 1, 4, 1),
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center
            };
            badge.Child = Txt(t.ThreatLevelLabel, 9, t.ThreatColor, FontWeights.Bold);
            SetC(grid, badge, 1);

            var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var nr = new StackPanel { Orientation = Orientation.Horizontal };
            nr.Children.Add(Txt(t.ProcessName, 12, TextPrimary, FontWeights.SemiBold));
            if (t.ProcessId > 0) { nr.Children.Add(Spc(5)); nr.Children.Add(Txt("PID " + t.ProcessId, 10, TextSecondary, FontWeights.Normal)); }
            if (t.IsHidden) { nr.Children.Add(Spc(5)); nr.Children.Add(Txt("??", 10, WarningYellow, FontWeights.Normal)); }
            if (t.AutoRemovable) { nr.Children.Add(Spc(3)); nr.Children.Add(Txt("?", 10, DangerRed, FontWeights.Normal)); }
            info.Children.Add(nr);

            var pt = Txt(t.FilePath, 10, TextSecondary, FontWeights.Normal);
            pt.TextTrimming = TextTrimming.CharacterEllipsis; pt.MaxWidth = 380; pt.ToolTip = t.FilePath;
            info.Children.Add(pt);
            if (t.Reasons.Count > 0)
            {
                var tr = Txt("? " + t.Reasons[0], 10, WarningYellow, FontWeights.Normal);
                tr.TextTrimming = TextTrimming.CharacterEllipsis; tr.MaxWidth = 380;
                info.Children.Add(tr);
            }
            SetC(grid, info, 2);

            var qa = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            string threatCid = t.ClientId;
            if (t.ProcessId > 0) { var qk = MakeThemedButton("Kill", DangerRed, DangerRedHover); qk.Click += (s, e) => { e.Handled = true; _plugin.RequestKillProcess(threatCid, t.ProcessId); Log(threatCid, "Kill ? PID " + t.ProcessId); }; qa.Children.Add(qk); }
            var qd = MakeThemedButton("Nuke", DangerRed, DangerRedHover);
            string threatPath = t.FilePath;
            qd.Click += (s, e) => { e.Handled = true; if (MessageBox.Show("Full remove?\n" + threatPath, "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) { _plugin.RequestFullRemove(threatCid, threatPath); Log(threatCid, "Nuke ? " + threatPath); } };
            qa.Children.Add(qd);
            SetC(grid, qa, 3);

            row.Child = grid;
            return row;
        }

        private void ShowDetail(ThreatEntry t)
        {
            _detailContent.Children.Clear();
            if (t == null) { _detailContent.Children.Add(Txt("Select a threat to inspect", 12, TextSecondary, FontWeights.Normal)); return; }

            var hdr = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            hdr.Children.Add(Txt(t.TypeIcon, 18, TextPrimary, FontWeights.Normal));
            hdr.Children.Add(Spc(5));
            hdr.Children.Add(Txt(t.ProcessName, 15, TextPrimary, FontWeights.Bold));
            _detailContent.Children.Add(hdr);

            var lvl = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(35, t.ThreatColor.R, t.ThreatColor.G, t.ThreatColor.B)),
                BorderBrush = new SolidColorBrush(t.ThreatColor),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(8, 3, 8, 3),
                Margin = new Thickness(0, 0, 0, 8),
                HorizontalAlignment = HorizontalAlignment.Left
            };
            lvl.Child = Txt(t.ThreatLevelLabel + " (Level " + t.ThreatLevel + ")", 12, t.ThreatColor, FontWeights.Bold);
            _detailContent.Children.Add(lvl);

            if (t.AutoRemovable)
            {
                var autoBadge = new Border { Background = new SolidColorBrush(Color.FromArgb(30, DangerRed.R, DangerRed.G, DangerRed.B)), BorderBrush = new SolidColorBrush(DangerRed), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 3, 8, 3), Margin = new Thickness(0, 0, 0, 8), HorizontalAlignment = HorizontalAlignment.Left };
                autoBadge.Child = Txt("? Auto-removable", 11, DangerRed, FontWeights.SemiBold);
                _detailContent.Children.Add(autoBadge);
            }

            AddField("Client", Trunc(t.ClientId, 20));
            AddField("Type", t.Type);
            if (t.ProcessId > 0) AddField("PID", t.ProcessId.ToString());
            AddField("Path", t.FilePath);
            AddField("Hidden", t.IsHidden ? "Yes" : "No");
            if (t.FileSize > 0) AddField("Size", t.SizeDisplay);
            if (!string.IsNullOrEmpty(t.Created)) AddField("Created", t.Created);
            if (!string.IsNullOrEmpty(t.FileHash) && t.FileHash != "ERROR")
            {
                _detailContent.Children.Add(Txt("SHA256:", 10, TextSecondary, FontWeights.SemiBold));
                var ht = Txt(t.FileHash, 9, TextSecondary, FontWeights.Normal);
                ht.FontFamily = new FontFamily("Cascadia Mono,Consolas,monospace");
                ht.TextWrapping = TextWrapping.Wrap;
                _detailContent.Children.Add(ht);
                _detailContent.Children.Add(Spc(0, 4));
            }
            if (!string.IsNullOrEmpty(t.RegistryPath)) AddField("Registry", t.RegistryPath);
            if (!string.IsNullOrEmpty(t.RegistryValue)) AddField("Value", t.RegistryValue);

            _detailContent.Children.Add(Spc(0, 6));
            _detailContent.Children.Add(Txt("Detection Reasons:", 12, TextPrimary, FontWeights.SemiBold));
            foreach (var r in t.Reasons)
            {
                var rr = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(3, 1, 0, 0) };
                rr.Children.Add(Txt("*", 11, WarningYellow, FontWeights.Normal));
                rr.Children.Add(Spc(4));
                rr.Children.Add(Txt(r, 11, WarningYellow, FontWeights.Normal));
                _detailContent.Children.Add(rr);
            }

            _detailContent.Children.Add(Spc(0, 10));
            var ap = new WrapPanel();
            string cid2 = t.ClientId;
            string path2 = t.FilePath;
            int pid2 = t.ProcessId;

            if (pid2 > 0)
            {
                var kb = MakeThemedButton("Kill", DangerRed, DangerRedHover);
                kb.Click += (s, e) => { _plugin.RequestKillProcess(cid2, pid2); Log(cid2, "Kill ? PID " + pid2); };
                ap.Children.Add(kb);
            }

            var db = MakeThemedButton("Delete File", DangerRed, DangerRedHover);
            db.Click += (s, e) => { if (MessageBox.Show("Delete?\n" + path2, "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) { _plugin.RequestDeleteFile(cid2, path2); Log(cid2, "Delete ? " + path2); } };
            ap.Children.Add(db);

            if (pid2 > 0)
            {
                var kd = MakeThemedButton("Kill+Delete", DangerRed, DangerRedHover);
                kd.Click += (s, e) => { if (MessageBox.Show("Kill process & delete file?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) { _plugin.RequestKillAndDelete(cid2, pid2, path2); Log(cid2, "Kill+Del ? PID " + pid2); } };
                ap.Children.Add(kd);
            }

            var qb = MakeThemedButton("Quarantine", WarningYellow, WarningYellow);
            qb.Click += (s, e) => { _plugin.RequestQuarantineFile(cid2, path2); Log(cid2, "Quarantine ? " + path2); };
            ap.Children.Add(qb);

            var fb = MakeThemedButton("Full Remove", DangerRed, DangerRedHover);
            fb.Click += (s, e) => { if (MessageBox.Show("Full remove (kill all instances, clean registry, delete)?\n" + path2, "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) { _plugin.RequestFullRemove(cid2, path2); Log(cid2, "Full remove ? " + path2); } };
            ap.Children.Add(fb);

            _detailContent.Children.Add(ap);

            var selected = GetSelectedReadyClients();
            var sameOnOtherClients = new List<ThreatEntry>();
            foreach (var otherCid in selected)
            {
                if (otherCid == t.ClientId) continue;
                if (_clientThreats.TryGetValue(otherCid, out var otherList))
                    sameOnOtherClients.AddRange(otherList.Where(ot => ot.ProcessName.Equals(t.ProcessName, StringComparison.OrdinalIgnoreCase)));
            }

            if (sameOnOtherClients.Count > 0)
            {
                _detailContent.Children.Add(Spc(0, 12));
                var crossHeader = new Border { Background = new SolidColorBrush(Color.FromArgb(20, OrangeColor.R, OrangeColor.G, OrangeColor.B)), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 4, 8, 4) };
                int totalClients = sameOnOtherClients.Select(x => x.ClientId).Distinct().Count() + 1;
                crossHeader.Child = Txt("Same threat on " + totalClients + " client(s)", 12, OrangeColor, FontWeights.SemiBold);
                _detailContent.Children.Add(crossHeader);

                var allMatching = new List<ThreatEntry> { t };
                allMatching.AddRange(sameOnOtherClients);

                var crossPanel = new WrapPanel { Margin = new Thickness(0, 4, 0, 0) };
                var nukeAllCross = MakeThemedButton("Nuke All Instances", DangerRed, DangerRedHover);
                nukeAllCross.Click += (s, e) =>
                {
                    if (MessageBox.Show("Full remove '" + t.ProcessName + "' from ALL " + totalClients + " client(s)?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                        foreach (var mt in allMatching) { _plugin.RequestFullRemove(mt.ClientId, mt.FilePath); Log(mt.ClientId, "Nuke ? " + mt.FilePath); }
                };
                crossPanel.Children.Add(nukeAllCross);
                _detailContent.Children.Add(crossPanel);

                foreach (var mt in allMatching)
                {
                    var cr = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4, 1, 0, 0) };
                    cr.Children.Add(Txt("*", 10, TextSecondary, FontWeights.Normal));
                    cr.Children.Add(Spc(4));
                    cr.Children.Add(Txt(Trunc(mt.ClientId, 16), 10, AccentBlue, FontWeights.Normal));
                    if (mt.ProcessId > 0) { cr.Children.Add(Spc(4)); cr.Children.Add(Txt("PID " + mt.ProcessId, 10, TextSecondary, FontWeights.Normal)); }
                    _detailContent.Children.Add(cr);
                }
            }
        }

        private void RenderProcesses()
        {
            _processListPanel.Children.Clear();
            var selected = GetSelectedReadyClients();
            var all = new List<ProcessEntry>();
            foreach (var cid in selected)
                if (_clientProcesses.TryGetValue(cid, out var list) && list != null) all.AddRange(list);

            if (all.Count == 0)
            {
                _processListPanel.Children.Add(Txt("Click 'Processes' to load from selected clients.", 12, TextSecondary, FontWeights.Normal));
                return;
            }

            var batchBar = new Border { Background = new SolidColorBrush(SurfaceLightColor), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 0, 4), CornerRadius = new CornerRadius(4) };
            batchBar.Child = Txt(all.Count + " processes across " + selected.Count + " client(s)", 11, TextSecondary, FontWeights.Normal);
            _processListPanel.Children.Add(batchBar);
            _processListPanel.Children.Add(MakeProcessHeaderRow());

            var grouped = all.GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).ThenBy(g => g.Key);
            foreach (var group in grouped)
            {
                int clientCount = group.Select(p => p.ClientId).Distinct().Count();
                if ((clientCount > 1 || selected.Count > 1) && !group.First().IsProtected)
                {
                    var gh = new Border { Background = new SolidColorBrush(SurfaceLightColor), Padding = new Thickness(8, 3, 8, 3), Margin = new Thickness(0, 4, 0, 1), CornerRadius = new CornerRadius(3) };
                    var ghRow = new DockPanel();
                    var ghActions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    string gn = group.Key;
                    var ge = group.ToList();

                    var killAllBtn = MakeThemedButton("Kill All (" + clientCount + ")", DangerRed, DangerRedHover);
                    killAllBtn.Click += (s, e) =>
                    {
                        if (MessageBox.Show("Kill '" + gn + "' on " + clientCount + " client(s)?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                            foreach (var proc in ge.Where(pp => !pp.IsProtected)) { _plugin.RequestKillProcess(proc.ClientId, proc.Pid); Log(proc.ClientId, "Kill ? " + proc.Name + " PID " + proc.Pid); }
                    };
                    ghActions.Children.Add(killAllBtn);

                    if (ge.Any(pp => !string.IsNullOrEmpty(pp.Path) && !pp.IsProtected))
                    {
                        var nukeBtn = MakeThemedButton("K+D All", OrangeColor, OrangeColor);
                        nukeBtn.Click += (s, e) =>
                        {
                            if (MessageBox.Show("Kill & Delete '" + gn + "' on " + clientCount + " client(s)?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                                foreach (var proc in ge.Where(pp => !pp.IsProtected && !string.IsNullOrEmpty(pp.Path))) { _plugin.RequestKillAndDelete(proc.ClientId, proc.Pid, proc.Path); Log(proc.ClientId, "K+D ? " + proc.Name); }
                        };
                        ghActions.Children.Add(nukeBtn);
                    }

                    DockPanel.SetDock(ghActions, Dock.Right); ghRow.Children.Add(ghActions);
                    var ghInfo = new StackPanel { Orientation = Orientation.Horizontal };
                    ghInfo.Children.Add(Txt(gn, 11, AccentBlue, FontWeights.SemiBold));
                    ghInfo.Children.Add(Spc(6));
                    ghInfo.Children.Add(Txt("*" + group.Count() + " on " + clientCount + " client(s)", 10, TextSecondary, FontWeights.Normal));
                    ghRow.Children.Add(ghInfo);
                    gh.Child = ghRow;
                    _processListPanel.Children.Add(gh);
                }

                int idx = 0;
                foreach (var entry in group.OrderBy(p => p.ClientId))
                {
                    _processListPanel.Children.Add(CreateProcessRow(entry, idx, selected.Count > 1));
                    idx++;
                }
            }
        }

        private void RenderStartups()
        {
            _startupListPanel.Children.Clear();
            var selected = GetSelectedReadyClients();
            var all = new List<StartupEntry>();
            foreach (var cid in selected)
                if (_clientStartups.TryGetValue(cid, out var list) && list != null) all.AddRange(list);

            if (all.Count == 0)
            {
                _startupListPanel.Children.Add(Txt("Click 'Startup' to load from selected clients.", 12, TextSecondary, FontWeights.Normal));
                return;
            }

            var batchBar = new Border { Background = new SolidColorBrush(SurfaceLightColor), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 0, 4), CornerRadius = new CornerRadius(4) };
            batchBar.Child = Txt(all.Count + " entries across " + selected.Count + " client(s)", 11, TextSecondary, FontWeights.Normal);
            _startupListPanel.Children.Add(batchBar);

            var grouped = all.GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).ThenBy(g => g.Key);
            foreach (var group in grouped)
            {
                int clientCount = group.Select(s => s.ClientId).Distinct().Count();
                if (clientCount > 1 || selected.Count > 1)
                {
                    var gh = new Border { Background = new SolidColorBrush(SurfaceLightColor), Padding = new Thickness(8, 3, 8, 3), Margin = new Thickness(0, 4, 0, 1), CornerRadius = new CornerRadius(3) };
                    var ghRow = new DockPanel();
                    var ghActions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    string gn = group.Key;
                    var ge = group.ToList();

                    var removeAllBtn = MakeThemedButton("Remove All (" + clientCount + ")", DangerRed, DangerRedHover);
                    removeAllBtn.Click += (s, e) =>
                    {
                        if (MessageBox.Show("Remove '" + gn + "' from " + clientCount + " client(s)?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                            foreach (var entry in ge) { _plugin.RequestRemoveStartupEntry(entry.ClientId, entry.FullKey); Log(entry.ClientId, "Remove ? " + entry.Name); }
                    };
                    ghActions.Children.Add(removeAllBtn);

                    DockPanel.SetDock(ghActions, Dock.Right); ghRow.Children.Add(ghActions);
                    var ghInfo = new StackPanel { Orientation = Orientation.Horizontal };
                    ghInfo.Children.Add(Txt(gn, 11, AccentBlue, FontWeights.SemiBold));
                    ghInfo.Children.Add(Spc(6));
                    ghInfo.Children.Add(Txt("*" + group.Count() + " on " + clientCount + " client(s)", 10, TextSecondary, FontWeights.Normal));
                    ghRow.Children.Add(ghInfo);
                    gh.Child = ghRow;
                    _startupListPanel.Children.Add(gh);
                }

                int idx = 0;
                foreach (var entry in group.OrderBy(s => s.ClientId))
                {
                    var bg = idx % 2 == 0 ? SurfaceColor : SurfaceColor;
                    var row = new Border { Background = new SolidColorBrush(bg), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 0, 1) };
                    var dock = new DockPanel();
                    var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    var rmBtn = MakeThemedButton("Remove", DangerRed, DangerRedHover);
                    string key = entry.FullKey; string eCid = entry.ClientId; string eName = entry.Name;
                    rmBtn.Click += (s, ev) => { if (MessageBox.Show("Remove '" + eName + "'?", "Confirm", MessageBoxButton.YesNo) == MessageBoxResult.Yes) { _plugin.RequestRemoveStartupEntry(eCid, key); Log(eCid, "Remove ? " + eName); } };
                    actions.Children.Add(rmBtn);
                    DockPanel.SetDock(actions, Dock.Right); dock.Children.Add(actions);
                    var info = new StackPanel();
                    var nr = new StackPanel { Orientation = Orientation.Horizontal };
                    if (selected.Count > 1) { nr.Children.Add(Txt("[" + Trunc(entry.ClientId, 10) + "]", 9, AccentBlue, FontWeights.Normal)); nr.Children.Add(Spc(4)); }
                    nr.Children.Add(Txt("[" + entry.Root + "]", 10, TextSecondary, FontWeights.Normal));
                    nr.Children.Add(Spc(4));
                    nr.Children.Add(Txt(entry.Name, 11, TextPrimary, FontWeights.SemiBold));
                    info.Children.Add(nr);
                    var vt = Txt(entry.Value, 10, TextSecondary, FontWeights.Normal); vt.TextTrimming = TextTrimming.CharacterEllipsis; vt.ToolTip = entry.Value;
                    info.Children.Add(vt);
                    dock.Children.Add(info); row.Child = dock;
                    _startupListPanel.Children.Add(row);
                    idx++;
                }
            }
        }

        private void RenderServices()
        {
            _serviceListPanel.Children.Clear();
            var selected = GetSelectedReadyClients();
            var all = new List<ServiceEntry>();
            foreach (var cid in selected)
                if (_clientServices.TryGetValue(cid, out var list) && list != null) all.AddRange(list);

            if (all.Count == 0)
            {
                _serviceListPanel.Children.Add(Txt("Click 'Services' to load from selected clients.", 12, TextSecondary, FontWeights.Normal));
                return;
            }

            var batchBar = new Border { Background = new SolidColorBrush(SurfaceLightColor), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 0, 4), CornerRadius = new CornerRadius(4) };
            batchBar.Child = Txt(all.Count + " services across " + selected.Count + " client(s)", 11, TextSecondary, FontWeights.Normal);
            _serviceListPanel.Children.Add(batchBar);

            var grouped = all.GroupBy(s => s.ServiceName, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).ThenBy(g => g.Key);
            foreach (var group in grouped)
            {
                int clientCount = group.Select(s => s.ClientId).Distinct().Count();
                if (clientCount > 1 || selected.Count > 1)
                {
                    var gh = new Border { Background = new SolidColorBrush(SurfaceLightColor), Padding = new Thickness(8, 3, 8, 3), Margin = new Thickness(0, 4, 0, 1), CornerRadius = new CornerRadius(3) };
                    var ghRow = new DockPanel();
                    var ghActions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    string gsn = group.Key; var ge = group.ToList();

                    var stopAllBtn = MakeThemedButton("Stop All (" + clientCount + ")", WarningYellow, WarningYellow);
                    stopAllBtn.Click += (s, e) => { foreach (var svc in ge) { _plugin.RequestStopService(svc.ClientId, svc.ServiceName); Log(svc.ClientId, "Stop ? " + svc.ServiceName); } };
                    ghActions.Children.Add(stopAllBtn);

                    var delAllBtn = MakeThemedButton("Delete All (" + clientCount + ")", DangerRed, DangerRedHover);
                    delAllBtn.Click += (s, e) =>
                    {
                        if (MessageBox.Show("Delete '" + gsn + "' from " + clientCount + " client(s)?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                            foreach (var svc in ge) { _plugin.RequestDeleteService(svc.ClientId, svc.ServiceName); Log(svc.ClientId, "Delete svc ? " + svc.ServiceName); }
                    };
                    ghActions.Children.Add(delAllBtn);

                    DockPanel.SetDock(ghActions, Dock.Right); ghRow.Children.Add(ghActions);
                    var ghInfo = new StackPanel { Orientation = Orientation.Horizontal };
                    ghInfo.Children.Add(Txt(group.Key, 11, AccentBlue, FontWeights.SemiBold));
                    ghInfo.Children.Add(Spc(6));
                    ghInfo.Children.Add(Txt("*" + group.Count() + " on " + clientCount + " client(s)", 10, TextSecondary, FontWeights.Normal));
                    ghRow.Children.Add(ghInfo);
                    gh.Child = ghRow;
                    _serviceListPanel.Children.Add(gh);
                }

                int idx = 0;
                foreach (var entry in group.OrderBy(s => s.ClientId))
                {
                    var bg = SurfaceColor;
                    var row = new Border { Background = new SolidColorBrush(bg), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 0, 1) };
                    var dock = new DockPanel();
                    var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    string sn = entry.ServiceName; string sCid = entry.ClientId;
                    var stopBtn = MakeThemedButton("Stop", WarningYellow, WarningYellow);
                    stopBtn.Click += (s, ev) => { _plugin.RequestStopService(sCid, sn); Log(sCid, "Stop ? " + sn); };
                    actions.Children.Add(stopBtn);
                    var delBtn = MakeThemedButton("Delete", DangerRed, DangerRedHover);
                    delBtn.Click += (s, ev) => { if (MessageBox.Show("Delete '" + sn + "'?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) { _plugin.RequestDeleteService(sCid, sn); Log(sCid, "Delete svc ? " + sn); } };
                    actions.Children.Add(delBtn);
                    DockPanel.SetDock(actions, Dock.Right); dock.Children.Add(actions);
                    var info = new StackPanel();
                    var statusClr = entry.Status.Contains("Running", StringComparison.OrdinalIgnoreCase) ? SuccessGreen
                        : entry.Status.Contains("Stopped", StringComparison.OrdinalIgnoreCase) ? TextSecondary : WarningYellow;
                    var hr = new StackPanel { Orientation = Orientation.Horizontal };
                    if (selected.Count > 1) { hr.Children.Add(Txt("[" + Trunc(entry.ClientId, 10) + "]", 9, AccentBlue, FontWeights.Normal)); hr.Children.Add(Spc(4)); }
                    hr.Children.Add(Txt("[" + entry.Status + "]", 10, statusClr, FontWeights.SemiBold));
                    hr.Children.Add(Spc(5));
                    hr.Children.Add(Txt(entry.DisplayName, 11, TextPrimary, FontWeights.SemiBold));
                    hr.Children.Add(Spc(5));
                    hr.Children.Add(Txt("(" + sn + ")", 10, TextSecondary, FontWeights.Normal));
                    info.Children.Add(hr);
                    var it = Txt(entry.ImagePath, 10, TextSecondary, FontWeights.Normal); it.TextTrimming = TextTrimming.CharacterEllipsis; it.ToolTip = entry.ImagePath;
                    info.Children.Add(it);
                    dock.Children.Add(info); row.Child = dock;
                    _serviceListPanel.Children.Add(row);
                    idx++;
                }
            }
        }

        private void UpdateStats()
        {
            var selected = GetSelectedReadyClients();
            var allThreats = new List<ThreatEntry>();
            foreach (var cid in selected)
                if (_clientThreats.TryGetValue(cid, out var list) && list != null) allThreats.AddRange(list);

            _statTotal.Text = "Total: " + allThreats.Count;
            int crit = allThreats.Count(t => t.ThreatLevel >= 8);
            int high = allThreats.Count(t => t.ThreatLevel >= 5 && t.ThreatLevel < 8);
            int med = allThreats.Count(t => t.ThreatLevel >= 4 && t.ThreatLevel < 5);
            _statCritical.Text = crit > 0 ? "Critical: " + crit : "";
            _statHigh.Text = high > 0 ? "High: " + high : "";
            _statMedium.Text = med > 0 ? "Medium: " + med : "";
        }

        private void AddField(string label, string value)
        {
            var row = new DockPanel { Margin = new Thickness(0, 1, 0, 1) };
            var l = Txt(label + ":", 11, TextSecondary, FontWeights.SemiBold); l.Width = 65;
            DockPanel.SetDock(l, Dock.Left); row.Children.Add(l);
            var v = Txt(value, 11, TextPrimary, FontWeights.Normal); v.TextWrapping = TextWrapping.Wrap; v.TextTrimming = TextTrimming.CharacterEllipsis; v.ToolTip = value;
            row.Children.Add(v);
            _detailContent.Children.Add(row);
        }

        private Border MakeProcessHeaderRow()
        {
            var border = new Border { Background = new SolidColorBrush(SurfaceLightColor), BorderBrush = new SolidColorBrush(BorderClr), BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8, 3, 8, 3) };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(55) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(50) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
            SetC(grid, Txt("PID", 10, TextSecondary, FontWeights.Bold), 0);
            SetC(grid, Txt("Name", 10, TextSecondary, FontWeights.Bold), 1);
            SetC(grid, Txt("Path", 10, TextSecondary, FontWeights.Bold), 2);
            SetC(grid, Txt("Mem", 10, TextSecondary, FontWeights.Bold), 3);
            SetC(grid, Txt("", 10, TextSecondary, FontWeights.Bold), 4);
            SetC(grid, Txt("Actions", 10, TextSecondary, FontWeights.Bold), 5);
            border.Child = grid; return border;
        }

        private Border CreateProcessRow(ProcessEntry e, int idx, bool showClientId)
        {
            var row = new Border { Background = new SolidColorBrush(SurfaceColor), Padding = new Thickness(8, 2, 8, 2) };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(55) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(50) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });

            var pidPanel = new StackPanel();
            pidPanel.Children.Add(Txt(e.Pid.ToString(), 11, TextSecondary, FontWeights.Normal));
            if (showClientId) pidPanel.Children.Add(Txt(Trunc(e.ClientId, 8), 8, AccentBlue, FontWeights.Normal));
            SetC(grid, pidPanel, 0);

            var nc = e.IsProtected ? SuccessGreen : TextPrimary;
            SetC(grid, Txt(e.Name, 11, nc, FontWeights.SemiBold), 1);
            var pt = Txt(e.Path, 10, TextSecondary, FontWeights.Normal); pt.TextTrimming = TextTrimming.CharacterEllipsis; pt.ToolTip = e.Path;
            SetC(grid, pt, 2);
            SetC(grid, Txt(e.MemoryDisplay, 10, TextSecondary, FontWeights.Normal), 3);
            SetC(grid, Txt(e.IsProtected ? "Protected" : e.IsVisible ? "Visible" : "Hidden", 11, TextPrimary, FontWeights.Normal), 4);

            if (!e.IsProtected)
            {
                var acts = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                string pCid = e.ClientId; int pPid = e.Pid; string pPath = e.Path;
                var kb = MakeThemedButton("Kill", DangerRed, DangerRedHover);
                kb.Click += (s, ev) => { _plugin.RequestKillProcess(pCid, pPid); Log(pCid, "Kill ? PID " + pPid); };
                acts.Children.Add(kb);
                if (!string.IsNullOrEmpty(pPath))
                {
                    var dbtn = MakeThemedButton("K+D", OrangeColor, OrangeColor);
                    dbtn.Click += (s, ev) => { if (MessageBox.Show("Kill & delete?", "Confirm", MessageBoxButton.YesNo) == MessageBoxResult.Yes) { _plugin.RequestKillAndDelete(pCid, pPid, pPath); Log(pCid, "K+D ? " + pPid); } };
                    acts.Children.Add(dbtn);
                }
                SetC(grid, acts, 5);
            }
            else SetC(grid, Txt("Protected", 10, SuccessGreen, FontWeights.Normal), 5);

            row.Child = grid; return row;
        }

        private List<ThreatEntry> ParseThreats(string json)
        {
            var list = new List<ThreatEntry>();
            try
            {
                json = json.Trim();
                if (!json.StartsWith("[")) return list;
                int pos = 1;
                while (pos < json.Length)
                {
                    int os = json.IndexOf('{', pos); if (os < 0) break;
                    int depth = 0; int oe = os;
                    for (int i = os; i < json.Length; i++)
                    {
                        if (json[i] == '{') depth++;
                        else if (json[i] == '}') { depth--; if (depth == 0) { oe = i; break; } }
                    }
                    string obj = json.Substring(os, oe - os + 1);
                    var t = new ThreatEntry
                    {
                        ProcessId = JInt(obj, "pid"),
                        ProcessName = JStr(obj, "name"),
                        FilePath = JStr(obj, "path"),
                        ThreatLevel = JInt(obj, "level"),
                        FileHash = JStr(obj, "hash"),
                        FileSize = JLong(obj, "size"),
                        Created = JStr(obj, "created"),
                        Type = JStr(obj, "type"),
                        RegistryPath = JStr(obj, "registry"),
                        RegistryValue = JStr(obj, "regValue"),
                        IsHidden = JBool(obj, "hidden"),
                        AutoRemovable = JBool(obj, "autoRemovable"),
                        Reasons = JStrArr(obj, "reasons")
                    };
                    if (!string.IsNullOrEmpty(t.ProcessName)) list.Add(t);
                    pos = oe + 1;
                }
            }
            catch (Exception ex) { Log("", "Parse error: " + ex.Message); }
            return list;
        }

        private List<AutoCleanEntry> ParseAutoCleanResults(string json)
        {
            var list = new List<AutoCleanEntry>();
            try
            {
                json = json.Trim();
                if (!json.StartsWith("[")) return list;
                int pos = 1;
                while (pos < json.Length)
                {
                    int os = json.IndexOf('{', pos); if (os < 0) break;
                    int depth = 0; int oe = os;
                    for (int i = os; i < json.Length; i++)
                    {
                        if (json[i] == '{') depth++;
                        else if (json[i] == '}') { depth--; if (depth == 0) { oe = i; break; } }
                    }
                    string obj = json.Substring(os, oe - os + 1);
                    var e = new AutoCleanEntry { Pid = JInt(obj, "pid"), Name = JStr(obj, "name"), Path = JStr(obj, "path") };
                    if (!string.IsNullOrEmpty(e.Name)) list.Add(e);
                    pos = oe + 1;
                }
            }
            catch { }
            return list;
        }

        private static int JInt(string j, string k) { var m = Regex.Match(j, "\"" + k + "\"\\s*:\\s*(-?\\d+)"); return m.Success && int.TryParse(m.Groups[1].Value, out var v) ? v : 0; }
        private static long JLong(string j, string k) { var m = Regex.Match(j, "\"" + k + "\"\\s*:\\s*(-?\\d+)"); return m.Success && long.TryParse(m.Groups[1].Value, out var v) ? v : 0; }
        private static string JStr(string j, string k) { var m = Regex.Match(j, "\"" + k + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\""); return m.Success ? m.Groups[1].Value.Replace("\\\"", "\"").Replace("\\\\", "\\") : ""; }
        private static bool JBool(string j, string k) { var m = Regex.Match(j, "\"" + k + "\"\\s*:\\s*(true|false)"); return m.Success && m.Groups[1].Value == "true"; }
        private static List<string> JStrArr(string j, string k)
        {
            var r = new List<string>();
            var m = Regex.Match(j, "\"" + k + "\"\\s*:\\s*\\[(.*?)\\]", RegexOptions.Singleline);
            if (m.Success)
                foreach (Match sm in Regex.Matches(m.Groups[1].Value, "\"((?:[^\"\\\\]|\\\\.)*)\""))
                    r.Add(sm.Groups[1].Value.Replace("\\\"", "\"").Replace("\\\\", "\\"));
            return r;
        }

        private void Log(string cid, string msg)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                string prefix = string.IsNullOrEmpty(cid) ? "" : "[" + Trunc(cid, 10) + "] ";
                _logTextBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + prefix + msg + "\n");
                if (_logTextBox.Text.Length > MaxLogLength)
                {
                    int removeUpTo = _logTextBox.Text.Length - LogTrimTarget;
                    int nl = _logTextBox.Text.IndexOf('\n', removeUpTo);
                    if (nl >= 0 && nl < _logTextBox.Text.Length - 1) removeUpTo = nl + 1;
                    _logTextBox.Select(0, removeUpTo);
                    _logTextBox.SelectedText = "";
                    _logTextBox.Select(_logTextBox.Text.Length, 0);
                }
                _logTextBox.ScrollToEnd();
            }));
        }

        private static string OpName(byte op) => op switch
        {
            0x01 => "Scan",
            0x02 => "Kill",
            0x03 => "Remove",
            0x05 => "Processes",
            0x06 => "Startup",
            0x07 => "Tasks",
            0x08 => "RmStartup",
            0x09 => "Quarantine",
            0x0A => "Hosts",
            0x0B => "RepairHosts",
            0x0C => "DNS",
            0x0D => "Services",
            0x0E => "StopSvc",
            0x0F => "DelSvc",
            0x10 => "DelFile",
            0x11 => "Kill+Del",
            0x12 => "FullRemove",
            0x13 => "AutoClean",
            _ => "0x" + op.ToString("X2")
        };

        private static string Trunc(string s, int max = 16) => string.IsNullOrEmpty(s) ? "" : s.Length <= max ? s : s.Substring(0, max) + "..";
        private static void SetC(Grid g, UIElement el, int col) { Grid.SetColumn(el, col); g.Children.Add(el); }
        private TextBlock Txt(string text, double size, Color color, FontWeight weight) => new TextBlock { Text = text, FontSize = size, Foreground = new SolidColorBrush(color), FontWeight = weight, VerticalAlignment = VerticalAlignment.Center };
        private static FrameworkElement Spc(double w = 0, double h = 0) => new Border { Width = w > 0 ? w : double.NaN, Height = h > 0 ? h : double.NaN };

        private Button MakeFilterBtn(string text, string filter)
        {
            var btn = new Button
            {
                Content = text,
                Background = new SolidColorBrush(_threatFilter == filter ? AccentBlue : ButtonBgClr),
                Foreground = new SolidColorBrush(TextPrimary),
                Cursor = Cursors.Hand,
                Margin = new Thickness(2, 0, 2, 0),
                Padding = new Thickness(8, 2, 8, 2),
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                BorderThickness = new Thickness(1),
                BorderBrush = new SolidColorBrush(ButtonBorderClr),
                Tag = filter
            };
            var style = new Style(typeof(Button));
            var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hoverTrigger.Setters.Add(new Setter(Button.BackgroundProperty, new SolidColorBrush(ButtonBgHoverClr)));
            style.Triggers.Add(hoverTrigger);
            btn.Style = style;
            btn.Click += (s, e) =>
            {
                _threatFilter = filter;
                UpdateFilterButtonVisuals();
                RenderThreats();
            };
            _filterButtons.Add(btn);
            return btn;
        }

        private void UpdateFilterButtonVisuals()
        {
            foreach (var fb in _filterButtons)
            {
                var filter = (string)fb.Tag;
                fb.Background = new SolidColorBrush(filter == _threatFilter ? AccentBlue : ButtonBgClr);
            }
        }

        private Button MakeThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var normalBrush = new SolidColorBrush(normalBg);
            var hoverBrush = new SolidColorBrush(hoverBg);
            var borderBrush = new SolidColorBrush(C("ButtonBorderColor"));
            var disabledBg = new SolidColorBrush(C("ButtonBgColor"));

            var template = new ControlTemplate(typeof(Button));
            var border = new FrameworkElementFactory(typeof(Border), "bd");
            border.SetValue(Border.BackgroundProperty, normalBrush);
            border.SetValue(Border.BorderBrushProperty, borderBrush);
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            border.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            border.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(cp);
            template.VisualTree = border;

            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Border.BackgroundProperty, hoverBrush, "bd"));
            template.Triggers.Add(hover);

            var pressed = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true };
            pressed.Setters.Add(new Setter(Border.BackgroundProperty, hoverBrush, "bd"));
            pressed.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd"));
            template.Triggers.Add(pressed);

            var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabled.Setters.Add(new Setter(Border.BackgroundProperty, disabledBg, "bd"));
            disabled.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp"));
            template.Triggers.Add(disabled);

            return new Button
            {
                Content = text,
                Template = template,
                Foreground = new SolidColorBrush(C("TextPrimaryColor")),
                Cursor = Cursors.Hand,
                Margin = new Thickness(2),
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
        }

        private Border MakeSeparator()
        {
            return new Border
            {
                Width = 1,
                Background = new SolidColorBrush(C("ButtonBorderColor")),
                Margin = new Thickness(4, 2, 4, 2)
            };
        }

        public void Dispose() { }
    }
}