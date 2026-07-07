// File: Plugins/Builtin/ProcessManagerPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class ProcessManagerPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, ProcessManagerUI> _clientUIs = new();

        public string PluginId => "procmgr";
        public string DisplayName => "Process Manager";
        public string Version => "1.0.0";
        public string Description => "Remote process manager with tree view, kill, and auto-refresh.";

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
            return Task.CompletedTask;
        }

        public string GetClientCode()
        {
            return @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_procmgr
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private bool _paused = false;
        private int _refreshIntervalMs = 2000;

        [DllImport(""kernel32.dll"", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport(""kernel32.dll"", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport(""kernel32.dll"", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport(""kernel32.dll"", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        private Dictionary<string, string> windowsProcessPaths = new Dictionary<string, string>()
        {
            { ""svchost.exe"", @""C:\Windows\System32\svchost.exe"" },
            { ""explorer.exe"", @""C:\Windows\explorer.exe"" },
            { ""taskhost.exe"", @""C:\Windows\system32\taskhost.exe"" },
            { ""services.exe"", @""C:\Windows\System32\services.exe"" },
            { ""lsass.exe"", @""C:\Windows\System32\lsass.exe"" },
            { ""wininit.exe"", @""C:\Windows\System32\wininit.exe"" },
            { ""csrss.exe"", @""C:\Windows\System32\csrss.exe"" },
            { ""smss.exe"", @""C:\Windows\System32\smss.exe"" },
            { ""spoolsv.exe"", @""C:\Windows\System32\spoolsv.exe"" },
            { ""winlogon.exe"", @""C:\Windows\System32\winlogon.exe"" },
            { ""dwm.exe"", @""C:\Windows\System32\dwm.exe"" },
            { ""taskeng.exe"", @""C:\Windows\System32\taskeng.exe"" },
            { ""logonui.exe"", @""C:\Windows\System32\logonui.exe"" },
            { ""ctfmon.exe"", @""C:\Windows\System32\ctfmon.exe"" },
            { ""cmd.exe"", @""C:\Windows\System32\cmd.exe"" },
            { ""wmiprvse.exe"", @""C:\Windows\System32\wbem\wmiprvse.exe"" },
            { ""notepad.exe"", @""C:\Windows\System32\notepad.exe"" },
            { ""regedit.exe"", @""C:\Windows\regedit.exe"" },
            { ""mspaint.exe"", @""C:\Windows\System32\mspaint.exe"" },
            { ""mstsc.exe"", @""C:\Windows\System32\mstsc.exe"" }
        };

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            await _send(new byte[] { 0x01 });

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

            var sendTask = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    if (!_paused)
                    {
                        try
                        {
                            byte[] processData = CollectProcessData();
                            if (processData != null && processData.Length > 0)
                            {
                                byte[] msg = new byte[processData.Length + 1];
                                msg[0] = 0x10;
                                Buffer.BlockCopy(processData, 0, msg, 1, processData.Length);
                                await _send(msg);
                            }
                        }
                        catch { }
                    }
                    for (int i = 0; i < _refreshIntervalMs / 100; i++)
                    {
                        if (_cts.IsCancellationRequested) break;
                        Thread.Sleep(100);
                    }
                }
            });

            await Task.WhenAny(recvTask, sendTask);
            _cts.Cancel();
        }

        private async Task HandleCommand(byte[] data)
        {
            if (data.Length < 1) return;
            byte cmd = data[0];
            switch (cmd)
            {
                case 0x01:
                    _paused = true;
                    await SendAck(""Paused"");
                    break;
                case 0x02:
                    _paused = false;
                    await SendAck(""Resumed"");
                    break;
                case 0x03:
                    if (data.Length >= 5)
                    {
                        int pid = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        await KillProcess(pid);
                        await SendRefresh();
                    }
                    break;
                case 0x04:
                    if (data.Length >= 5)
                    {
                        int interval = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        if (interval >= 500 && interval <= 30000)
                            _refreshIntervalMs = interval;
                    }
                    break;
                case 0x05:
                    await SendRefresh();
                    break;
                case 0x06:
                    if (data.Length >= 5)
                    {
                        int pid = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        await KillProcessTree(pid);
                        await SendRefresh();
                    }
                    break;
                case 0x07:
                    if (data.Length >= 5)
                    {
                        int count = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        int offset = 5;
                        int killed = 0;
                        int failed = 0;
                        for (int i = 0; i < count && offset + 4 <= data.Length; i++)
                        {
                            int pid = data[offset] | (data[offset+1] << 8) | (data[offset+2] << 16) | (data[offset+3] << 24);
                            offset += 4;
                            Process proc = null;
                            try { proc = Process.GetProcessById(pid); proc.Kill(); killed++; }
                            catch { failed++; }
                            finally { if (proc != null) proc.Dispose(); }
                        }
                        await SendStatus(0xFE, ""Killed "" + killed + "" process(es)"" + (failed > 0 ? "", "" + failed + "" failed"" : """"));
                        await SendRefresh();
                    }
                    break;
                case 0x08:
                    if (data.Length >= 5)
                    {
                        int count = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
                        int offset = 5;
                        int totalKilled = 0;
                        for (int i = 0; i < count && offset + 4 <= data.Length; i++)
                        {
                            int pid = data[offset] | (data[offset+1] << 8) | (data[offset+2] << 16) | (data[offset+3] << 24);
                            offset += 4;
                            List<int> toKill = new List<int>();
                            GetChildPids(pid, toKill);
                            toKill.Add(pid);
                            foreach (int p in toKill)
                            {
                                Process proc = null;
                                try { proc = Process.GetProcessById(p); proc.Kill(); totalKilled++; }
                                catch { }
                                finally { if (proc != null) proc.Dispose(); }
                            }
                        }
                        await SendStatus(0xFE, ""Killed "" + totalKilled + "" process(es) across "" + count + "" tree(s)"");
                        await SendRefresh();
                    }
                    break;
            }
        }

        private async Task SendRefresh()
        {
            Thread.Sleep(300);
            try
            {
                byte[] processData = CollectProcessData();
                if (processData != null)
                {
                    byte[] msg = new byte[processData.Length + 1];
                    msg[0] = 0x10;
                    Buffer.BlockCopy(processData, 0, msg, 1, processData.Length);
                    await _send(msg);
                }
            }
            catch { }
        }

        private async Task KillProcess(int pid)
        {
            Process process = null;
            string errorMsg = null;
            string successName = null;
            try { process = Process.GetProcessById(pid); successName = process.ProcessName; process.Kill(); }
            catch (Exception ex) { errorMsg = ex.Message; successName = null; }
            finally { if (process != null) process.Dispose(); }
            if (errorMsg != null) await SendStatus(0xFF, ""Kill failed PID "" + pid + "": "" + errorMsg);
            else if (successName != null) await SendStatus(0xFE, ""Killed: "" + successName + "" (PID "" + pid + "")"");
        }

        private async Task KillProcessTree(int pid)
        {
            string errorMsg = null;
            int killed = 0;
            try
            {
                List<int> toKill = new List<int>();
                GetChildPids(pid, toKill);
                toKill.Add(pid);
                foreach (int p in toKill)
                {
                    Process proc = null;
                    try { proc = Process.GetProcessById(p); proc.Kill(); killed++; }
                    catch { }
                    finally { if (proc != null) proc.Dispose(); }
                }
            }
            catch (Exception ex) { errorMsg = ex.Message; }
            if (errorMsg != null) await SendStatus(0xFF, ""Kill tree failed: "" + errorMsg);
            else await SendStatus(0xFE, ""Killed tree: "" + killed + "" process(es) from PID "" + pid);
        }

        private void GetChildPids(int parentPid, List<int> result)
        {
            IntPtr snap = CreateToolhelp32Snapshot(2, 0);
            if (snap.ToInt64() == -1) return;
            try
            {
                PROCESSENTRY32 entry = new PROCESSENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                if (Process32First(snap, ref entry))
                {
                    do
                    {
                        if ((int)entry.th32ParentProcessID == parentPid)
                        {
                            int childPid = (int)entry.th32ProcessID;
                            result.Add(childPid);
                            GetChildPids(childPid, result);
                        }
                    } while (Process32Next(snap, ref entry));
                }
            }
            finally { CloseHandle(snap); }
        }

        private byte[] CollectProcessData()
        {
            Dictionary<int, int> parentMap = GetParentMap();
            Dictionary<int, string> filePaths = GetProcessFilePaths();
            Process[] processes = Process.GetProcesses();
            try
            {
                Dictionary<int, ProcInfo> infoMap = new Dictionary<int, ProcInfo>();
                foreach (Process p in processes)
                {
                    try
                    {
                        string path = """";
                        if (filePaths.ContainsKey(p.Id)) path = filePaths[p.Id];
                        string desc = ""Unknown"";
                        if (!string.IsNullOrEmpty(path))
                        {
                            try
                            {
                                FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(path);
                                if (!string.IsNullOrEmpty(fvi.FileDescription)) desc = fvi.FileDescription;
                            }
                            catch { }
                        }
                        long memBytes = 0;
                        try { memBytes = p.WorkingSet64; } catch { }
                        int parentPid = -1;
                        if (parentMap.ContainsKey(p.Id)) parentPid = parentMap[p.Id];
                        infoMap[p.Id] = new ProcInfo { PID = p.Id, Name = p.ProcessName, FilePath = path, Description = desc, MemoryBytes = memBytes, ParentPID = parentPid };
                    }
                    catch { }
                }
                List<ProcInfo> roots = new List<ProcInfo>();
                foreach (ProcInfo pi in infoMap.Values)
                {
                    if (!infoMap.ContainsKey(pi.ParentPID)) roots.Add(pi);
                }
                Dictionary<int, List<ProcInfo>> childrenMap = new Dictionary<int, List<ProcInfo>>();
                foreach (ProcInfo pi in infoMap.Values)
                {
                    if (infoMap.ContainsKey(pi.ParentPID))
                    {
                        if (!childrenMap.ContainsKey(pi.ParentPID)) childrenMap[pi.ParentPID] = new List<ProcInfo>();
                        childrenMap[pi.ParentPID].Add(pi);
                    }
                }
                using (MemoryStream ms = new MemoryStream())
                using (BinaryWriter bw = new BinaryWriter(ms, Encoding.UTF8))
                {
                    bw.Write(infoMap.Count);
                    bw.Write(roots.Count);
                    foreach (ProcInfo root in roots) SerializeNode(bw, root, childrenMap);
                    return ms.ToArray();
                }
            }
            finally
            {
                foreach (Process p in processes) { try { p.Dispose(); } catch { } }
            }
        }

        private void SerializeNode(BinaryWriter bw, ProcInfo node, Dictionary<int, List<ProcInfo>> childrenMap)
        {
            bw.Write(node.PID);
            bw.Write(node.Name ?? """");
            bw.Write(node.FilePath ?? """");
            bw.Write(node.Description ?? """");
            bw.Write(node.MemoryBytes);
            List<ProcInfo> children = null;
            if (childrenMap.ContainsKey(node.PID)) children = childrenMap[node.PID];
            int childCount = children != null ? children.Count : 0;
            bw.Write(childCount);
            if (children != null) { foreach (ProcInfo child in children) SerializeNode(bw, child, childrenMap); }
        }

        private Dictionary<int, int> GetParentMap()
        {
            Dictionary<int, int> map = new Dictionary<int, int>();
            IntPtr snap = CreateToolhelp32Snapshot(2, 0);
            if (snap.ToInt64() == -1) return map;
            try
            {
                PROCESSENTRY32 entry = new PROCESSENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                if (Process32First(snap, ref entry))
                {
                    do { map[(int)entry.th32ProcessID] = (int)entry.th32ParentProcessID; } while (Process32Next(snap, ref entry));
                }
            }
            finally { CloseHandle(snap); }
            return map;
        }

        private Dictionary<int, string> GetProcessFilePaths()
        {
            Dictionary<int, string> paths = new Dictionary<int, string>();
            ManagementObjectSearcher searcher = null;
            ManagementObjectCollection objects = null;
            try
            {
                searcher = new ManagementObjectSearcher(""SELECT Description, ProcessId, ExecutablePath, CommandLine FROM Win32_Process"");
                objects = searcher.Get();
                foreach (ManagementObject obj in objects)
                {
                    try
                    {
                        int pid = Convert.ToInt32(obj[""ProcessId""]);
                        string filename = (obj[""Description""] ?? """").ToString();
                        string filePath = (obj[""ExecutablePath""] ?? """").ToString();
                        if (string.IsNullOrEmpty(filePath)) { string cmdLine = (obj[""CommandLine""] ?? """").ToString(); filePath = ExtractPathFromCmd(cmdLine); }
                        if (string.IsNullOrEmpty(filePath)) { if (windowsProcessPaths.ContainsKey(filename)) filePath = windowsProcessPaths[filename]; }
                        paths[pid] = filePath ?? """";
                    }
                    catch { }
                    finally { obj.Dispose(); }
                }
            }
            catch { }
            finally { if (objects != null) objects.Dispose(); if (searcher != null) searcher.Dispose(); }
            return paths;
        }

        private string ExtractPathFromCmd(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return """";
            string[] tokens = commandLine.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string token in tokens)
            {
                string clean = token.Trim('""');
                if (clean.EndsWith("".exe"", StringComparison.OrdinalIgnoreCase) || clean.EndsWith("".dll"", StringComparison.OrdinalIgnoreCase)) return clean;
            }
            return """";
        }

        private async Task SendAck(string message)
        {
            byte[] mb = Encoding.UTF8.GetBytes(message);
            byte[] msg = new byte[mb.Length + 1];
            msg[0] = 0xFE;
            Buffer.BlockCopy(mb, 0, msg, 1, mb.Length);
            await _send(msg);
        }

        private async Task SendStatus(byte code, string message)
        {
            byte[] mb = Encoding.UTF8.GetBytes(message);
            byte[] msg = new byte[mb.Length + 1];
            msg[0] = code;
            Buffer.BlockCopy(mb, 0, msg, 1, mb.Length);
            try { await _send(msg); } catch { }
        }

        private class ProcInfo
        {
            public int PID;
            public string Name;
            public string FilePath;
            public string Description;
            public long MemoryBytes;
            public int ParentPID;
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            var ui = new ProcessManagerUI(context, _host, this);
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
            if (_clientUIs.TryRemove(clientId, out var ui))
                ui.Dispose();
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
        }
    }

    // ==================== PROCESS INFO MODEL ====================

    public class ProcessInfoNode
    {
        public int PID { get; set; }
        public string Name { get; set; }
        public string FilePath { get; set; }
        public string Description { get; set; }
        public long MemoryBytes { get; set; }
        public List<ProcessInfoNode> Children { get; set; } = new();

        public string MemoryDisplay
        {
            get
            {
                if (MemoryBytes <= 0) return "—";
                if (MemoryBytes < 1024) return $"{MemoryBytes} B";
                if (MemoryBytes < 1024 * 1024) return $"{MemoryBytes / 1024.0:F1} KB";
                if (MemoryBytes < 1024L * 1024 * 1024) return $"{MemoryBytes / (1024.0 * 1024):F1} MB";
                return $"{MemoryBytes / (1024.0 * 1024 * 1024):F2} GB";
            }
        }

        public int TotalDescendantCount
        {
            get
            {
                int count = Children.Count;
                foreach (var c in Children)
                    count += c.TotalDescendantCount;
                return count;
            }
        }
    }
}
