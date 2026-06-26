#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace WpfApp.Plugins.Builtin
{
    // ==================== DATA MODELS ====================

    public class RegValueEntry
    {
        public string Name { get; set; }
        public string FullPath { get; set; }
        public string Type { get; set; }
        public string DisplayValue { get; set; }

        public string Icon
        {
            get
            {
                return Type switch
                {
                    "REG_SZ" or "REG_EXPAND_SZ" => "??",
                    "REG_DWORD" or "REG_QWORD" => "??",
                    "REG_BINARY" => "??",
                    "REG_MULTI_SZ" => "??",
                    _ => "?"
                };
            }
        }
    }

    public class RegKeyEntry
    {
        public string Name { get; set; }
        public string FullPath { get; set; }
        public bool HasSubKeys { get; set; }
    }

    // ==================== PLUGIN ====================

    [SupportedOSPlatform("windows")]
    public class RegistryPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, RegistryUI> _clientUIs = new();

        public string PluginId => "regedit";
        public string DisplayName => "Registry Editor";
        public string Version => "1.0.0";
        public string Description => "Remote Windows Registry browser with key/value management.";

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
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ClientPlugin_regedit
{
    public class RegValue
    {
        public string KeyName { get; set; }
        public string FullPath { get; set; }
        public string Type { get; set; }
        public object Value { get; set; }
    }

    public class RegInfo
    {
        public bool ContainsSubKeys { get; set; }
        public string[] SubKeys { get; set; }
        public string FullPath { get; set; }
        public List<RegValue> Values = new List<RegValue>();
    }

    public class Main
    {
        private Func<byte[], Task> _send;
        private CancellationTokenSource _cts = new CancellationTokenSource();

        private static readonly Dictionary<string, byte> TypeIdentifierMap = new Dictionary<string, byte>
        {
            { ""REG_SZ"", 1 },
            { ""REG_EXPAND_SZ"", 2 },
            { ""REG_BINARY"", 3 },
            { ""REG_DWORD"", 4 },
            { ""REG_MULTI_SZ"", 5 },
            { ""REG_QWORD"", 6 },
            { ""Unknown"", 7 }
        };

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;

            try
            {
                // Send ready signal
                await _send(new byte[] { 0xAA });

                while (!_cts.IsCancellationRequested)
                {
                    byte[] data = await receiveData();
                    if (data == null || data.Length == 0) break;

                    byte cmd = data[0];
                    byte[] payload = new byte[data.Length - 1];
                    if (payload.Length > 0)
                        Buffer.BlockCopy(data, 1, payload, 0, payload.Length);

                    Exception caught = null;
                    try
                    {
                        switch (cmd)
                        {
                            case 0x01: // Browse key
                                await HandleBrowseKey(Encoding.UTF8.GetString(payload));
                                break;
                            case 0x02: // Delete subkey
                                await HandleDeleteSubkey(Encoding.UTF8.GetString(payload));
                                break;
                            case 0x03: // Delete value
                                await HandleDeleteValue(payload);
                                break;
                            case 0x04: // Create subkey
                                await HandleCreateSubkey(Encoding.UTF8.GetString(payload));
                                break;
                            case 0x05: // Set value
                                await HandleSetValue(payload);
                                break;
                            case 0x06: // Rename subkey
                                await HandleRenameSubkey(payload);
                                break;
                            case 0x07: // List root hives
                                await HandleListRoots();
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        caught = ex;
                    }
                    if (caught != null)
                    {
                        await SendError(cmd, caught.Message);
                    }
                }
            }
            catch { }
        }

        private static RegistryHive? GetRootHive(string keyPath)
        {
            string[] parts = keyPath.Split('\\');
            if (parts.Length == 0) return null;

            string first = parts[0].ToUpper();
            if (first.StartsWith(""HKLM"") || first.StartsWith(""HKEY_LOCAL_MACHINE""))
                return RegistryHive.LocalMachine;
            if (first.StartsWith(""HKCU"") || first.StartsWith(""HKEY_CURRENT_USER""))
                return RegistryHive.CurrentUser;
            if (first.StartsWith(""HKCR"") || first.StartsWith(""HKEY_CLASSES_ROOT""))
                return RegistryHive.ClassesRoot;
            if (first.StartsWith(""HKU"") || first.StartsWith(""HKEY_USERS""))
                return RegistryHive.Users;
            if (first.StartsWith(""HKCC"") || first.StartsWith(""HKEY_CURRENT_CONFIG""))
                return RegistryHive.CurrentConfig;

            return null;
        }

        private static string GetSubPath(string keyPath)
        {
            int idx = keyPath.IndexOf('\\');
            return idx >= 0 ? keyPath.Substring(idx + 1) : """";
        }

        private static RegInfo GetRegInfo(string path)
        {
            RegistryHive? hive = GetRootHive(path);
            if (hive == null) return null;

            string subPath = GetSubPath(path);

            using (RegistryKey baseKey = RegistryKey.OpenBaseKey((RegistryHive)hive, RegistryView.Registry64))
            {
                using (RegistryKey key = string.IsNullOrEmpty(subPath) ? baseKey : baseKey.OpenSubKey(subPath))
                {
                    if (key == null) return null;

                    RegInfo info = new RegInfo();
                    info.FullPath = path;
                    info.ContainsSubKeys = key.SubKeyCount > 0;
                    info.SubKeys = key.GetSubKeyNames();
                    
                    foreach (string valueName in key.GetValueNames())
                    {
                        RegValue val = new RegValue();
                        val.KeyName = valueName;
                        val.FullPath = path + ""\\"" + valueName;

                        string type = ""Unknown"";
                        switch (key.GetValueKind(valueName))
                        {
                            case RegistryValueKind.String: type = ""REG_SZ""; break;
                            case RegistryValueKind.ExpandString: type = ""REG_EXPAND_SZ""; break;
                            case RegistryValueKind.Binary: type = ""REG_BINARY""; break;
                            case RegistryValueKind.DWord: type = ""REG_DWORD""; break;
                            case RegistryValueKind.MultiString: type = ""REG_MULTI_SZ""; break;
                            case RegistryValueKind.QWord: type = ""REG_QWORD""; break;
                        }
                        val.Type = type;
                        val.Value = key.GetValue(valueName);
                        info.Values.Add(val);
                    }

                    return info;
                }
            }
        }

        private static byte[] SerializeRegInfo(RegInfo regInfo)
        {
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter w = new BinaryWriter(ms))
            {
                w.Write(regInfo.ContainsSubKeys);
                w.Write(regInfo.SubKeys.Length);
                foreach (string subKey in regInfo.SubKeys)
                {
                    w.Write(subKey);
                }
                w.Write(regInfo.FullPath);
                w.Write(regInfo.Values.Count);

                foreach (RegValue value in regInfo.Values)
                {
                    w.Write(value.KeyName);
                    w.Write(value.FullPath);
                    w.Write(TypeIdentifierMap[value.Type]);

                    if (value.Value is string)
                    {
                        w.Write((byte)TypeIdentifierMap[""REG_SZ""]);
                        w.Write((string)value.Value);
                    }
                    else if (value.Value is int)
                    {
                        w.Write((byte)TypeIdentifierMap[""REG_DWORD""]);
                        w.Write((int)value.Value);
                    }
                    else if (value.Value is long)
                    {
                        w.Write((byte)TypeIdentifierMap[""REG_QWORD""]);
                        w.Write((long)value.Value);
                    }
                    else if (value.Value is byte[])
                    {
                        w.Write((byte)TypeIdentifierMap[""REG_BINARY""]);
                        byte[] byteArray = (byte[])value.Value;
                        w.Write(byteArray.Length);
                        w.Write(byteArray);
                    }
                    else if (value.Value is string[])
                    {
                        w.Write((byte)TypeIdentifierMap[""REG_MULTI_SZ""]);
                        string[] stringArray = (string[])value.Value;
                        w.Write(stringArray.Length);
                        foreach (string str in stringArray)
                        {
                            w.Write(str);
                        }
                    }
                    else
                    {
                        w.Write((byte)TypeIdentifierMap[""Unknown""]);
                    }
                }

                return ms.ToArray();
            }
        }

        private async Task HandleBrowseKey(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                await HandleListRoots();
                return;
            }

            RegInfo info = GetRegInfo(path);
            if (info != null)
            {
                byte[] serialized = SerializeRegInfo(info);
                byte[] msg = new byte[serialized.Length + 1];
                msg[0] = 0x01;
                Buffer.BlockCopy(serialized, 0, msg, 1, serialized.Length);
                await _send(msg);
            }
            else
            {
                await SendError(0x01, ""Key not found: "" + path);
            }
        }

        private async Task HandleListRoots()
        {
            string[] roots = new string[]
            {
                ""HKEY_LOCAL_MACHINE"",
                ""HKEY_CURRENT_USER"",
                ""HKEY_CLASSES_ROOT"",
                ""HKEY_USERS"",
                ""HKEY_CURRENT_CONFIG""
            };

            string result = string.Join(""\n"", roots);
            byte[] resultBytes = Encoding.UTF8.GetBytes(result);
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x07;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleDeleteSubkey(string path)
        {
            RegistryHive? hive = GetRootHive(path);
            if (hive == null)
            {
                await SendError(0x02, ""Invalid registry path"");
                return;
            }

            string subPath = GetSubPath(path);
            bool success = false;

            Exception deleteError = null;
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey((RegistryHive)hive, RegistryView.Registry64))
            {
                try
                {
                    baseKey.DeleteSubKeyTree(subPath);
                    success = true;
                }
                catch (Exception ex)
                {
                    deleteError = ex;
                }
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(success ? ""OK|"" + path : ""FAIL|"" + (deleteError != null ? deleteError.Message : ""Unknown error""));
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x02;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleDeleteValue(byte[] payload)
        {
            string text = Encoding.UTF8.GetString(payload);
            string[] parts = text.Split(new char[] { '|' }, 2);
            if (parts.Length != 2)
            {
                await SendError(0x03, ""Invalid format. Expected: path|valueName"");
                return;
            }

            string path = parts[0];
            string valueName = parts[1];

            RegistryHive? hive = GetRootHive(path);
            if (hive == null)
            {
                await SendError(0x03, ""Invalid registry path"");
                return;
            }

            string subPath = GetSubPath(path);
            bool success = false;

            Exception deleteError = null;
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey((RegistryHive)hive, RegistryView.Registry64))
            {
                using (RegistryKey key = baseKey.OpenSubKey(subPath, true))
                {
                    if (key == null)
                    {
                        await SendError(0x03, ""Key not found: "" + path);
                        return;
                    }
                    try
                    {
                        key.DeleteValue(valueName);
                        success = true;
                    }
                    catch (Exception ex)
                    {
                        deleteError = ex;
                    }
                }
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(success ? ""OK|"" + valueName : ""FAIL|"" + (deleteError != null ? deleteError.Message : ""Unknown error""));
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x03;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleCreateSubkey(string path)
        {
            RegistryHive? hive = GetRootHive(path);
            if (hive == null)
            {
                await SendError(0x04, ""Invalid registry path"");
                return;
            }

            string subPath = GetSubPath(path);
            bool success = false;

            Exception createError = null;
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey((RegistryHive)hive, RegistryView.Registry64))
            {
                try
                {
                    using (RegistryKey created = baseKey.CreateSubKey(subPath))
                    {
                        success = created != null;
                    }
                }
                catch (Exception ex)
                {
                    createError = ex;
                }
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(success ? ""OK|"" + path : ""FAIL|"" + (createError != null ? createError.Message : ""Unknown error""));
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x04;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleSetValue(byte[] payload)
        {
            if (payload.Length < 5) 
            {
                await SendError(0x05, ""Invalid payload"");
                return;
            }

            int offset = 0;
            byte typeId = payload[offset++];

            int pathLen = payload[offset] | (payload[offset + 1] << 8);
            offset += 2;
            if (payload.Length < offset + pathLen) { await SendError(0x05, ""Invalid path length""); return; }
            string path = Encoding.UTF8.GetString(payload, offset, pathLen);
            offset += pathLen;

            if (payload.Length < offset + 2) { await SendError(0x05, ""Invalid name length""); return; }
            int nameLen = payload[offset] | (payload[offset + 1] << 8);
            offset += 2;
            if (payload.Length < offset + nameLen) { await SendError(0x05, ""Invalid name""); return; }
            string valueName = Encoding.UTF8.GetString(payload, offset, nameLen);
            offset += nameLen;

            RegistryHive? hive = GetRootHive(path);
            if (hive == null)
            {
                await SendError(0x05, ""Invalid registry path"");
                return;
            }

            string subPath = GetSubPath(path);
            bool success = false;
            Exception setError = null;

            using (RegistryKey baseKey = RegistryKey.OpenBaseKey((RegistryHive)hive, RegistryView.Registry64))
            {
                using (RegistryKey key = baseKey.OpenSubKey(subPath, true))
                {
                    if (key == null)
                    {
                        await SendError(0x05, ""Key not found: "" + path);
                        return;
                    }

                    try
                    {
                        byte[] remaining = new byte[payload.Length - offset];
                        if (remaining.Length > 0)
                            Buffer.BlockCopy(payload, offset, remaining, 0, remaining.Length);

                        switch (typeId)
                        {
                            case 1:
                                key.SetValue(valueName, Encoding.UTF8.GetString(remaining), RegistryValueKind.String);
                                success = true;
                                break;
                            case 2:
                                key.SetValue(valueName, Encoding.UTF8.GetString(remaining), RegistryValueKind.ExpandString);
                                success = true;
                                break;
                            case 3:
                                key.SetValue(valueName, remaining, RegistryValueKind.Binary);
                                success = true;
                                break;
                            case 4:
                                if (remaining.Length >= 4)
                                {
                                    key.SetValue(valueName, BitConverter.ToInt32(remaining, 0), RegistryValueKind.DWord);
                                    success = true;
                                }
                                break;
                            case 5:
                                string multiStr = Encoding.UTF8.GetString(remaining);
                                string[] lines = multiStr.Split(new char[] { '\n' });
                                key.SetValue(valueName, lines, RegistryValueKind.MultiString);
                                success = true;
                                break;
                            case 6:
                                if (remaining.Length >= 8)
                                {
                                    key.SetValue(valueName, BitConverter.ToInt64(remaining, 0), RegistryValueKind.QWord);
                                    success = true;
                                }
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        setError = ex;
                    }
                }
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(success ? ""OK|"" + valueName : ""FAIL|"" + (setError != null ? setError.Message : ""Unsupported type or invalid data""));
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x05;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private async Task HandleRenameSubkey(byte[] payload)
        {
            string text = Encoding.UTF8.GetString(payload);
            string[] parts = text.Split(new char[] { '|' }, 2);
            if (parts.Length != 2)
            {
                await SendError(0x06, ""Invalid format. Expected: oldPath|newName"");
                return;
            }

            string oldPath = parts[0];
            string newName = parts[1];

            string parentPath = oldPath;
            int lastSlash = oldPath.LastIndexOf('\\');
            if (lastSlash >= 0)
                parentPath = oldPath.Substring(0, lastSlash);

            string newPath = parentPath + ""\\"" + newName;

            RegistryHive? hive = GetRootHive(oldPath);
            if (hive == null)
            {
                await SendError(0x06, ""Invalid registry path"");
                return;
            }

            bool success = false;
            Exception renameError = null;

            try
            {
                CopyKey(oldPath, newPath);

                string oldSubPath = GetSubPath(oldPath);
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey((RegistryHive)hive, RegistryView.Registry64))
                {
                    baseKey.DeleteSubKeyTree(oldSubPath);
                }
                success = true;
            }
            catch (Exception ex)
            {
                renameError = ex;
            }

            byte[] resultBytes = Encoding.UTF8.GetBytes(success ? ""OK|"" + newPath : ""FAIL|"" + (renameError != null ? renameError.Message : ""Unknown error""));
            byte[] msg = new byte[resultBytes.Length + 1];
            msg[0] = 0x06;
            Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
            await _send(msg);
        }

        private static void CopyKey(string sourcePath, string destPath)
        {
            RegistryHive? srcHive = GetRootHive(sourcePath);
            RegistryHive? dstHive = GetRootHive(destPath);
            if (srcHive == null || dstHive == null) return;

            string srcSub = GetSubPath(sourcePath);
            string dstSub = GetSubPath(destPath);

            using (RegistryKey srcBase = RegistryKey.OpenBaseKey((RegistryHive)srcHive, RegistryView.Registry64))
            using (RegistryKey dstBase = RegistryKey.OpenBaseKey((RegistryHive)dstHive, RegistryView.Registry64))
            using (RegistryKey srcKey = srcBase.OpenSubKey(srcSub))
            using (RegistryKey dstKey = dstBase.CreateSubKey(dstSub))
            {
                if (srcKey == null || dstKey == null) return;

                foreach (string valName in srcKey.GetValueNames())
                {
                    dstKey.SetValue(valName, srcKey.GetValue(valName), srcKey.GetValueKind(valName));
                }

                foreach (string subKeyName in srcKey.GetSubKeyNames())
                {
                    CopyKey(sourcePath + ""\\"" + subKeyName, destPath + ""\\"" + subKeyName);
                }
            }
        }

        private async Task SendError(byte forCommand, string message)
        {
            byte[] errBytes = Encoding.UTF8.GetBytes(message);
            byte[] msg = new byte[errBytes.Length + 2];
            msg[0] = 0xFF;
            msg[1] = forCommand;
            Buffer.BlockCopy(errBytes, 0, msg, 2, errBytes.Length);
            try { await _send(msg); } catch { }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            var ui = new RegistryUI(context, _host);
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
            if (_clientUIs.TryRemove(clientId, out var ui))
            {
                ui.Dispose();
            }
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
        }
    }

    // ==================== REGISTRY UI ====================

    [SupportedOSPlatform("windows")]
    public class RegistryUI : UserControl, IDisposable
    {
        private readonly PluginContext _context;
        private readonly PluginHost _host;

        private readonly TreeView _keyTree;
        private readonly ListView _valueListView;
        private readonly TextBox _pathBox;
        private readonly TextBlock _statusBar;

        private readonly Button _refreshButton;
        private readonly Button _rootsButton;
        private readonly Button _createKeyButton;
        private readonly Button _deleteKeyButton;
        private readonly Button _renameKeyButton;
        private readonly Button _createValueButton;
        private readonly Button _editValueButton;
        private readonly Button _deleteValueButton;

        private string _currentPath = "";
        private readonly List<RegValueEntry> _currentValues = new();
        private readonly List<RegKeyEntry> _currentSubKeys = new();

        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BgDarkColorVal => C("BackgroundColor");
        private Color SurfColorVal => C("SurfaceColor");
        private Color SurfLightColorVal => C("SurfaceLightColor");
        private Color BorderColorVal => C("BorderColor");
        private Color TextPrimaryColorVal => C("TextPrimaryColor");
        private Color TextSecondaryColorVal => C("TextSecondaryColor");
        private Color PrimaryColorVal => C("PrimaryColor");
        private Color PrimaryHoverColorVal => C("PrimaryHoverColor");
        private Color DangerColorVal => C("DangerColor");
        private Color DangerHoverColorVal => C("DangerHoverColor");
        private Color SuccessColorVal => C("SuccessColor");
        private Color DisabledBgColorVal => C("ButtonBgColor");
        private Color DisabledFgColorVal => C("TextSecondaryColor");

        private SolidColorBrush BgDark => B("BackgroundBrush");
        private SolidColorBrush BgMedium => B("SurfaceBrush");
        private SolidColorBrush BgLight => B("SurfaceLightBrush");
        private SolidColorBrush FgDefault => B("TextPrimaryBrush");
        private SolidColorBrush FgDim => B("TextSecondaryBrush");
        private SolidColorBrush AccentBlue => B("PrimaryBrush");
        private SolidColorBrush BorderBrushVal => B("BorderBrush");
        private SolidColorBrush DisabledBgBrush => B("ButtonBgBrush");
        private SolidColorBrush DisabledFgBrush => B("TextSecondaryBrush");

        public RegistryUI(PluginContext context, PluginHost host)
        {
            _context = context;
            _host = host;

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // ===== Toolbar =====
            var toolbarBorder = new Border
            {
                Background = BgMedium,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(6, 4, 6, 4)
            };

            var toolbar = new WrapPanel();

            _rootsButton = MakeThemedButton("?? Roots", SurfLightColorVal, C("ButtonBgHoverColor"));
            _rootsButton.Click += (s, e) => RequestRoots();

            _refreshButton = MakeThemedButton("?? Refresh", SurfLightColorVal, C("ButtonBgHoverColor"));
            _refreshButton.Click += (s, e) => RefreshCurrent();

            _createKeyButton = MakeThemedButton("??+ New Key", SurfLightColorVal, C("ButtonBgHoverColor"));
            _createKeyButton.Click += (s, e) => CreateNewKey();

            _deleteKeyButton = MakeThemedButton("??? Delete Key", DangerColorVal, DangerHoverColorVal);
            _deleteKeyButton.Click += (s, e) => DeleteSelectedKey();

            _renameKeyButton = MakeThemedButton("? Rename Key", SurfLightColorVal, C("ButtonBgHoverColor"));
            _renameKeyButton.Click += (s, e) => RenameSelectedKey();

            _createValueButton = MakeThemedButton("??+ New Value", SurfLightColorVal, C("ButtonBgHoverColor"));
            _createValueButton.Click += (s, e) => CreateNewValue();

            _editValueButton = MakeThemedButton("? Edit Value", SurfLightColorVal, C("ButtonBgHoverColor"));
            _editValueButton.Click += (s, e) => EditSelectedValue();

            _deleteValueButton = MakeThemedButton("?? Delete Value", DangerColorVal, DangerHoverColorVal);
            _deleteValueButton.Click += (s, e) => DeleteSelectedValue();

            toolbar.Children.Add(_rootsButton);
            toolbar.Children.Add(_refreshButton);
            toolbar.Children.Add(MakeSeparator());
            toolbar.Children.Add(_createKeyButton);
            toolbar.Children.Add(_renameKeyButton);
            toolbar.Children.Add(_deleteKeyButton);
            toolbar.Children.Add(MakeSeparator());
            toolbar.Children.Add(_createValueButton);
            toolbar.Children.Add(_editValueButton);
            toolbar.Children.Add(_deleteValueButton);

            toolbarBorder.Child = toolbar;
            Grid.SetRow(toolbarBorder, 0);
            mainGrid.Children.Add(toolbarBorder);

            // ===== Path bar =====
            var pathBorder = new Border
            {
                Background = BgMedium,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(6, 4, 6, 4)
            };

            var pathPanel = new DockPanel();

            var goButton = MakeThemedButton("Go", PrimaryColorVal, PrimaryHoverColorVal);
            goButton.Click += (s, e) => NavigateTo(_pathBox.Text);
            DockPanel.SetDock(goButton, Dock.Right);

            _pathBox = new TextBox
            {
                Background = BgDark,
                Foreground = FgDefault,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 5, 8, 5),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                CaretBrush = FgDefault,
                VerticalContentAlignment = VerticalAlignment.Center,
                Style = null,
                Text = "HKEY_CURRENT_USER"
            };
            _pathBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) { NavigateTo(_pathBox.Text); e.Handled = true; }
            };

            pathPanel.Children.Add(goButton);
            pathPanel.Children.Add(_pathBox);

            pathBorder.Child = pathPanel;
            Grid.SetRow(pathBorder, 1);
            mainGrid.Children.Add(pathBorder);

            // ===== Content: split panel =====
            var contentGrid = new Grid { Margin = new Thickness(0) };
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(280) });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left: Key tree
            var leftPanel = new Border
            {
                Background = BgDark,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 0, 1, 0)
            };

            _keyTree = new TreeView
            {
                Background = Brushes.Transparent,
                Foreground = FgDefault,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                Padding = new Thickness(4)
            };

            string[] rootHives = { "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG" };
            foreach (string hive in rootHives)
            {
                var item = new TreeViewItem
                {
                    Header = $"??? {hive}",
                    Tag = hive,
                    Foreground = FgDefault,
                    FontSize = 13
                };
                item.Selected += TreeItem_Selected;
                item.Expanded += TreeItem_Expanded;
                item.Items.Add(new TreeViewItem { Header = "Loading...", Foreground = FgDim });
                _keyTree.Items.Add(item);
            }

            leftPanel.Child = _keyTree;
            Grid.SetColumn(leftPanel, 0);
            contentGrid.Children.Add(leftPanel);

            // Splitter
            var splitter = new GridSplitter
            {
                Width = 4,
                Background = BorderBrushVal,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Stretch
            };
            Grid.SetColumn(splitter, 1);
            contentGrid.Children.Add(splitter);

            // Right: Values list
            _valueListView = new ListView
            {
                Background = BgDark,
                Foreground = FgDefault,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13
            };

            var gridView = new GridView();
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "",
                DisplayMemberBinding = new System.Windows.Data.Binding("Icon"),
                Width = 30
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Name",
                DisplayMemberBinding = new System.Windows.Data.Binding("Name"),
                Width = 200
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Type",
                DisplayMemberBinding = new System.Windows.Data.Binding("Type"),
                Width = 120
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Value",
                DisplayMemberBinding = new System.Windows.Data.Binding("DisplayValue"),
                Width = 300
            });

            _valueListView.View = gridView;

            var valueItemStyle = new Style(typeof(ListViewItem));
            valueItemStyle.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueItemStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            valueItemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(2)));
            valueItemStyle.Setters.Add(new Setter(Control.MarginProperty, new Thickness(0)));
            valueItemStyle.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
            valueItemStyle.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch));

            var valueHoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            valueHoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueHoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, BgLight));
            valueItemStyle.Triggers.Add(valueHoverTrigger);

            var valueSelectedTrigger = new Trigger { Property = System.Windows.Controls.Primitives.Selector.IsSelectedProperty, Value = true };
            valueSelectedTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueSelectedTrigger.Setters.Add(new Setter(Control.BackgroundProperty, AccentBlue));
            valueItemStyle.Triggers.Add(valueSelectedTrigger);

            var valueSelectedHoverTrigger = new MultiTrigger();
            valueSelectedHoverTrigger.Conditions.Add(new Condition(UIElement.IsMouseOverProperty, true));
            valueSelectedHoverTrigger.Conditions.Add(new Condition(System.Windows.Controls.Primitives.Selector.IsSelectedProperty, true));
            valueSelectedHoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueSelectedHoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(PrimaryHoverColorVal)));
            valueItemStyle.Triggers.Add(valueSelectedHoverTrigger);

            _valueListView.ItemContainerStyle = valueItemStyle;

            _valueListView.MouseDoubleClick += ValueList_DoubleClick;
            _valueListView.SelectionChanged += ValueList_SelectionChanged;

            Grid.SetColumn(_valueListView, 2);
            contentGrid.Children.Add(_valueListView);

            Grid.SetRow(contentGrid, 2);
            mainGrid.Children.Add(contentGrid);

            // ===== Status bar =====
            var statusBorder = new Border
            {
                Background = BgMedium,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(10, 5, 10, 5)
            };

            _statusBar = new TextBlock
            {
                Text = "Ready — Select a registry hive to browse",
                Foreground = FgDim,
                FontSize = 12
            };

            statusBorder.Child = _statusBar;
            Grid.SetRow(statusBorder, 3);
            mainGrid.Children.Add(statusBorder);

            this.Content = mainGrid;
            this.Background = BgDark;

            UpdateButtonStates();
        }

        // ==================== THEMED BUTTON FACTORY ====================

        private Button MakeThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var normalBgBrush = new SolidColorBrush(normalBg);
            var hoverBgBrush = new SolidColorBrush(hoverBg);

            var template = new ControlTemplate(typeof(Button));

            var borderFactory = new FrameworkElementFactory(typeof(Border));
            borderFactory.Name = "btnBorder";
            borderFactory.SetValue(Border.BackgroundProperty, normalBgBrush);
            borderFactory.SetValue(Border.BorderBrushProperty, new SolidColorBrush(C("ButtonBorderColor")));
            borderFactory.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            borderFactory.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            borderFactory.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var contentFactory = new FrameworkElementFactory(typeof(ContentPresenter));
            contentFactory.Name = "btnContent";
            contentFactory.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            contentFactory.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            borderFactory.AppendChild(contentFactory);

            template.VisualTree = borderFactory;

            // Hover
            var hoverTrigger = new Trigger
            {
                Property = UIElement.IsMouseOverProperty,
                Value = true
            };
            hoverTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBgBrush, "btnBorder"));
            template.Triggers.Add(hoverTrigger);

            // Pressed
            var pressedTrigger = new Trigger
            {
                Property = ButtonBase.IsPressedProperty,
                Value = true
            };
            pressedTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBgBrush, "btnBorder"));
            pressedTrigger.Setters.Add(new Setter(Border.OpacityProperty, 0.8, "btnBorder"));
            template.Triggers.Add(pressedTrigger);

            // Disabled
            var disabledTrigger = new Trigger
            {
                Property = UIElement.IsEnabledProperty,
                Value = false
            };
            disabledTrigger.Setters.Add(new Setter(Border.BackgroundProperty, DisabledBgBrush, "btnBorder"));
            disabledTrigger.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "btnContent"));
            template.Triggers.Add(disabledTrigger);

            return new Button
            {
                Content = text,
                Template = template,
                Foreground = FgDefault,
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
                Background = BorderBrushVal,
                Margin = new Thickness(6, 4, 6, 4)
            };
        }

        private void SetStatus(string text)
        {
            Dispatcher.BeginInvoke(() => _statusBar.Text = text);
        }

        private void UpdateButtonStates()
        {
            Dispatcher.BeginInvoke(() =>
            {
                var selectedTreeItem = _keyTree.SelectedItem as TreeViewItem;
                var selectedValue = _valueListView.SelectedItem as RegValueEntry;

                bool hasKeySelected = selectedTreeItem != null;
                bool hasValueSelected = selectedValue != null;
                bool hasPath = !string.IsNullOrEmpty(_currentPath);

                _createKeyButton.IsEnabled = hasPath;
                _deleteKeyButton.IsEnabled = hasKeySelected && hasPath;
                _renameKeyButton.IsEnabled = hasKeySelected && hasPath;
                _createValueButton.IsEnabled = hasPath;
                _editValueButton.IsEnabled = hasValueSelected;
                _deleteValueButton.IsEnabled = hasValueSelected;
                _refreshButton.IsEnabled = true;
            });
        }

        // ==================== TREE EVENTS ====================

        private void TreeItem_Selected(object sender, RoutedEventArgs e)
        {
            if (sender is TreeViewItem item && item.Tag is string path)
            {
                e.Handled = true;
                NavigateTo(path);
            }
        }

        private void TreeItem_Expanded(object sender, RoutedEventArgs e)
        {
            if (sender is TreeViewItem item && item.Tag is string path)
            {
                if (item.Items.Count == 1 && item.Items[0] is TreeViewItem dummy && dummy.Header?.ToString() == "Loading...")
                {
                    SendBrowseKey(path);
                }
            }
        }

        private void ValueList_DoubleClick(object sender, MouseButtonEventArgs e)
        {
            EditSelectedValue();
        }

        private void ValueList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateButtonStates();
            if (_valueListView.SelectedItem is RegValueEntry entry)
            {
                SetStatus($"{entry.Type}: {entry.FullPath}");
            }
        }

        // ==================== NAVIGATION ====================

        private void NavigateTo(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            _currentPath = path;
            Dispatcher.BeginInvoke(() => _pathBox.Text = path);
            SendBrowseKey(path);
        }

        private void RefreshCurrent()
        {
            if (string.IsNullOrEmpty(_currentPath))
                RequestRoots();
            else
                SendBrowseKey(_currentPath);
        }

        // ==================== ACTIONS ====================

        private async void CreateNewKey()
        {
            if (string.IsNullOrEmpty(_currentPath))
            {
                SetStatus("Navigate to a key first");
                return;
            }

            string name = PromptInput("New Registry Key", "Enter key name:");
            if (string.IsNullOrWhiteSpace(name)) return;

            string fullPath = _currentPath + "\\" + name;

            byte[] pathBytes = Encoding.UTF8.GetBytes(fullPath);
            byte[] msg = new byte[pathBytes.Length + 1];
            msg[0] = 0x04;
            Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);

            SetStatus($"Creating key: {fullPath}...");
            await _context.SendToClient(msg);
        }

        private async void DeleteSelectedKey()
        {
            if (string.IsNullOrEmpty(_currentPath)) return;

            if (_keyTree.SelectedItem is TreeViewItem selectedItem && selectedItem.Tag is string keyPath)
            {
                var result = MessageBox.Show(
                    $"Delete registry key and ALL its contents?\n\n{keyPath}\n\nThis cannot be undone!",
                    "Confirm Delete Key",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result != MessageBoxResult.Yes) return;

                byte[] pathBytes = Encoding.UTF8.GetBytes(keyPath);
                byte[] msg = new byte[pathBytes.Length + 1];
                msg[0] = 0x02;
                Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);

                SetStatus($"Deleting key: {keyPath}...");
                await _context.SendToClient(msg);
            }
        }

        private async void RenameSelectedKey()
        {
            if (_keyTree.SelectedItem is TreeViewItem selectedItem && selectedItem.Tag is string keyPath)
            {
                string oldName = keyPath.Split('\\').LastOrDefault() ?? "";
                string newName = PromptInput("Rename Registry Key", "Enter new name:", oldName);
                if (string.IsNullOrWhiteSpace(newName) || newName == oldName) return;

                string renameStr = keyPath + "|" + newName;
                byte[] renameBytes = Encoding.UTF8.GetBytes(renameStr);
                byte[] msg = new byte[renameBytes.Length + 1];
                msg[0] = 0x06;
                Buffer.BlockCopy(renameBytes, 0, msg, 1, renameBytes.Length);

                SetStatus($"Renaming key...");
                await _context.SendToClient(msg);
            }
        }

        private async void CreateNewValue()
        {
            if (string.IsNullOrEmpty(_currentPath))
            {
                SetStatus("Navigate to a key first");
                return;
            }

            string typeStr = PromptInput("New Registry Value", "Enter type (REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ):", "REG_SZ");
            if (string.IsNullOrWhiteSpace(typeStr)) return;

            string name = PromptInput("New Registry Value", "Enter value name:");
            if (name == null) return;

            string valueStr = PromptInput("New Registry Value", "Enter value:", "");
            if (valueStr == null) return;

            byte typeId = typeStr.ToUpper() switch
            {
                "REG_SZ" => 1,
                "REG_EXPAND_SZ" => 2,
                "REG_BINARY" => 3,
                "REG_DWORD" => 4,
                "REG_MULTI_SZ" => 5,
                "REG_QWORD" => 6,
                _ => 1
            };

            byte[] valueData;
            switch (typeId)
            {
                case 4:
                    if (int.TryParse(valueStr, out int dw))
                        valueData = BitConverter.GetBytes(dw);
                    else { SetStatus("Invalid DWORD value"); return; }
                    break;
                case 6:
                    if (long.TryParse(valueStr, out long qw))
                        valueData = BitConverter.GetBytes(qw);
                    else { SetStatus("Invalid QWORD value"); return; }
                    break;
                case 3:
                    try { valueData = HexStringToBytes(valueStr); }
                    catch { SetStatus("Invalid hex string for binary value"); return; }
                    break;
                default:
                    valueData = Encoding.UTF8.GetBytes(valueStr);
                    break;
            }

            byte[] pathBytes = Encoding.UTF8.GetBytes(_currentPath);
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);

            byte[] msg = new byte[1 + 1 + 2 + pathBytes.Length + 2 + nameBytes.Length + valueData.Length];
            int offset = 0;
            msg[offset++] = 0x05;
            msg[offset++] = typeId;
            msg[offset++] = (byte)(pathBytes.Length & 0xFF);
            msg[offset++] = (byte)((pathBytes.Length >> 8) & 0xFF);
            Buffer.BlockCopy(pathBytes, 0, msg, offset, pathBytes.Length);
            offset += pathBytes.Length;
            msg[offset++] = (byte)(nameBytes.Length & 0xFF);
            msg[offset++] = (byte)((nameBytes.Length >> 8) & 0xFF);
            Buffer.BlockCopy(nameBytes, 0, msg, offset, nameBytes.Length);
            offset += nameBytes.Length;
            Buffer.BlockCopy(valueData, 0, msg, offset, valueData.Length);

            SetStatus($"Creating value: {name}...");
            await _context.SendToClient(msg);
        }

        private void EditSelectedValue()
        {
            if (_valueListView.SelectedItem is RegValueEntry entry)
            {
                string newValue = PromptInput($"Edit {entry.Type}", $"Edit value for '{entry.Name}':", entry.DisplayValue);
                if (newValue == null) return;

                byte typeId = entry.Type switch
                {
                    "REG_SZ" => 1,
                    "REG_EXPAND_SZ" => 2,
                    "REG_BINARY" => 3,
                    "REG_DWORD" => 4,
                    "REG_MULTI_SZ" => 5,
                    "REG_QWORD" => 6,
                    _ => 1
                };

                byte[] valueData;
                switch (typeId)
                {
                    case 4:
                        if (int.TryParse(newValue, out int dw))
                            valueData = BitConverter.GetBytes(dw);
                        else { SetStatus("Invalid DWORD value"); return; }
                        break;
                    case 6:
                        if (long.TryParse(newValue, out long qw))
                            valueData = BitConverter.GetBytes(qw);
                        else { SetStatus("Invalid QWORD value"); return; }
                        break;
                    case 3:
                        try { valueData = HexStringToBytes(newValue); }
                        catch { SetStatus("Invalid hex string"); return; }
                        break;
                    default:
                        valueData = Encoding.UTF8.GetBytes(newValue);
                        break;
                }

                byte[] pathBytes = Encoding.UTF8.GetBytes(_currentPath);
                byte[] nameBytes = Encoding.UTF8.GetBytes(entry.Name);

                byte[] msg = new byte[1 + 1 + 2 + pathBytes.Length + 2 + nameBytes.Length + valueData.Length];
                int offset = 0;
                msg[offset++] = 0x05;
                msg[offset++] = typeId;
                msg[offset++] = (byte)(pathBytes.Length & 0xFF);
                msg[offset++] = (byte)((pathBytes.Length >> 8) & 0xFF);
                Buffer.BlockCopy(pathBytes, 0, msg, offset, pathBytes.Length);
                offset += pathBytes.Length;
                msg[offset++] = (byte)(nameBytes.Length & 0xFF);
                msg[offset++] = (byte)((nameBytes.Length >> 8) & 0xFF);
                Buffer.BlockCopy(nameBytes, 0, msg, offset, nameBytes.Length);
                offset += nameBytes.Length;
                Buffer.BlockCopy(valueData, 0, msg, offset, valueData.Length);

                SetStatus($"Updating value: {entry.Name}...");
                _ = _context.SendToClient(msg);
            }
        }

        private async void DeleteSelectedValue()
        {
            if (_valueListView.SelectedItem is RegValueEntry entry)
            {
                var result = MessageBox.Show(
                    $"Delete registry value?\n\n{entry.Name} ({entry.Type})\n\nThis cannot be undone!",
                    "Confirm Delete Value",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result != MessageBoxResult.Yes) return;

                string deleteStr = _currentPath + "|" + entry.Name;
                byte[] deleteBytes = Encoding.UTF8.GetBytes(deleteStr);
                byte[] msg = new byte[deleteBytes.Length + 1];
                msg[0] = 0x03;
                Buffer.BlockCopy(deleteBytes, 0, msg, 1, deleteBytes.Length);

                SetStatus($"Deleting value: {entry.Name}...");
                await _context.SendToClient(msg);
            }
        }

        // ==================== SEND COMMANDS ====================

        private async void SendBrowseKey(string path)
        {
            SetStatus($"Loading: {path}...");
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            byte[] msg = new byte[pathBytes.Length + 1];
            msg[0] = 0x01;
            Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);
            await _context.SendToClient(msg);
        }

        private async void RequestRoots()
        {
            _currentPath = "";
            Dispatcher.BeginInvoke(() => _pathBox.Text = "");
            SetStatus("Loading root hives...");
            await _context.SendToClient(new byte[] { 0x07 });
        }

        // ==================== HANDLE RESPONSES ====================

        public void HandleServerData(byte[] data)
        {
            if (data == null || data.Length == 0) return;

            byte responseType = data[0];
            byte[] payload = new byte[data.Length - 1];
            if (payload.Length > 0)
                Buffer.BlockCopy(data, 1, payload, 0, payload.Length);

            Dispatcher.BeginInvoke(() =>
            {
                switch (responseType)
                {
                    case 0xAA:
                        SetStatus("Plugin connected. Select a registry hive to browse.");
                        break;

                    case 0x01:
                        HandleBrowseResult(payload);
                        break;

                    case 0x02:
                        HandleActionResult("Delete key", payload);
                        break;

                    case 0x03:
                        HandleActionResult("Delete value", payload);
                        break;

                    case 0x04:
                        HandleActionResult("Create key", payload);
                        break;

                    case 0x05:
                        HandleActionResult("Set value", payload);
                        break;

                    case 0x06:
                        HandleActionResult("Rename key", payload);
                        break;

                    case 0x07:
                        HandleRootsList(payload);
                        break;

                    case 0xFF:
                        if (payload.Length > 1)
                        {
                            string errMsg = Encoding.UTF8.GetString(payload, 1, payload.Length - 1);
                            SetStatus($"Error: {errMsg}");
                        }
                        break;
                }
            });
        }

        private void HandleBrowseResult(byte[] payload)
        {
            try
            {
                using var ms = new MemoryStream(payload);
                using var reader = new BinaryReader(ms);

                bool containsSubKeys = reader.ReadBoolean();
                int subKeyCount = reader.ReadInt32();

                _currentSubKeys.Clear();
                string[] subKeyNames = new string[subKeyCount];
                for (int i = 0; i < subKeyCount; i++)
                {
                    subKeyNames[i] = reader.ReadString();
                }

                string fullPath = reader.ReadString();
                _currentPath = fullPath;
                _pathBox.Text = fullPath;

                int valueCount = reader.ReadInt32();
                _currentValues.Clear();
                _valueListView.Items.Clear();

                for (int i = 0; i < valueCount; i++)
                {
                    string keyName = reader.ReadString();
                    string valFullPath = reader.ReadString();
                    byte typeId = reader.ReadByte();
                    byte valueTypeId = reader.ReadByte();

                    string typeName = typeId switch
                    {
                        1 => "REG_SZ",
                        2 => "REG_EXPAND_SZ",
                        3 => "REG_BINARY",
                        4 => "REG_DWORD",
                        5 => "REG_MULTI_SZ",
                        6 => "REG_QWORD",
                        _ => "Unknown"
                    };

                    string displayValue = "";

                    switch (valueTypeId)
                    {
                        case 1:
                            displayValue = reader.ReadString();
                            break;
                        case 4:
                            displayValue = reader.ReadInt32().ToString();
                            break;
                        case 6:
                            displayValue = reader.ReadInt64().ToString();
                            break;
                        case 3:
                            int byteLen = reader.ReadInt32();
                            byte[] bytes = reader.ReadBytes(byteLen);
                            displayValue = BitConverter.ToString(bytes).Replace("-", " ");
                            if (displayValue.Length > 100) displayValue = displayValue.Substring(0, 100) + "...";
                            break;
                        case 5:
                            int strCount = reader.ReadInt32();
                            var strings = new List<string>();
                            for (int j = 0; j < strCount; j++)
                                strings.Add(reader.ReadString());
                            displayValue = string.Join(" | ", strings);
                            break;
                        case 7:
                            displayValue = "(unknown type)";
                            break;
                    }

                    var entry = new RegValueEntry
                    {
                        Name = string.IsNullOrEmpty(keyName) ? "(Default)" : keyName,
                        FullPath = valFullPath,
                        Type = typeName,
                        DisplayValue = displayValue
                    };

                    _currentValues.Add(entry);
                    _valueListView.Items.Add(entry);
                }

                UpdateTreeForPath(fullPath, subKeyNames, containsSubKeys);

                int valCount = _currentValues.Count;
                SetStatus($"{fullPath} — {subKeyCount} subkey(s), {valCount} value(s)");
                UpdateButtonStates();
            }
            catch (Exception ex)
            {
                SetStatus($"Parse error: {ex.Message}");
            }
        }

        private void UpdateTreeForPath(string path, string[] subKeyNames, bool hasSubKeys)
        {
            string[] pathParts = path.Split('\\');
            if (pathParts.Length == 0) return;

            TreeViewItem currentNode = null;
            foreach (TreeViewItem rootItem in _keyTree.Items)
            {
                if (rootItem.Tag is string rootPath && rootPath.Equals(pathParts[0], StringComparison.OrdinalIgnoreCase))
                {
                    currentNode = rootItem;
                    break;
                }
            }

            if (currentNode == null) return;

            for (int i = 1; i < pathParts.Length; i++)
            {
                TreeViewItem found = null;
                foreach (var child in currentNode.Items)
                {
                    if (child is TreeViewItem ti && ti.Tag is string tag)
                    {
                        string childName = tag.Split('\\').LastOrDefault() ?? "";
                        if (childName.Equals(pathParts[i], StringComparison.OrdinalIgnoreCase))
                        {
                            found = ti;
                            break;
                        }
                    }
                }

                if (found == null)
                {
                    string partialPath = string.Join("\\", pathParts.Take(i + 1));
                    found = new TreeViewItem
                    {
                        Header = $"?? {pathParts[i]}",
                        Tag = partialPath,
                        Foreground = FgDefault,
                        FontSize = 13
                    };
                    found.Selected += TreeItem_Selected;
                    found.Expanded += TreeItem_Expanded;
                    currentNode.Items.Add(found);
                }

                currentNode = found;
            }

            currentNode.Items.Clear();
            foreach (string subKey in subKeyNames)
            {
                string childPath = path + "\\" + subKey;
                var childItem = new TreeViewItem
                {
                    Header = $"?? {subKey}",
                    Tag = childPath,
                    Foreground = FgDefault,
                    FontSize = 13
                };
                childItem.Selected += TreeItem_Selected;
                childItem.Expanded += TreeItem_Expanded;
                childItem.Items.Add(new TreeViewItem { Header = "Loading...", Foreground = FgDim });
                currentNode.Items.Add(childItem);
            }

            currentNode.IsExpanded = true;
        }

        private void HandleRootsList(byte[] payload)
        {
            SetStatus("Root hives loaded. Select one to browse.");
        }

        private void HandleActionResult(string action, byte[] payload)
        {
            string result = Encoding.UTF8.GetString(payload);
            if (result.StartsWith("OK|"))
            {
                string detail = result.Substring(3);
                SetStatus($"{action} successful: {detail}");
                RefreshCurrent();
            }
            else if (result.StartsWith("FAIL|"))
            {
                string detail = result.Substring(5);
                SetStatus($"{action} failed: {detail}");
            }
            else
            {
                SetStatus($"{action}: {result}");
            }
        }

        // ==================== UTILITY ====================

        private string PromptInput(string title, string prompt, string defaultValue = "")
        {
            var dialog = new Window
            {
                Title = title,
                Width = 450,
                Height = 180,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Window.GetWindow(this),
                Background = BgMedium,
                ResizeMode = ResizeMode.NoResize
            };

            var panel = new StackPanel { Margin = new Thickness(16) };

            var promptText = new TextBlock
            {
                Text = prompt,
                Foreground = FgDefault,
                Margin = new Thickness(0, 0, 0, 8),
                FontSize = 13
            };
            panel.Children.Add(promptText);

            var inputBox = new TextBox
            {
                Text = defaultValue,
                Background = BgDark,
                Foreground = FgDefault,
                Padding = new Thickness(8, 5, 8, 5),
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(1),
                CaretBrush = FgDefault,
                Style = null,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13
            };
            panel.Children.Add(inputBox);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 14, 0, 0)
            };

            var okButton = MakeThemedButton("OK", PrimaryColorVal, PrimaryHoverColorVal);
            okButton.Width = 80;
            okButton.Click += (s, e) => { dialog.DialogResult = true; dialog.Close(); };

            var cancelButton = MakeThemedButton("Cancel", SurfLightColorVal, C("ButtonBgHoverColor"));
            cancelButton.Width = 80;
            cancelButton.Click += (s, e) => { dialog.DialogResult = false; dialog.Close(); };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            panel.Children.Add(buttonPanel);

            dialog.Content = panel;
            inputBox.SelectAll();
            inputBox.Focus();

            inputBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) { dialog.DialogResult = true; dialog.Close(); }
                if (e.Key == Key.Escape) { dialog.DialogResult = false; dialog.Close(); }
            };

            return dialog.ShowDialog() == true ? inputBox.Text : null;
        }

        private static byte[] HexStringToBytes(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "");
            if (hex.Length % 2 != 0)
                hex = "0" + hex;

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        public void Dispose() { }
    }
}