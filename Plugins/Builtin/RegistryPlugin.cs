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
                    "REG_SZ" or "REG_EXPAND_SZ" => "📝",
                    "REG_DWORD" or "REG_QWORD" => "#",
                    "REG_BINARY" => "0x",
                    "REG_MULTI_SZ" => "📋",
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
}
