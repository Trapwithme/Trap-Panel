// File: Plugins/Builtin/Socks5Plugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class Socks5Plugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, Socks5UI> _uis = new();

        public string PluginId => "socks5";
        public string DisplayName => "SOCKS5 Proxy";
        public string Version => "1.0.0";
        public string Description => "SOCKS5 proxy server tunneled through client connection.";

        public Task Initialize(PluginHost host) { _host = host; return Task.CompletedTask; }
        public Task Shutdown() { foreach (var u in _uis.Values) u.Dispose(); _uis.Clear(); return Task.CompletedTask; }

        public string GetClientCode()
        {
            return @"
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_socks5
{
    public class Main
    {
        Func<byte[], Task> _send;
        Func<Task<byte[]>> _recv;
        volatile bool _running;

        readonly ConcurrentDictionary<int, ConnState> _connections = new ConcurrentDictionary<int, ConnState>();

        class ConnState
        {
            public Socket Socket;
            public int ConnId;
            public CancellationTokenSource Cts;
            public volatile bool Closed;

            public ConnState()
            {
                Cts = new CancellationTokenSource();
            }
        }

        async Task Log(string msg)
        {
            try
            {
                byte[] b = Encoding.UTF8.GetBytes(msg);
                byte[] m = new byte[b.Length + 1];
                m[0] = 0xFD;
                Buffer.BlockCopy(b, 0, m, 1, b.Length);
                await _send(m);
            }
            catch { }
        }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            _recv = receiveData;
            _running = true;

            await Log(""[SOCKS5] Client plugin started"");
            await _send(new byte[] { 0x01 });

            try
            {
                while (_running)
                {
                    byte[] cmd = null;
                    bool fail = false;
                    try { cmd = await _recv(); }
                    catch { fail = true; }
                    if (fail || cmd == null || cmd.Length == 0) break;

                    switch (cmd[0])
                    {
                        case 0x10:
                            byte[] cmdCopy = new byte[cmd.Length];
                            Buffer.BlockCopy(cmd, 0, cmdCopy, 0, cmd.Length);
                            ThreadPool.QueueUserWorkItem(delegate { HandleConnectWrapper(cmdCopy); });
                            break;
                        case 0x20:
                            HandleDataFromServer(cmd);
                            break;
                        case 0x21:
                            HandleCloseFromServer(cmd);
                            break;
                        case 0x02:
                            _running = false;
                            await _send(new byte[] { 0xFE, 0x02 });
                            break;
                    }
                }
            }
            catch { }

            _running = false;

            foreach (System.Collections.Generic.KeyValuePair<int, ConnState> kvp in _connections)
            {
                kvp.Value.Cts.Cancel();
                kvp.Value.Closed = true;
                try { kvp.Value.Socket.Shutdown(SocketShutdown.Both); } catch { }
                try { kvp.Value.Socket.Close(); } catch { }
            }
            _connections.Clear();
        }

        void HandleConnectWrapper(byte[] cmd)
        {
            try { HandleConnect(cmd).Wait(); }
            catch { }
        }

        void HandleDataFromServer(byte[] data)
        {
            if (data.Length < 6) return;
            int connId = BitConverter.ToInt32(data, 1);
            ConnState cs;
            if (_connections.TryGetValue(connId, out cs) && !cs.Closed)
            {
                try
                {
                    int len = data.Length - 5;
                    cs.Socket.Send(data, 5, len, SocketFlags.None);
                }
                catch
                {
                    cs.Cts.Cancel();
                }
            }
        }

        void HandleCloseFromServer(byte[] data)
        {
            if (data.Length < 5) return;
            int connId = BitConverter.ToInt32(data, 1);
            ConnState cs;
            if (_connections.TryRemove(connId, out cs))
            {
                cs.Closed = true;
                cs.Cts.Cancel();
                try { cs.Socket.Shutdown(SocketShutdown.Both); } catch { }
                try { cs.Socket.Close(); } catch { }
            }
        }

        async Task HandleConnect(byte[] cmd)
        {
            if (cmd.Length < 13) return;

            int connId = BitConverter.ToInt32(cmd, 1);
            int addrLen = cmd[5] | (cmd[6] << 8);
            if (cmd.Length < 9 + addrLen) return;
            string addr = Encoding.UTF8.GetString(cmd, 7, addrLen);
            int port = cmd[7 + addrLen] | (cmd[8 + addrLen] << 8);
            int timeout = BitConverter.ToInt32(cmd, 9 + addrLen);

            await Log(""[SOCKS5] Connect #"" + connId + "" -> "" + addr + "":"" + port);

            Socket sock = null;
            bool connected = false;
            Exception connectEx = null;
            bool outerError = false;
            string outerErrorMsg = null;

            try
            {
                sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                sock.NoDelay = true;

                try
                {
                    IPAddress[] addresses = Dns.GetHostAddresses(addr);
                    IPAddress target = null;
                    for (int i = 0; i < addresses.Length; i++)
                    {
                        if (addresses[i].AddressFamily == AddressFamily.InterNetwork)
                        {
                            target = addresses[i];
                            break;
                        }
                    }
                    if (target == null && addresses.Length > 0)
                        target = addresses[0];
                    if (target == null)
                        throw new SocketException((int)SocketError.HostNotFound);

                    IAsyncResult ar = sock.BeginConnect(target, port, null, null);
                    bool success = ar.AsyncWaitHandle.WaitOne(timeout);
                    if (success && sock.Connected)
                    {
                        sock.EndConnect(ar);
                        connected = true;
                    }
                    else
                    {
                        try { sock.EndConnect(ar); } catch { }
                        connectEx = new SocketException((int)SocketError.TimedOut);
                    }
                }
                catch (SocketException ex)
                {
                    connectEx = ex;
                }
                catch (Exception ex)
                {
                    connectEx = ex;
                }

                if (!connected)
                {
                    byte errCode;
                    SocketException sex = connectEx as SocketException;
                    if (sex != null && sex.SocketErrorCode == SocketError.TimedOut) errCode = 0x06;
                    else if (sex != null && sex.SocketErrorCode == SocketError.HostUnreachable) errCode = 0x04;
                    else if (sex != null && sex.SocketErrorCode == SocketError.ConnectionRefused) errCode = 0x05;
                    else if (sex != null && sex.SocketErrorCode == SocketError.NetworkUnreachable) errCode = 0x03;
                    else errCode = 0x01;

                    byte[] err = new byte[6];
                    err[0] = 0x11;
                    Buffer.BlockCopy(BitConverter.GetBytes(connId), 0, err, 1, 4);
                    err[5] = errCode;
                    await _send(err);
                    try { sock.Close(); } catch { }
                    return;
                }

                ConnState cs = new ConnState();
                cs.Socket = sock;
                cs.ConnId = connId;
                _connections[connId] = cs;

                IPEndPoint ep = (IPEndPoint)sock.LocalEndPoint;
                byte[] addrBytes = ep.Address.GetAddressBytes();
                byte[] resp = new byte[11];
                resp[0] = 0x12;
                Buffer.BlockCopy(BitConverter.GetBytes(connId), 0, resp, 1, 4);
                Buffer.BlockCopy(addrBytes, 0, resp, 5, Math.Min(4, addrBytes.Length));
                resp[9] = (byte)(ep.Port >> 8);
                resp[10] = (byte)(ep.Port & 0xFF);
                await _send(resp);

                await Log(""[SOCKS5] Connected #"" + connId + "" -> "" + addr + "":"" + port);
                await ReadFromRemoteLoop(cs);
            }
            catch (Exception ex)
            {
                outerError = true;
                outerErrorMsg = ex.Message;
            }

            if (outerError)
            {
                byte[] errPacket = new byte[6];
                errPacket[0] = 0x11;
                Buffer.BlockCopy(BitConverter.GetBytes(connId), 0, errPacket, 1, 4);
                errPacket[5] = 0x01;
                try { await _send(errPacket); } catch { }
                await Log(""[SOCKS5] Error #"" + connId + "": "" + outerErrorMsg);
            }

            ConnState removed;
            _connections.TryRemove(connId, out removed);
            try { if (sock != null) sock.Shutdown(SocketShutdown.Both); } catch { }
            try { if (sock != null) sock.Close(); } catch { }

            byte[] cls = new byte[5];
            cls[0] = 0x14;
            Buffer.BlockCopy(BitConverter.GetBytes(connId), 0, cls, 1, 4);
            try { await _send(cls); } catch { }

            await Log(""[SOCKS5] Closed #"" + connId);
        }

        async Task ReadFromRemoteLoop(ConnState cs)
        {
            byte[] buf = new byte[8192];
            try
            {
                while (!cs.Closed && !cs.Cts.IsCancellationRequested && cs.Socket.Connected)
                {
                    int read = 0;
                    try
                    {
                        read = cs.Socket.Receive(buf, 0, buf.Length, SocketFlags.None);
                    }
                    catch { break; }

                    if (read <= 0) break;

                    byte[] msg = new byte[5 + read];
                    msg[0] = 0x13;
                    Buffer.BlockCopy(BitConverter.GetBytes(cs.ConnId), 0, msg, 1, 4);
                    Buffer.BlockCopy(buf, 0, msg, 5, read);
                    await _send(msg);
                }
            }
            catch { }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext ctx)
        {
            if (!_host.IsPluginActive(ctx.ClientId, PluginId))
                _ = Task.Run(async () => { try { await _host.StartPluginForClient(ctx.ClientId, PluginId); } catch { } });
            var ui = new Socks5UI(ctx, _host);
            _uis[ctx.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string cid, byte[] data)
        {
            if (data != null && data.Length > 0 && _uis.TryGetValue(cid, out var ui))
                ui.OnData(data);
            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string cid)
        {
            if (_uis.TryRemove(cid, out var ui)) ui.Dispose();
            return Task.CompletedTask;
        }

        public void Dispose() { foreach (var u in _uis.Values) u.Dispose(); _uis.Clear(); }
    }

    [SupportedOSPlatform("windows")]
    public class Socks5Server : IDisposable
    {
        private TcpListener _listener;
        private readonly PluginContext _ctx;
        private volatile bool _running;
        private int _nextConnId;
        private readonly ConcurrentDictionary<int, Socks5Connection> _conns = new();
        private readonly Action<string> _log;
        private readonly Action<int> _updateCount;
        private long _totalBytesIn, _totalBytesOut;
        private int _totalConns;

        public int Port { get; private set; }
        public bool IsRunning => _running;
        public int ActiveConnections => _conns.Count;
        public long TotalBytesIn => Interlocked.Read(ref _totalBytesIn);
        public long TotalBytesOut => Interlocked.Read(ref _totalBytesOut);
        public int TotalConnections => _totalConns;

        public Socks5Server(PluginContext ctx, Action<string> log, Action<int> updateCount)
        {
            _ctx = ctx;
            _log = log;
            _updateCount = updateCount;
        }

        public void Start(int port, string bindAddr = "127.0.0.1")
        {
            if (_running) return;
            Port = port;
            var ip = IPAddress.Parse(bindAddr);
            _listener = new TcpListener(ip, port);
            _listener.Start();
            _running = true;
            _log($"SOCKS5 listening on {bindAddr}:{port}");
            _ = AcceptLoop();
        }

        public void Stop()
        {
            _running = false;
            try { _listener?.Stop(); } catch { }
            foreach (var c in _conns.Values) c.Close();
            _conns.Clear();
            _updateCount(0);
            _log("SOCKS5 stopped");
        }

        private async Task AcceptLoop()
        {
            while (_running)
            {
                TcpClient client = null;
                try { client = await _listener.AcceptTcpClientAsync(); }
                catch { if (!_running) break; continue; }

                int connId = Interlocked.Increment(ref _nextConnId);
                Interlocked.Increment(ref _totalConns);
                var conn = new Socks5Connection(connId, client, _ctx, _log, this);
                _conns[connId] = conn;
                _updateCount(_conns.Count);
                _ = Task.Run(async () =>
                {
                    try { await conn.HandleAsync(); }
                    catch (Exception ex) { _log($"#{connId} Error: {ex.Message}"); }
                    finally
                    {
                        _conns.TryRemove(connId, out _);
                        _updateCount(_conns.Count);
                        conn.Close();
                    }
                });
            }
        }

        public void HandleClientData(byte[] data)
        {
            if (data == null || data.Length < 5) return;
            int connId = BitConverter.ToInt32(data, 1);

            switch (data[0])
            {
                case 0x13:
                    if (_conns.TryGetValue(connId, out var conn) && data.Length > 5)
                    {
                        int len = data.Length - 5;
                        Interlocked.Add(ref _totalBytesIn, len);
                        conn.OnRemoteData(data, 5, len);
                    }
                    break;
                case 0x11:
                    if (_conns.TryGetValue(connId, out var errConn))
                    {
                        byte errCode = data.Length > 5 ? data[5] : (byte)0x01;
                        errConn.OnConnectError(errCode);
                    }
                    break;
                case 0x12:
                    if (_conns.TryGetValue(connId, out var okConn) && data.Length >= 11)
                    {
                        byte[] addr = new byte[4];
                        Buffer.BlockCopy(data, 5, addr, 0, 4);
                        int port = (data[9] << 8) | data[10];
                        okConn.OnConnectSuccess(addr, port);
                    }
                    break;
                case 0x14:
                    if (_conns.TryRemove(connId, out var clConn))
                    {
                        clConn.Close();
                        _updateCount(_conns.Count);
                    }
                    break;
            }
        }

        public void AddBytesOut(int count)
        {
            Interlocked.Add(ref _totalBytesOut, count);
        }

        public void Dispose()
        {
            Stop();
        }
    }

    public class Socks5Connection
    {
        private readonly int _id;
        private readonly TcpClient _client;
        private readonly PluginContext _ctx;
        private readonly Action<string> _log;
        private readonly Socks5Server _server;
        private NetworkStream _stream;
        private volatile bool _closed;
        private readonly ManualResetEventSlim _connectEvent = new(false);
        private byte _connectResult;
        private byte[] _boundAddr;
        private int _boundPort;
        private readonly ConcurrentQueue<byte[]> _remoteDataQueue = new();
        private readonly SemaphoreSlim _remoteDataSignal = new(0);

        public Socks5Connection(int id, TcpClient client, PluginContext ctx, Action<string> log, Socks5Server server)
        {
            _id = id; _client = client; _ctx = ctx; _log = log; _server = server;
            _client.NoDelay = true;
        }

        public async Task HandleAsync()
        {
            _stream = _client.GetStream();

            var hdr = new byte[2];
            int r = await ReadExactAsync(_stream, hdr, 0, 2);
            if (r < 2 || hdr[0] != 0x05) { _log($"#{_id} Invalid SOCKS version"); return; }

            int nMethods = hdr[1];
            var methods = new byte[nMethods];
            r = await ReadExactAsync(_stream, methods, 0, nMethods);
            if (r < nMethods) return;

            await _stream.WriteAsync(new byte[] { 0x05, 0x00 }, 0, 2);

            var req = new byte[4];
            r = await ReadExactAsync(_stream, req, 0, 4);
            if (r < 4 || req[0] != 0x05) return;

            byte cmd = req[1];
            byte atyp = req[3];

            if (cmd != 0x01)
            {
                await SendReply(0x07, new byte[] { 0, 0, 0, 0 }, 0);
                return;
            }

            string destAddr;

            switch (atyp)
            {
                case 0x01:
                    var ipv4 = new byte[4];
                    await ReadExactAsync(_stream, ipv4, 0, 4);
                    destAddr = new IPAddress(ipv4).ToString();
                    break;
                case 0x03:
                    var dlenBuf = new byte[1];
                    await ReadExactAsync(_stream, dlenBuf, 0, 1);
                    var domainBuf = new byte[dlenBuf[0]];
                    await ReadExactAsync(_stream, domainBuf, 0, domainBuf.Length);
                    destAddr = Encoding.ASCII.GetString(domainBuf);
                    break;
                case 0x04:
                    var ipv6 = new byte[16];
                    await ReadExactAsync(_stream, ipv6, 0, 16);
                    destAddr = new IPAddress(ipv6).ToString();
                    break;
                default:
                    await SendReply(0x08, new byte[] { 0, 0, 0, 0 }, 0);
                    return;
            }

            var portBuf = new byte[2];
            await ReadExactAsync(_stream, portBuf, 0, 2);
            int destPort = (portBuf[0] << 8) | portBuf[1];

            _log($"#{_id} CONNECT {destAddr}:{destPort}");

            var addrBytes = Encoding.UTF8.GetBytes(destAddr);
            var msg = new byte[13 + addrBytes.Length];
            msg[0] = 0x10;
            Buffer.BlockCopy(BitConverter.GetBytes(_id), 0, msg, 1, 4);
            msg[5] = (byte)(addrBytes.Length & 0xFF);
            msg[6] = (byte)((addrBytes.Length >> 8) & 0xFF);
            Buffer.BlockCopy(addrBytes, 0, msg, 7, addrBytes.Length);
            msg[7 + addrBytes.Length] = (byte)(destPort & 0xFF);
            msg[8 + addrBytes.Length] = (byte)((destPort >> 8) & 0xFF);
            Buffer.BlockCopy(BitConverter.GetBytes(10000), 0, msg, 9 + addrBytes.Length, 4);

            await _ctx.SendToClient(msg);

            if (!_connectEvent.Wait(15000))
            {
                _log($"#{_id} Connect timeout");
                await SendReply(0x06, new byte[] { 0, 0, 0, 0 }, 0);
                return;
            }

            if (_connectResult != 0x00)
            {
                _log($"#{_id} Connect failed: 0x{_connectResult:X2}");
                await SendReply(_connectResult, new byte[] { 0, 0, 0, 0 }, 0);
                return;
            }

            await SendReply(0x00, _boundAddr ?? new byte[] { 0, 0, 0, 0 }, _boundPort);
            _log($"#{_id} Connected -> {destAddr}:{destPort}");

            await RelayAsync();
        }

        private static async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead);
                if (read <= 0) return totalRead;
                totalRead += read;
            }
            return totalRead;
        }

        private async Task SendReply(byte rep, byte[] addr, int port)
        {
            var reply = new byte[10];
            reply[0] = 0x05;
            reply[1] = rep;
            reply[2] = 0x00;
            reply[3] = 0x01;
            if (addr != null && addr.Length >= 4)
                Buffer.BlockCopy(addr, 0, reply, 4, 4);
            reply[8] = (byte)(port >> 8);
            reply[9] = (byte)(port & 0xFF);
            await _stream.WriteAsync(reply, 0, 10);
        }

        private async Task RelayAsync()
        {
            var buf = new byte[8192];
            var cts = new CancellationTokenSource();

            var localTask = Task.Run(async () =>
            {
                try
                {
                    while (!_closed && !cts.IsCancellationRequested)
                    {
                        int read = await _stream.ReadAsync(buf, 0, buf.Length);
                        if (read <= 0) break;

                        _server.AddBytesOut(read);

                        var msg = new byte[5 + read];
                        msg[0] = 0x20;
                        Buffer.BlockCopy(BitConverter.GetBytes(_id), 0, msg, 1, 4);
                        Buffer.BlockCopy(buf, 0, msg, 5, read);
                        await _ctx.SendToClient(msg);
                    }
                }
                catch { }
                cts.Cancel();
            });

            var remoteTask = Task.Run(async () =>
            {
                try
                {
                    while (!_closed && !cts.IsCancellationRequested)
                    {
                        if (await _remoteDataSignal.WaitAsync(1000))
                        {
                            byte[] data;
                            while (_remoteDataQueue.TryDequeue(out data))
                            {
                                await _stream.WriteAsync(data, 0, data.Length);
                            }
                        }
                    }
                }
                catch { }
                cts.Cancel();
            });

            await Task.WhenAny(localTask, remoteTask);
            cts.Cancel();

            var cls = new byte[5];
            cls[0] = 0x21;
            Buffer.BlockCopy(BitConverter.GetBytes(_id), 0, cls, 1, 4);
            try { await _ctx.SendToClient(cls); } catch { }
        }

        public void OnConnectSuccess(byte[] addr, int port)
        {
            _connectResult = 0x00;
            _boundAddr = addr;
            _boundPort = port;
            _connectEvent.Set();
        }

        public void OnConnectError(byte errCode)
        {
            _connectResult = errCode;
            _connectEvent.Set();
        }

        public void OnRemoteData(byte[] data, int offset, int length)
        {
            var copy = new byte[length];
            Buffer.BlockCopy(data, offset, copy, 0, length);
            _remoteDataQueue.Enqueue(copy);
            _remoteDataSignal.Release();
        }

        public void Close()
        {
            _closed = true;
            _connectEvent.Set();
            _remoteDataSignal.Release();
            try { _stream?.Close(); } catch { }
            try { _client?.Close(); } catch { }
        }
    }

}
