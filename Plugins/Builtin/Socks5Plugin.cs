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

    [SupportedOSPlatform("windows")]
    public class Socks5UI : UserControl, IDisposable
    {
        private readonly PluginContext _ctx;
        private readonly PluginHost _host;
        private Socks5Server _server;
        private bool _disposed;
        private bool _clientReady;
        private DispatcherTimer _statsTimer;

        private readonly TextBox _portBox;
        private readonly TextBox _bindBox;
        private readonly Button _startBtn;
        private readonly Button _stopBtn;
        private readonly TextBlock _statusText;
        private readonly TextBlock _connCountText;
        private readonly TextBlock _bytesInText;
        private readonly TextBlock _bytesOutText;
        private readonly TextBlock _totalConnsText;
        private readonly TextBox _logBox;
        private readonly Border _indicator;
        private int _logLines;

        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        SolidColorBrush BgDark => B("BackgroundBrush");
        SolidColorBrush BgMed => B("SurfaceBrush");
        SolidColorBrush BgLight => B("SurfaceLightBrush");
        SolidColorBrush BdBrush => B("BorderBrush");
        SolidColorBrush TxBrush => B("TextPrimaryBrush");
        SolidColorBrush DmBrush => B("TextSecondaryBrush");
        SolidColorBrush GnBrush => B("SuccessBrush");
        SolidColorBrush RdBrush => B("DangerBrush");
        SolidColorBrush BlBrush => B("PrimaryBrush");
        SolidColorBrush YlBrush => B("WarningBrush");
        SolidColorBrush DsBrush => B("ButtonBgBrush");
        Color ButtonBorderClr => C("ButtonBorderColor");

        public Socks5UI(PluginContext ctx, PluginHost host)
        {
            _ctx = ctx;
            _host = host;

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // Row 0: Config toolbar
            var configBorder = new Border
            {
                Background = BgMed,
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(12, 8, 12, 8)
            };
            var configPanel = new DockPanel { LastChildFill = false };

            _indicator = new Border
            {
                Width = 10,
                Height = 10,
                CornerRadius = new CornerRadius(5),
                Background = DsBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Waiting for client..."
            };
            _statusText = new TextBlock
            {
                Text = "Waiting for client...",
                Foreground = YlBrush,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            var leftConfig = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            leftConfig.Children.Add(_indicator);
            leftConfig.Children.Add(_statusText);
            leftConfig.Children.Add(Lbl("Bind:"));
            _bindBox = MakeTextBox("127.0.0.1");
            _bindBox.Width = 140;
            leftConfig.Children.Add(_bindBox);
            leftConfig.Children.Add(Lbl("Port:"));
            _portBox = MakeTextBox("1080");
            _portBox.Width = 80;
            leftConfig.Children.Add(_portBox);
            DockPanel.SetDock(leftConfig, Dock.Left);
            configPanel.Children.Add(leftConfig);

            _startBtn = MakeBtn("Start", C("SuccessColor"), C("SuccessHoverColor"));
            _startBtn.Click += (s, e) => StartProxy();
            _stopBtn = MakeBtn("Stop", C("DangerColor"), C("DangerHoverColor"));
            _stopBtn.IsEnabled = false;
            _stopBtn.Click += (s, e) => StopProxy();
            var rightBtns = new StackPanel { Orientation = Orientation.Horizontal };
            rightBtns.Children.Add(_startBtn);
            rightBtns.Children.Add(_stopBtn);
            DockPanel.SetDock(rightBtns, Dock.Right);
            configPanel.Children.Add(rightBtns);

            configBorder.Child = configPanel;
            Grid.SetRow(configBorder, 0);
            root.Children.Add(configBorder);

            // Row 1: Stats
            var statsBorder = new Border
            {
                Background = BgMed,
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 10, 16, 10)
            };
            var statsPanel = new StackPanel { Orientation = Orientation.Horizontal };

            _connCountText = MakeStatValue("0", GnBrush);
            _totalConnsText = MakeStatValue("0", BlBrush);
            _bytesInText = MakeStatValue("0 B", BlBrush);
            _bytesOutText = MakeStatValue("0 B", BlBrush);

            statsPanel.Children.Add(MakeStatGroup("Active", _connCountText));
            statsPanel.Children.Add(MakeStatSep());
            statsPanel.Children.Add(MakeStatGroup("Total", _totalConnsText));
            statsPanel.Children.Add(MakeStatSep());
            statsPanel.Children.Add(MakeStatGroup("↓ Received", _bytesInText));
            statsPanel.Children.Add(MakeStatSep());
            statsPanel.Children.Add(MakeStatGroup("↑ Sent", _bytesOutText));

            statsBorder.Child = statsPanel;
            Grid.SetRow(statsBorder, 1);
            root.Children.Add(statsBorder);

            // Row 3: Log
            var logOuter = new DockPanel();

            var logHeader = new Border
            {
                Background = BgMed,
                Padding = new Thickness(12, 6, 12, 6),
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            var logHeaderPanel = new DockPanel();
            var clearBtn = MakeBtn("Clear", C("SurfaceLightColor"), C("ButtonBgHoverColor"));
            clearBtn.Click += (s, e) => { _logBox.Text = ""; _logLines = 0; };
            DockPanel.SetDock(clearBtn, Dock.Right);
            logHeaderPanel.Children.Add(clearBtn);
            logHeaderPanel.Children.Add(new TextBlock
            {
                Text = "Activity Log",
                Foreground = DmBrush,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            logHeader.Child = logHeaderPanel;
            DockPanel.SetDock(logHeader, Dock.Top);
            logOuter.Children.Add(logHeader);

            _logBox = new TextBox
            {
                Background = BgDark,
                Foreground = GnBrush,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11.5,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(12, 8, 12, 8),
                CaretBrush = Brushes.Transparent,
                AcceptsReturn = true,
                Style = null
            };
            logOuter.Children.Add(_logBox);
            Grid.SetRow(logOuter, 2);
            root.Children.Add(logOuter);

            Content = root;
            Background = BgDark;

            _statsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _statsTimer.Tick += (s, e) => UpdateStats();
            _statsTimer.Start();

            Log("SOCKS5 proxy plugin initialized");
            Log("Waiting for client plugin to connect...");
        }

        private TextBlock MakeStatValue(string text, SolidColorBrush color)
        {
            return new TextBlock
            {
                Text = text,
                Foreground = color,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
        }

        private StackPanel MakeStatGroup(string label, TextBlock value)
        {
            var sp = new StackPanel { Margin = new Thickness(0, 0, 20, 0) };
            sp.Children.Add(new TextBlock
            {
                Text = label,
                Foreground = DmBrush,
                FontSize = 10,
                Margin = new Thickness(0, 0, 0, 2)
            });
            sp.Children.Add(value);
            return sp;
        }

        private Border MakeStatSep()
        {
            return new Border
            {
                Width = 1,
                Background = new SolidColorBrush(C("BorderColor")),
                Margin = new Thickness(12, 2, 20, 2)
            };
        }

        private void UpdateStats()
        {
            if (_disposed || _server == null) return;
            _connCountText.Text = _server.ActiveConnections.ToString();
            _totalConnsText.Text = _server.TotalConnections.ToString();
            _bytesInText.Text = FormatBytes(_server.TotalBytesIn);
            _bytesOutText.Text = FormatBytes(_server.TotalBytesOut);
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        }

        private void StartProxy()
        {
            if (!_clientReady)
            {
                Log("Client plugin not ready yet");
                return;
            }

            if (!int.TryParse(_portBox.Text.Trim(), out int port) || port < 1 || port > 65535)
            {
                Log("Invalid port number");
                return;
            }

            string bind = _bindBox.Text.Trim();
            if (string.IsNullOrEmpty(bind)) bind = "127.0.0.1";

            try
            {
                _server = new Socks5Server(_ctx, s => Log(s), c => { });
                _server.Start(port, bind);
                _startBtn.IsEnabled = false;
                _stopBtn.IsEnabled = true;
                _portBox.IsEnabled = false;
                _bindBox.IsEnabled = false;
                _statusText.Text = $"Running on {bind}:{port}";
                _statusText.Foreground = GnBrush;
                _indicator.Background = GnBrush;
                _indicator.ToolTip = "Proxy running";
            }
            catch (Exception ex)
            {
                Log($"Failed to start: {ex.Message}");
            }
        }

        private void StopProxy()
        {
            _server?.Stop();
            _server?.Dispose();
            _server = null;
            _startBtn.IsEnabled = _clientReady;
            _stopBtn.IsEnabled = false;
            _portBox.IsEnabled = true;
            _bindBox.IsEnabled = true;
            _statusText.Text = "Stopped";
            _statusText.Foreground = RdBrush;
            _indicator.Background = RdBrush;
            _indicator.ToolTip = "Proxy stopped";
        }

        private void Log(string msg)
        {
            if (_disposed) return;
            var line = $"[{DateTime.Now:HH:mm:ss}] {msg}\n";
            if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => LogInternal(line)); return; }
            LogInternal(line);
        }

        private void LogInternal(string line)
        {
            if (_disposed) return;
            _logBox.AppendText(line);
            _logLines++;
            if (_logLines > 500)
            {
                var t = _logBox.Text;
                int cut = 0;
                for (int i = 0; i < 50 && cut < t.Length; i++)
                {
                    int nl = t.IndexOf('\n', cut);
                    if (nl < 0) break;
                    cut = nl + 1;
                }
                if (cut > 0) { _logBox.Text = t.Substring(cut); _logLines -= 50; }
            }
            _logBox.ScrollToEnd();
        }

        public void OnData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;

            switch (data[0])
            {
                case 0x01:
                    Dispatcher.BeginInvoke(() =>
                    {
                        _clientReady = true;
                        _startBtn.IsEnabled = true;
                        _statusText.Text = "Client ready";
                        _statusText.Foreground = BlBrush;
                        _indicator.Background = BlBrush;
                        _indicator.ToolTip = "Client connected";
                        Log("Client plugin connected and ready");
                    });
                    break;
                case 0xFD:
                    if (data.Length > 1)
                        Log(Encoding.UTF8.GetString(data, 1, data.Length - 1));
                    break;
                case 0xFE:
                    if (data.Length > 2)
                        Log($"[ACK] {Encoding.UTF8.GetString(data, 2, data.Length - 2)}");
                    break;
                case 0x11:
                case 0x12:
                case 0x13:
                case 0x14:
                    _server?.HandleClientData(data);
                    break;
            }
        }

        private TextBlock Lbl(string text)
        {
            return new TextBlock
            {
                Text = text,
                Foreground = DmBrush,
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 6, 0)
            };
        }

        private TextBox MakeTextBox(string text)
        {
            return new TextBox
            {
                Text = text,
                Background = BgDark,
                Foreground = TxBrush,
                BorderBrush = BdBrush,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 7, 10, 7),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                CaretBrush = TxBrush,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 4, 0),
                Style = null
            };
        }

        private Button MakeBtn(string text, Color bg, Color hover, SolidColorBrush fg = null)
        {
            var nb = new SolidColorBrush(bg); var hb = new SolidColorBrush(hover);
            var bb = new SolidColorBrush(ButtonBorderClr); var db = new SolidColorBrush(C("ButtonBgColor"));
            var tp = new ControlTemplate(typeof(Button));
            var bd = new FrameworkElementFactory(typeof(Border), "bd");
            bd.SetValue(Border.BackgroundProperty, nb); bd.SetValue(Border.BorderBrushProperty, bb);
            bd.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            bd.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            bd.SetValue(Border.SnapsToDevicePixelsProperty, true);
            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            bd.AppendChild(cp); tp.VisualTree = bd;
            var h = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; h.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); tp.Triggers.Add(h);
            var p = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(p);
            var d = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; d.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); d.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tp.Triggers.Add(d);
            return new Button { Content = text, Template = tp, Foreground = fg ?? TxBrush, Cursor = Cursors.Hand, Margin = new Thickness(6, 0, 4, 0), FontSize = 13, FontWeight = FontWeights.SemiBold };
        }

        public void Dispose()
        {
            _disposed = true;
            _statsTimer?.Stop();
            _server?.Dispose();
        }
    }
}