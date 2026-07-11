// File: ShutdownPlugin.cs
#nullable disable

using System;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Windows.Controls;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class ShutdownPlugin : IServerPlugin, IOneClickPlugin
    {
        private PluginHost _host;
        private const byte OP_SHUTDOWN = 0x00;

        public string PluginId => "shutdown";
        public string DisplayName => "Shutdown Machine";
        public string Version => "1.0.0";
        public string Description => "One-click: forces the target machine to shut down immediately. No confirmation.";

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _host.Log("[SHUTDOWN] Plugin initialized");
            return Task.CompletedTask;
        }

        public Task Shutdown() => Task.CompletedTask;

        public string GetClientCode()
        {
            return @"
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_shutdown
{
    public class Main
    {
        private Func<byte[], Task> _send;
        private Func<Task<byte[]>> _receive;

        public async Task Run(Func<byte[], Task> send, Func<Task<byte[]>> receive)
        {
            _send = send;
            _receive = receive;

            await _send(new byte[] { 0xFE });

            while (true)
            {
                byte[] data = await _receive();
                if (data == null || data.Length == 0) break;

                byte opcode = data[0];

                try
                {
                    switch (opcode)
                    {
                        case 0x00:
                            int delay = 0;
                            if (data.Length >= 5)
                                delay = BitConverter.ToInt32(data, 1);
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = ""shutdown"",
                                Arguments = $""/s /f /t {delay}"",
                                CreateNoWindow = true,
                                UseShellExecute = false
                            });
                            break;
                    }
                }
                catch { }
            }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context) => null;

        public Task Execute(PluginContext context)
        {
            // payload: 4-byte delay (seconds) = 0
            return context.SendToClient(new byte[] { OP_SHUTDOWN, 0, 0, 0, 0 });
        }

        public Task OnClientDataReceived(string clientId, byte[] data) => Task.CompletedTask;

        public Task OnClientDisconnected(string clientId) => Task.CompletedTask;

        public void Dispose() { }
    }
}
