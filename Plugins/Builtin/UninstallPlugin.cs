// File: UninstallPlugin.cs
#nullable disable

using System;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Windows.Controls;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class UninstallPlugin : IServerPlugin, IOneClickPlugin
    {
        private PluginHost _host;
        private const byte OP_UNINSTALL = 0x00;

        public string PluginId => "uninstall";
        public string DisplayName => "Uninstall Client";
        public string Version => "1.0.0";
        public string Description => "One-click: removes the client from the target machine and terminates it. No confirmation.";

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _host.Log("[UNINSTALL] Plugin initialized");
            return Task.CompletedTask;
        }

        public Task Shutdown() => Task.CompletedTask;

        public string GetClientCode()
        {
            return @"
using System;
using System.Diagnostics;

namespace ClientPlugin_uninstall
{
    public class Main
    {
        public async System.Threading.Tasks.Task Run(System.Func<byte[], System.Threading.Tasks.Task> send, System.Func<System.Threading.Tasks.Task<byte[]>> receive)
        {
            await send(new byte[] { 0xFE });

            while (true)
            {
                byte[] data = await receive();
                if (data == null || data.Length == 0) break;

                if (data[0] == 0x00)
                {
                    Process.GetCurrentProcess().Kill();
                }
            }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context) => null;

        public Task Execute(PluginContext context)
        {
            return context.SendToClient(new byte[] { OP_UNINSTALL });
        }

        public Task OnClientDataReceived(string clientId, byte[] data) => Task.CompletedTask;

        public Task OnClientDisconnected(string clientId) => Task.CompletedTask;

        public void Dispose() { }
    }
}
