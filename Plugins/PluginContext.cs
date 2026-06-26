// File: PluginContext.cs
#nullable disable

using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace WpfApp.Plugins
{
    [SupportedOSPlatform("windows")]
    public class PluginContext
    {
        public string ClientId { get; }
        public string PluginId { get; }
        private readonly PluginHost _host;

        public PluginContext(string clientId, string pluginId, PluginHost host)
        {
            ClientId = clientId;
            PluginId = pluginId;
            _host = host;
        }

        public Task SendToClient(byte[] data)
        {
            return _host.SendPluginDataToClient(ClientId, PluginId, data);
        }

        public void Log(string message)
        {
            _host.Log($"[{PluginId}] {message}");
        }

        public Task StopPlugin()
        {
            return _host.StopPluginForClient(ClientId, PluginId);
        }
    }
}