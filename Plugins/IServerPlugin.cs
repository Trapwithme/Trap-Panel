// File: IServerPlugin.cs
#nullable disable

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace WpfApp.Plugins
{
    public interface IServerPlugin : IDisposable
    {
        string PluginId { get; }
        string DisplayName { get; }
        string Version { get; }
        string Description { get; }

        string GetClientCode();
        UserControl CreateUI(PluginContext context);
        Task OnClientDataReceived(string clientId, byte[] data);
        Task OnClientDisconnected(string clientId);
        Task Initialize(PluginHost host);
        Task Shutdown();
    }

    /// <summary>
    /// Implement this alongside IServerPlugin for plugins that manage multiple clients in a single shared tab.
    /// </summary>
    public interface IMultiClientPlugin
    {
        UserControl CreateSharedUI();
        void AddClient(string clientId, PluginContext context);
        void RemoveClient(string clientId);
        void RemoveAllClients();
        List<string> GetManagedClientIds();
    }
}