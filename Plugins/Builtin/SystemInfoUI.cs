using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    [SupportedOSPlatform("windows")]
    public class SystemInfoUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];

        private Color BgColor => C("BackgroundColor");
        private Color SurfaceColor => C("SurfaceColor");
        private Color SurfaceLightColor => C("SurfaceLightColor");
        private Color BorderClr => C("BorderColor");
        private Color TextPrimary => C("TextPrimaryColor");
        private Color TextSecondary => C("TextSecondaryColor");
        private Color AccentBlue => C("PrimaryColor");
        private Color PrimaryHoverColor => C("PrimaryHoverColor");

        private readonly SystemInfoPlugin _plugin;
        private readonly ConcurrentDictionary<string, PluginContext> _clients = new();
        private readonly ConcurrentDictionary<string, string> _clientInfo = new();

        private readonly ListBox _clientList;
        private readonly TextBlock _statusLabel;
        private readonly ItemsControl _infoTree;
        private readonly StackPanel _infoPanel;
        private readonly Button _refreshBtn;

        private string _selectedClient = null;
        private int _refreshVersion = 0;
        private readonly ConcurrentDictionary<string, int> _clientVersion = new();

        public SystemInfoUI(SystemInfoPlugin plugin)
        {
            _plugin = plugin;
            Background = new SolidColorBrush(BgColor);

            var root = new Grid { Margin = new Thickness(0) };
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left sidebar: client list
            var sidebar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 1, 0)
            };

            var sidebarStack = new StackPanel { Margin = new Thickness(0) };

            var sideHeader = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                Padding = new Thickness(10, 8, 10, 8),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            sideHeader.Child = new TextBlock
            {
                Text = "CLIENTS",
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(TextSecondary)
            };
            sidebarStack.Children.Add(sideHeader);

            _clientList = new ListBox
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderThickness = new Thickness(0),
                Foreground = new SolidColorBrush(TextPrimary),
                FontSize = 12,
                Padding = new Thickness(0),
                Margin = new Thickness(0)
            };
            _clientList.SelectionChanged += (s, e) =>
            {
                if (_clientList.SelectedItem is ListBoxItem item && item.Tag is string cid)
                {
                    _selectedClient = cid;
                    ShowInfoForClient(cid);
                }
            };
            sidebarStack.Children.Add(_clientList);
            sidebar.Child = sidebarStack;
            Grid.SetColumn(sidebar, 0);
            root.Children.Add(sidebar);

            // Splitter
            var splitter = new GridSplitter
            {
                Width = 3,
                Background = new SolidColorBrush(BorderClr),
                HorizontalAlignment = HorizontalAlignment.Stretch,
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0)
            };
            Grid.SetColumn(splitter, 1);
            root.Children.Add(splitter);

            // Right panel: info display
            var rightPanel = new Grid { Background = new SolidColorBrush(BgColor) };
            rightPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rightPanel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            rightPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Toolbar
            var toolbar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 6, 10, 6)
            };
            var toolbarStack = new StackPanel { Orientation = Orientation.Horizontal };

            _refreshBtn = MakeButton("REFRESH", AccentBlue);
            _refreshBtn.Click += (s, e) => RefreshSelected();
            toolbarStack.Children.Add(_refreshBtn);

            _statusLabel = new TextBlock
            {
                Text = "Select a client and click Refresh",
                FontSize = 11,
                Foreground = new SolidColorBrush(TextSecondary),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            toolbarStack.Children.Add(_statusLabel);
            toolbar.Child = toolbarStack;
            Grid.SetRow(toolbar, 0);
            rightPanel.Children.Add(toolbar);

            // Info panel with scroll
            var scroll = new ScrollViewer
            {
                Background = new SolidColorBrush(BgColor),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(10),
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };

            _infoPanel = new StackPanel { Margin = new Thickness(0) };
            _infoTree = new ItemsControl
            {
                ItemsPanel = new ItemsPanelTemplate(),
                ItemTemplate = null
            };
            scroll.Content = _infoPanel;
            Grid.SetRow(scroll, 1);
            rightPanel.Children.Add(scroll);

            // Status bar at bottom
            var statusBar = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(10, 4, 10, 4),
                Height = 26
            };
            var statusText = new TextBlock
            {
                Text = "System Info v1.0",
                FontSize = 10,
                Foreground = new SolidColorBrush(TextSecondary),
                VerticalAlignment = VerticalAlignment.Center
            };
            statusBar.Child = statusText;
            Grid.SetRow(statusBar, 2);
            rightPanel.Children.Add(statusBar);

            Grid.SetColumn(rightPanel, 2);
            root.Children.Add(rightPanel);

            Content = root;
        }

        private Button MakeButton(string text, Color bgColor)
        {
            var btn = new Button
            {
                Content = new TextBlock
                {
                    Text = text,
                    FontSize = 12,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(C("TextPrimaryColor"))
                },
                Background = new SolidColorBrush(bgColor),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 5, 10, 5),
                Cursor = Cursors.Hand,
                FontFamily = new FontFamily("Segoe UI")
            };
            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(PrimaryHoverColor)));
            var trigger = new Style(typeof(Button));
            trigger.Triggers.Add(hover);
            btn.Style = trigger;
            return btn;
        }

        public void OnClientAdded(string clientId)
        {
            if (!Application.Current.Dispatcher.CheckAccess())
            {
                Application.Current.Dispatcher.BeginInvoke(new Action(() => OnClientAdded(clientId)));
                return;
            }
            var item = new ListBoxItem
            {
                Content = new TextBlock { Text = clientId, FontSize = 11, Foreground = new SolidColorBrush(TextPrimary) },
                Tag = clientId,
                Padding = new Thickness(8, 4, 8, 4),
                Background = new SolidColorBrush(SurfaceColor),
                BorderThickness = new Thickness(0)
            };
            item.MouseEnter += (s, e) => item.Background = new SolidColorBrush(SurfaceLightColor);
            item.MouseLeave += (s, e) => item.Background = new SolidColorBrush(SurfaceColor);
            _clientList.Items.Add(item);
            if (_clientList.Items.Count == 1)
                _clientList.SelectedItem = item;
        }

        public void OnClientRemoved(string clientId)
        {
            var toRemove = _clientList.Items.OfType<ListBoxItem>().FirstOrDefault(i => (string)i.Tag == clientId);
            if (toRemove != null)
                _clientList.Items.Remove(toRemove);
            _clientInfo.TryRemove(clientId, out _);
            if (_selectedClient == clientId)
            {
                _selectedClient = null;
                _infoPanel.Children.Clear();
                _statusLabel.Text = "Client disconnected";
            }
        }

        private async void RefreshSelected()
        {
            if (_selectedClient == null) return;
            _refreshBtn.IsEnabled = false;
            _statusLabel.Text = "Requesting system info...";
            _infoPanel.Children.Clear();
            _infoPanel.Children.Add(new TextBlock
            {
                Text = "Waiting for response...",
                FontSize = 11,
                Foreground = new SolidColorBrush(TextSecondary),
                Margin = new Thickness(0, 20, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Center
            });
            int ver = ++_refreshVersion;
            _clientVersion[_selectedClient] = ver;
            _plugin.RequestInfo(_selectedClient);
            await Task.Delay(100);
            _refreshBtn.IsEnabled = true;
        }

        public void OnSystemInfoReceived(string clientId, byte[] payload)
        {
            if (!(Application.Current.Dispatcher.CheckAccess()))
            {
                Application.Current.Dispatcher.BeginInvoke(new Action(() => OnSystemInfoReceived(clientId, payload)));
                return;
            }

            string text = Encoding.UTF8.GetString(payload);
            _clientInfo[clientId] = text;

            if (clientId == _selectedClient)
            {
                int storedVer;
                if (_clientVersion.TryGetValue(clientId, out storedVer) && storedVer == _refreshVersion)
                    DisplayInfo(text);
                else if (!_clientVersion.ContainsKey(clientId))
                    DisplayInfo(text);
            }
        }

        private void ShowInfoForClient(string clientId)
        {
            if (_clientInfo.TryGetValue(clientId, out string info))
            {
                DisplayInfo(info);
                _statusLabel.Text = "System info loaded";
            }
            else
            {
                _infoPanel.Children.Clear();
                _infoPanel.Children.Add(new TextBlock
                {
                    Text = "Click Refresh to gather system information",
                    FontSize = 11,
                    Foreground = new SolidColorBrush(TextSecondary),
                    Margin = new Thickness(0, 20, 0, 0),
                    HorizontalAlignment = HorizontalAlignment.Center
                });
                _statusLabel.Text = "No data - click Refresh";
            }
        }

        private void DisplayInfo(string rawInfo)
        {
            _infoPanel.Children.Clear();

            var lines = rawInfo.Split('\n');
            var categories = new Dictionary<string, List<KeyValuePair<string, string>>>();
            var progList = new List<string>();
            var drives = new List<string>();
            var nets = new List<string>();

            string currentCategory = "General";
            categories[currentCategory] = new List<KeyValuePair<string, string>>();

            foreach (string line in lines)
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;

                if (trimmed.StartsWith("PROG|"))
                {
                    progList.Add(trimmed.Substring(5));
                    continue;
                }
                if (trimmed.StartsWith("DRIVE|"))
                {
                    drives.Add(trimmed.Substring(6));
                    continue;
                }
                if (trimmed.StartsWith("NET|"))
                {
                    nets.Add(trimmed.Substring(4));
                    continue;
                }

                int eqIdx = trimmed.IndexOf('=');
                if (eqIdx < 0) continue;

                string key = trimmed.Substring(0, eqIdx);
                string val = trimmed.Substring(eqIdx + 1);

                if (key == "OSName") currentCategory = "Operating System";
                else if (key == "CPUName") currentCategory = "Hardware";
                else if (key == "DriveCount") currentCategory = "Storage";
                else if (key == "NetAdapterCount") currentCategory = "Network";
                else if (key == "InstalledProgramCount") currentCategory = "Software";
                else if (key == "Antivirus") currentCategory = "Security";

                if (!categories.ContainsKey(currentCategory))
                    categories[currentCategory] = new List<KeyValuePair<string, string>>();

                categories[currentCategory].Add(new KeyValuePair<string, string>(key, val));
            }

            foreach (var cat in categories)
            {
                if (cat.Key == "Storage" || cat.Key == "Network" || cat.Key == "Software" || cat.Key == "Security")
                    continue;

                AddCategoryHeader(cat.Key);

                foreach (var kvp in cat.Value)
                    AddInfoRow(kvp.Key, kvp.Value);
            }

            // Storage section
            if (drives.Count > 0)
            {
                AddCategoryHeader("Storage");

                var driveHeader = new Border
                {
                    Background = new SolidColorBrush(SurfaceLightColor),
                    Padding = new Thickness(8, 3, 8, 3),
                    Margin = new Thickness(8, 0, 8, 2),
                    CornerRadius = new CornerRadius(3)
                };
                var driveGrid = new WrapPanel { Orientation = Orientation.Horizontal };
                driveGrid.Children.Add(MakeCol("Drive", 80));
                driveGrid.Children.Add(MakeCol("Label", 120));
                driveGrid.Children.Add(MakeCol("Size", 80));
                driveGrid.Children.Add(MakeCol("Free", 80));
                driveGrid.Children.Add(MakeCol("Format", 60));
                driveGrid.Children.Add(MakeCol("Type", 80));
                driveHeader.Child = driveGrid;
                _infoPanel.Children.Add(driveHeader);

                foreach (string d in drives)
                {
                    string[] parts = d.Split('|');
                    if (parts.Length < 6) continue;
                    var row = new Border
                    {
                        Background = new SolidColorBrush(SurfaceColor),
                        Padding = new Thickness(8, 2, 8, 2),
                        Margin = new Thickness(8, 0, 8, 1),
                        CornerRadius = new CornerRadius(2)
                    };
                    var rowPanel = new WrapPanel { Orientation = Orientation.Horizontal };
                    rowPanel.Children.Add(MakeCol(parts[0], 80));
                    rowPanel.Children.Add(MakeCol(parts[1], 120));
                    rowPanel.Children.Add(MakeCol(parts[2], 80));
                    rowPanel.Children.Add(MakeCol(parts[3], 80));
                    rowPanel.Children.Add(MakeCol(parts[4], 60));
                    rowPanel.Children.Add(MakeCol(parts[5], 80));
                    row.Child = rowPanel;
                    _infoPanel.Children.Add(row);
                }
            }

            // Network section
            if (nets.Count > 0)
            {
                AddCategoryHeader("Network");

                var netHeader = new Border
                {
                    Background = new SolidColorBrush(SurfaceLightColor),
                    Padding = new Thickness(8, 3, 8, 3),
                    Margin = new Thickness(8, 0, 8, 2),
                    CornerRadius = new CornerRadius(3)
                };
                var netGrid = new WrapPanel { Orientation = Orientation.Horizontal };
                netGrid.Children.Add(MakeCol("Adapter", 140));
                netGrid.Children.Add(MakeCol("IP Address", 140));
                netGrid.Children.Add(MakeCol("MAC", 100));
                netGrid.Children.Add(MakeCol("DNS", 140));
                netHeader.Child = netGrid;
                _infoPanel.Children.Add(netHeader);

                foreach (string n in nets)
                {
                    string[] parts = n.Split('|');
                    if (parts.Length < 4) continue;
                    var row = new Border
                    {
                        Background = new SolidColorBrush(SurfaceColor),
                        Padding = new Thickness(8, 2, 8, 2),
                        Margin = new Thickness(8, 0, 8, 1),
                        CornerRadius = new CornerRadius(2)
                    };
                    var rowPanel = new WrapPanel { Orientation = Orientation.Horizontal };
                    rowPanel.Children.Add(MakeCol(parts[0], 140));
                    rowPanel.Children.Add(MakeCol(parts[1], 140));
                    rowPanel.Children.Add(MakeCol(parts[2], 100));
                    rowPanel.Children.Add(MakeCol(parts[3], 140));
                    row.Child = rowPanel;
                    _infoPanel.Children.Add(row);
                }
            }

            // Software section
            if (progList.Count > 0)
            {
                AddCategoryHeader("Software (" + progList.Count + " installed)");
                var progBox = new TextBox
                {
                    Text = string.Join("\n", progList.ToArray()),
                    Background = new SolidColorBrush(SurfaceColor),
                    Foreground = new SolidColorBrush(TextPrimary),
                    BorderBrush = new SolidColorBrush(BorderClr),
                    FontSize = 10,
                    FontFamily = new FontFamily("Consolas"),
                    IsReadOnly = true,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    MaxHeight = 200,
                    Padding = new Thickness(6),
                    Margin = new Thickness(8, 0, 8, 8)
                };
                _infoPanel.Children.Add(progBox);
            }

            // Security section
            if (categories.ContainsKey("Security") && categories["Security"].Count > 0)
            {
                AddCategoryHeader("Security");
                foreach (var kvp in categories["Security"])
                    AddInfoRow(kvp.Key, kvp.Value);
            }

            _statusLabel.Text = "Loaded " + lines.Length + " items";
        }

        private void AddCategoryHeader(string text)
        {
            var hdr = new Border
            {
                Background = new SolidColorBrush(SurfaceLightColor),
                Padding = new Thickness(10, 6, 10, 6),
                Margin = new Thickness(0, 4, 0, 2),
                CornerRadius = new CornerRadius(4),
                BorderBrush = new SolidColorBrush(BorderClr),
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            hdr.Child = new TextBlock
            {
                Text = text.ToUpper(),
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(AccentBlue)
            };
            _infoPanel.Children.Add(hdr);
        }

        private void AddInfoRow(string key, string value)
        {
            var row = new Border
            {
                Background = new SolidColorBrush(SurfaceColor),
                Padding = new Thickness(8, 3, 8, 3),
                Margin = new Thickness(8, 0, 8, 1),
                CornerRadius = new CornerRadius(2)
            };
            var panel = new DockPanel();
            var keyBlock = new TextBlock
            {
                Text = key,
                FontSize = 11,
                Foreground = new SolidColorBrush(TextSecondary),
                Width = 170,
                FontWeight = FontWeights.SemiBold
            };
            DockPanel.SetDock(keyBlock, Dock.Left);
            panel.Children.Add(keyBlock);
            var valBlock = new TextBlock
            {
                Text = value,
                FontSize = 11,
                Foreground = new SolidColorBrush(TextPrimary),
                TextWrapping = TextWrapping.Wrap
            };
            panel.Children.Add(valBlock);
            row.Child = panel;
            _infoPanel.Children.Add(row);
        }

        private TextBlock MakeCol(string text, double width)
        {
            return new TextBlock
            {
                Text = text,
                FontSize = 10,
                Foreground = new SolidColorBrush(TextSecondary),
                Width = width,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
        }

        public void Dispose()
        {
            _clients.Clear();
            _clientInfo.Clear();
        }
    }
}
