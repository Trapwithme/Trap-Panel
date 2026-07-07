#nullable disable

using System;
using System.Collections.Generic;
using System.IO;
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
    public class RegistryUI : UserControl, IDisposable
    {
        private readonly PluginContext _context;
        private readonly PluginHost _host;

        private readonly TreeView _keyTree;
        private readonly ListView _valueListView;
        private readonly TextBox _pathBox;
        private readonly TextBlock _statusBar;

        private readonly Button _refreshButton;
        private readonly Button _rootsButton;
        private readonly Button _createKeyButton;
        private readonly Button _deleteKeyButton;
        private readonly Button _renameKeyButton;
        private readonly Button _createValueButton;
        private readonly Button _editValueButton;
        private readonly Button _deleteValueButton;

        private string _currentPath = "";
        private readonly List<RegValueEntry> _currentValues = new();
        private readonly List<RegKeyEntry> _currentSubKeys = new();

        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BgDarkColorVal => C("BackgroundColor");
        private Color SurfColorVal => C("SurfaceColor");
        private Color SurfLightColorVal => C("SurfaceLightColor");
        private Color BorderColorVal => C("BorderColor");
        private Color TextPrimaryColorVal => C("TextPrimaryColor");
        private Color TextSecondaryColorVal => C("TextSecondaryColor");
        private Color PrimaryColorVal => C("PrimaryColor");
        private Color PrimaryHoverColorVal => C("PrimaryHoverColor");
        private Color DangerColorVal => C("DangerColor");
        private Color DangerHoverColorVal => C("DangerHoverColor");
        private Color SuccessColorVal => C("SuccessColor");
        private Color DisabledBgColorVal => C("ButtonBgColor");
        private Color DisabledFgColorVal => C("TextSecondaryColor");

        private SolidColorBrush BgDark => B("BackgroundBrush");
        private SolidColorBrush BgMedium => B("SurfaceBrush");
        private SolidColorBrush BgLight => B("SurfaceLightBrush");
        private SolidColorBrush FgDefault => B("TextPrimaryBrush");
        private SolidColorBrush FgDim => B("TextSecondaryBrush");
        private SolidColorBrush AccentBlue => B("PrimaryBrush");
        private SolidColorBrush BorderBrushVal => B("BorderBrush");
        private SolidColorBrush DisabledBgBrush => B("ButtonBgBrush");
        private SolidColorBrush DisabledFgBrush => B("TextSecondaryBrush");

        public RegistryUI(PluginContext context, PluginHost host)
        {
            _context = context;
            _host = host;

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // ===== Toolbar =====
            var toolbarBorder = new Border
            {
                Background = BgMedium,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(6, 4, 6, 4)
            };

            var toolbar = new WrapPanel();

            _rootsButton = MakeThemedButton("?? Roots", SurfLightColorVal, C("ButtonBgHoverColor"));
            _rootsButton.Click += (s, e) => RequestRoots();

            _refreshButton = MakeThemedButton("?? Refresh", SurfLightColorVal, C("ButtonBgHoverColor"));
            _refreshButton.Click += (s, e) => RefreshCurrent();

            _createKeyButton = MakeThemedButton("??+ New Key", SurfLightColorVal, C("ButtonBgHoverColor"));
            _createKeyButton.Click += (s, e) => CreateNewKey();

            _deleteKeyButton = MakeThemedButton("??? Delete Key", DangerColorVal, DangerHoverColorVal);
            _deleteKeyButton.Click += (s, e) => DeleteSelectedKey();

            _renameKeyButton = MakeThemedButton("? Rename Key", SurfLightColorVal, C("ButtonBgHoverColor"));
            _renameKeyButton.Click += (s, e) => RenameSelectedKey();

            _createValueButton = MakeThemedButton("??+ New Value", SurfLightColorVal, C("ButtonBgHoverColor"));
            _createValueButton.Click += (s, e) => CreateNewValue();

            _editValueButton = MakeThemedButton("? Edit Value", SurfLightColorVal, C("ButtonBgHoverColor"));
            _editValueButton.Click += (s, e) => EditSelectedValue();

            _deleteValueButton = MakeThemedButton("?? Delete Value", DangerColorVal, DangerHoverColorVal);
            _deleteValueButton.Click += (s, e) => DeleteSelectedValue();

            toolbar.Children.Add(_rootsButton);
            toolbar.Children.Add(_refreshButton);
            toolbar.Children.Add(MakeSeparator());
            toolbar.Children.Add(_createKeyButton);
            toolbar.Children.Add(_renameKeyButton);
            toolbar.Children.Add(_deleteKeyButton);
            toolbar.Children.Add(MakeSeparator());
            toolbar.Children.Add(_createValueButton);
            toolbar.Children.Add(_editValueButton);
            toolbar.Children.Add(_deleteValueButton);

            toolbarBorder.Child = toolbar;
            Grid.SetRow(toolbarBorder, 0);
            mainGrid.Children.Add(toolbarBorder);

            // ===== Path bar =====
            var pathBorder = new Border
            {
                Background = BgMedium,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(6, 4, 6, 4)
            };

            var pathPanel = new DockPanel();

            var goButton = MakeThemedButton("Go", PrimaryColorVal, PrimaryHoverColorVal);
            goButton.Click += (s, e) => NavigateTo(_pathBox.Text);
            DockPanel.SetDock(goButton, Dock.Right);

            _pathBox = new TextBox
            {
                Background = BgDark,
                Foreground = FgDefault,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 5, 8, 5),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                CaretBrush = FgDefault,
                VerticalContentAlignment = VerticalAlignment.Center,
                Style = null,
                Text = "HKEY_CURRENT_USER"
            };
            _pathBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) { NavigateTo(_pathBox.Text); e.Handled = true; }
            };

            pathPanel.Children.Add(goButton);
            pathPanel.Children.Add(_pathBox);

            pathBorder.Child = pathPanel;
            Grid.SetRow(pathBorder, 1);
            mainGrid.Children.Add(pathBorder);

            // ===== Content: split panel =====
            var contentGrid = new Grid { Margin = new Thickness(0) };
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(280) });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left: Key tree
            var leftPanel = new Border
            {
                Background = BgDark,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 0, 1, 0)
            };

            _keyTree = new TreeView
            {
                Background = Brushes.Transparent,
                Foreground = FgDefault,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13,
                Padding = new Thickness(4)
            };

            string[] rootHives = { "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG" };
            foreach (string hive in rootHives)
            {
                var item = new TreeViewItem
                {
                    Header = $"??? {hive}",
                    Tag = hive,
                    Foreground = FgDefault,
                    FontSize = 13
                };
                item.Selected += TreeItem_Selected;
                item.Expanded += TreeItem_Expanded;
                item.Items.Add(new TreeViewItem { Header = "Loading...", Foreground = FgDim });
                _keyTree.Items.Add(item);
            }

            leftPanel.Child = _keyTree;
            Grid.SetColumn(leftPanel, 0);
            contentGrid.Children.Add(leftPanel);

            // Splitter
            var splitter = new GridSplitter
            {
                Width = 4,
                Background = BorderBrushVal,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Stretch
            };
            Grid.SetColumn(splitter, 1);
            contentGrid.Children.Add(splitter);

            // Right: Values list
            _valueListView = new ListView
            {
                Background = BgDark,
                Foreground = FgDefault,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13
            };

            var gridView = new GridView();
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "",
                DisplayMemberBinding = new System.Windows.Data.Binding("Icon"),
                Width = 30
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Name",
                DisplayMemberBinding = new System.Windows.Data.Binding("Name"),
                Width = 200
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Type",
                DisplayMemberBinding = new System.Windows.Data.Binding("Type"),
                Width = 120
            });
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Value",
                DisplayMemberBinding = new System.Windows.Data.Binding("DisplayValue"),
                Width = 300
            });

            _valueListView.View = gridView;

            var valueItemStyle = new Style(typeof(ListViewItem));
            valueItemStyle.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueItemStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            valueItemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(2)));
            valueItemStyle.Setters.Add(new Setter(Control.MarginProperty, new Thickness(0)));
            valueItemStyle.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
            valueItemStyle.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch));

            var valueHoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            valueHoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueHoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, BgLight));
            valueItemStyle.Triggers.Add(valueHoverTrigger);

            var valueSelectedTrigger = new Trigger { Property = System.Windows.Controls.Primitives.Selector.IsSelectedProperty, Value = true };
            valueSelectedTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueSelectedTrigger.Setters.Add(new Setter(Control.BackgroundProperty, AccentBlue));
            valueItemStyle.Triggers.Add(valueSelectedTrigger);

            var valueSelectedHoverTrigger = new MultiTrigger();
            valueSelectedHoverTrigger.Conditions.Add(new Condition(UIElement.IsMouseOverProperty, true));
            valueSelectedHoverTrigger.Conditions.Add(new Condition(System.Windows.Controls.Primitives.Selector.IsSelectedProperty, true));
            valueSelectedHoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, FgDefault));
            valueSelectedHoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(PrimaryHoverColorVal)));
            valueItemStyle.Triggers.Add(valueSelectedHoverTrigger);

            _valueListView.ItemContainerStyle = valueItemStyle;

            _valueListView.MouseDoubleClick += ValueList_DoubleClick;
            _valueListView.SelectionChanged += ValueList_SelectionChanged;

            Grid.SetColumn(_valueListView, 2);
            contentGrid.Children.Add(_valueListView);

            Grid.SetRow(contentGrid, 2);
            mainGrid.Children.Add(contentGrid);

            // ===== Status bar =====
            var statusBorder = new Border
            {
                Background = BgMedium,
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(10, 5, 10, 5)
            };

            _statusBar = new TextBlock
            {
                Text = "Ready - Select a registry hive to browse",
                Foreground = FgDim,
                FontSize = 12
            };

            statusBorder.Child = _statusBar;
            Grid.SetRow(statusBorder, 3);
            mainGrid.Children.Add(statusBorder);

            this.Content = mainGrid;
            this.Background = BgDark;

            UpdateButtonStates();
        }

        // ==================== THEMED BUTTON FACTORY ====================

        private Button MakeThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var normalBgBrush = new SolidColorBrush(normalBg);
            var hoverBgBrush = new SolidColorBrush(hoverBg);

            var template = new ControlTemplate(typeof(Button));

            var borderFactory = new FrameworkElementFactory(typeof(Border));
            borderFactory.Name = "btnBorder";
            borderFactory.SetValue(Border.BackgroundProperty, normalBgBrush);
            borderFactory.SetValue(Border.BorderBrushProperty, new SolidColorBrush(C("ButtonBorderColor")));
            borderFactory.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            borderFactory.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            borderFactory.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var contentFactory = new FrameworkElementFactory(typeof(ContentPresenter));
            contentFactory.Name = "btnContent";
            contentFactory.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            contentFactory.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            borderFactory.AppendChild(contentFactory);

            template.VisualTree = borderFactory;

            // Hover
            var hoverTrigger = new Trigger
            {
                Property = UIElement.IsMouseOverProperty,
                Value = true
            };
            hoverTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBgBrush, "btnBorder"));
            template.Triggers.Add(hoverTrigger);

            // Pressed
            var pressedTrigger = new Trigger
            {
                Property = ButtonBase.IsPressedProperty,
                Value = true
            };
            pressedTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBgBrush, "btnBorder"));
            pressedTrigger.Setters.Add(new Setter(Border.OpacityProperty, 0.8, "btnBorder"));
            template.Triggers.Add(pressedTrigger);

            // Disabled
            var disabledTrigger = new Trigger
            {
                Property = UIElement.IsEnabledProperty,
                Value = false
            };
            disabledTrigger.Setters.Add(new Setter(Border.BackgroundProperty, DisabledBgBrush, "btnBorder"));
            disabledTrigger.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "btnContent"));
            template.Triggers.Add(disabledTrigger);

            return new Button
            {
                Content = text,
                Template = template,
                Foreground = FgDefault,
                Cursor = Cursors.Hand,
                Margin = new Thickness(2),
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
        }

        private Border MakeSeparator()
        {
            return new Border
            {
                Width = 1,
                Background = BorderBrushVal,
                Margin = new Thickness(6, 4, 6, 4)
            };
        }

        private void SetStatus(string text)
        {
            Dispatcher.BeginInvoke(() => _statusBar.Text = text);
        }

        private void UpdateButtonStates()
        {
            Dispatcher.BeginInvoke(() =>
            {
                var selectedTreeItem = _keyTree.SelectedItem as TreeViewItem;
                var selectedValue = _valueListView.SelectedItem as RegValueEntry;

                bool hasKeySelected = selectedTreeItem != null;
                bool hasValueSelected = selectedValue != null;
                bool hasPath = !string.IsNullOrEmpty(_currentPath);

                _createKeyButton.IsEnabled = hasPath;
                _deleteKeyButton.IsEnabled = hasKeySelected && hasPath;
                _renameKeyButton.IsEnabled = hasKeySelected && hasPath;
                _createValueButton.IsEnabled = hasPath;
                _editValueButton.IsEnabled = hasValueSelected;
                _deleteValueButton.IsEnabled = hasValueSelected;
                _refreshButton.IsEnabled = true;
            });
        }

        // ==================== TREE EVENTS ====================

        private void TreeItem_Selected(object sender, RoutedEventArgs e)
        {
            if (sender is TreeViewItem item && item.Tag is string path)
            {
                e.Handled = true;
                NavigateTo(path);
            }
        }

        private void TreeItem_Expanded(object sender, RoutedEventArgs e)
        {
            if (sender is TreeViewItem item && item.Tag is string path)
            {
                if (item.Items.Count == 1 && item.Items[0] is TreeViewItem dummy && dummy.Header?.ToString() == "Loading...")
                {
                    SendBrowseKey(path);
                }
            }
        }

        private void ValueList_DoubleClick(object sender, MouseButtonEventArgs e)
        {
            EditSelectedValue();
        }

        private void ValueList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateButtonStates();
            if (_valueListView.SelectedItem is RegValueEntry entry)
            {
                SetStatus($"{entry.Type}: {entry.FullPath}");
            }
        }

        // ==================== NAVIGATION ====================

        private void NavigateTo(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            _currentPath = path;
            Dispatcher.BeginInvoke(() => _pathBox.Text = path);
            SendBrowseKey(path);
        }

        private void RefreshCurrent()
        {
            if (string.IsNullOrEmpty(_currentPath))
                RequestRoots();
            else
                SendBrowseKey(_currentPath);
        }

        // ==================== ACTIONS ====================

        private async void CreateNewKey()
        {
            if (string.IsNullOrEmpty(_currentPath))
            {
                SetStatus("Navigate to a key first");
                return;
            }

            string name = PromptInput("New Registry Key", "Enter key name:");
            if (string.IsNullOrWhiteSpace(name)) return;

            string fullPath = _currentPath + "\\" + name;

            byte[] pathBytes = Encoding.UTF8.GetBytes(fullPath);
            byte[] msg = new byte[pathBytes.Length + 1];
            msg[0] = 0x04;
            Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);

            SetStatus($"Creating key: {fullPath}...");
            await _context.SendToClient(msg);
        }

        private async void DeleteSelectedKey()
        {
            if (string.IsNullOrEmpty(_currentPath)) return;

            if (_keyTree.SelectedItem is TreeViewItem selectedItem && selectedItem.Tag is string keyPath)
            {
                var result = MessageBox.Show(
                    $"Delete registry key and ALL its contents?\n\n{keyPath}\n\nThis cannot be undone!",
                    "Confirm Delete Key",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result != MessageBoxResult.Yes) return;

                byte[] pathBytes = Encoding.UTF8.GetBytes(keyPath);
                byte[] msg = new byte[pathBytes.Length + 1];
                msg[0] = 0x02;
                Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);

                SetStatus($"Deleting key: {keyPath}...");
                await _context.SendToClient(msg);
            }
        }

        private async void RenameSelectedKey()
        {
            if (_keyTree.SelectedItem is TreeViewItem selectedItem && selectedItem.Tag is string keyPath)
            {
                string oldName = keyPath.Split('\\').LastOrDefault() ?? "";
                string newName = PromptInput("Rename Registry Key", "Enter new name:", oldName);
                if (string.IsNullOrWhiteSpace(newName) || newName == oldName) return;

                string renameStr = keyPath + "|" + newName;
                byte[] renameBytes = Encoding.UTF8.GetBytes(renameStr);
                byte[] msg = new byte[renameBytes.Length + 1];
                msg[0] = 0x06;
                Buffer.BlockCopy(renameBytes, 0, msg, 1, renameBytes.Length);

                SetStatus($"Renaming key...");
                await _context.SendToClient(msg);
            }
        }

        private async void CreateNewValue()
        {
            if (string.IsNullOrEmpty(_currentPath))
            {
                SetStatus("Navigate to a key first");
                return;
            }

            string typeStr = PromptInput("New Registry Value", "Enter type (REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ):", "REG_SZ");
            if (string.IsNullOrWhiteSpace(typeStr)) return;

            string name = PromptInput("New Registry Value", "Enter value name:");
            if (name == null) return;

            string valueStr = PromptInput("New Registry Value", "Enter value:", "");
            if (valueStr == null) return;

            byte typeId = typeStr.ToUpper() switch
            {
                "REG_SZ" => 1,
                "REG_EXPAND_SZ" => 2,
                "REG_BINARY" => 3,
                "REG_DWORD" => 4,
                "REG_MULTI_SZ" => 5,
                "REG_QWORD" => 6,
                _ => 1
            };

            byte[] valueData;
            switch (typeId)
            {
                case 4:
                    if (int.TryParse(valueStr, out int dw))
                        valueData = BitConverter.GetBytes(dw);
                    else { SetStatus("Invalid DWORD value"); return; }
                    break;
                case 6:
                    if (long.TryParse(valueStr, out long qw))
                        valueData = BitConverter.GetBytes(qw);
                    else { SetStatus("Invalid QWORD value"); return; }
                    break;
                case 3:
                    try { valueData = HexStringToBytes(valueStr); }
                    catch { SetStatus("Invalid hex string for binary value"); return; }
                    break;
                default:
                    valueData = Encoding.UTF8.GetBytes(valueStr);
                    break;
            }

            byte[] pathBytes = Encoding.UTF8.GetBytes(_currentPath);
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);

            byte[] msg = new byte[1 + 1 + 2 + pathBytes.Length + 2 + nameBytes.Length + valueData.Length];
            int offset = 0;
            msg[offset++] = 0x05;
            msg[offset++] = typeId;
            msg[offset++] = (byte)(pathBytes.Length & 0xFF);
            msg[offset++] = (byte)((pathBytes.Length >> 8) & 0xFF);
            Buffer.BlockCopy(pathBytes, 0, msg, offset, pathBytes.Length);
            offset += pathBytes.Length;
            msg[offset++] = (byte)(nameBytes.Length & 0xFF);
            msg[offset++] = (byte)((nameBytes.Length >> 8) & 0xFF);
            Buffer.BlockCopy(nameBytes, 0, msg, offset, nameBytes.Length);
            offset += nameBytes.Length;
            Buffer.BlockCopy(valueData, 0, msg, offset, valueData.Length);

            SetStatus($"Creating value: {name}...");
            await _context.SendToClient(msg);
        }

        private void EditSelectedValue()
        {
            if (_valueListView.SelectedItem is RegValueEntry entry)
            {
                string newValue = PromptInput($"Edit {entry.Type}", $"Edit value for '{entry.Name}':", entry.DisplayValue);
                if (newValue == null) return;

                byte typeId = entry.Type switch
                {
                    "REG_SZ" => 1,
                    "REG_EXPAND_SZ" => 2,
                    "REG_BINARY" => 3,
                    "REG_DWORD" => 4,
                    "REG_MULTI_SZ" => 5,
                    "REG_QWORD" => 6,
                    _ => 1
                };

                byte[] valueData;
                switch (typeId)
                {
                    case 4:
                        if (int.TryParse(newValue, out int dw))
                            valueData = BitConverter.GetBytes(dw);
                        else { SetStatus("Invalid DWORD value"); return; }
                        break;
                    case 6:
                        if (long.TryParse(newValue, out long qw))
                            valueData = BitConverter.GetBytes(qw);
                        else { SetStatus("Invalid QWORD value"); return; }
                        break;
                    case 3:
                        try { valueData = HexStringToBytes(newValue); }
                        catch { SetStatus("Invalid hex string"); return; }
                        break;
                    default:
                        valueData = Encoding.UTF8.GetBytes(newValue);
                        break;
                }

                byte[] pathBytes = Encoding.UTF8.GetBytes(_currentPath);
                byte[] nameBytes = Encoding.UTF8.GetBytes(entry.Name);

                byte[] msg = new byte[1 + 1 + 2 + pathBytes.Length + 2 + nameBytes.Length + valueData.Length];
                int offset = 0;
                msg[offset++] = 0x05;
                msg[offset++] = typeId;
                msg[offset++] = (byte)(pathBytes.Length & 0xFF);
                msg[offset++] = (byte)((pathBytes.Length >> 8) & 0xFF);
                Buffer.BlockCopy(pathBytes, 0, msg, offset, pathBytes.Length);
                offset += pathBytes.Length;
                msg[offset++] = (byte)(nameBytes.Length & 0xFF);
                msg[offset++] = (byte)((nameBytes.Length >> 8) & 0xFF);
                Buffer.BlockCopy(nameBytes, 0, msg, offset, nameBytes.Length);
                offset += nameBytes.Length;
                Buffer.BlockCopy(valueData, 0, msg, offset, valueData.Length);

                SetStatus($"Updating value: {entry.Name}...");
                _ = _context.SendToClient(msg);
            }
        }

        private async void DeleteSelectedValue()
        {
            if (_valueListView.SelectedItem is RegValueEntry entry)
            {
                var result = MessageBox.Show(
                    $"Delete registry value?\n\n{entry.Name} ({entry.Type})\n\nThis cannot be undone!",
                    "Confirm Delete Value",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result != MessageBoxResult.Yes) return;

                string deleteStr = _currentPath + "|" + entry.Name;
                byte[] deleteBytes = Encoding.UTF8.GetBytes(deleteStr);
                byte[] msg = new byte[deleteBytes.Length + 1];
                msg[0] = 0x03;
                Buffer.BlockCopy(deleteBytes, 0, msg, 1, deleteBytes.Length);

                SetStatus($"Deleting value: {entry.Name}...");
                await _context.SendToClient(msg);
            }
        }

        // ==================== SEND COMMANDS ====================

        private async void SendBrowseKey(string path)
        {
            SetStatus($"Loading: {path}...");
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            byte[] msg = new byte[pathBytes.Length + 1];
            msg[0] = 0x01;
            Buffer.BlockCopy(pathBytes, 0, msg, 1, pathBytes.Length);
            await _context.SendToClient(msg);
        }

        private async void RequestRoots()
        {
            _currentPath = "";
            Dispatcher.BeginInvoke(() => _pathBox.Text = "");
            SetStatus("Loading root hives...");
            await _context.SendToClient(new byte[] { 0x07 });
        }

        // ==================== HANDLE RESPONSES ====================

        public void HandleServerData(byte[] data)
        {
            if (data == null || data.Length == 0) return;

            byte responseType = data[0];
            byte[] payload = new byte[data.Length - 1];
            if (payload.Length > 0)
                Buffer.BlockCopy(data, 1, payload, 0, payload.Length);

            Dispatcher.BeginInvoke(() =>
            {
                switch (responseType)
                {
                    case 0xAA:
                        SetStatus("Plugin connected. Select a registry hive to browse.");
                        break;

                    case 0x01:
                        HandleBrowseResult(payload);
                        break;

                    case 0x02:
                        HandleActionResult("Delete key", payload);
                        break;

                    case 0x03:
                        HandleActionResult("Delete value", payload);
                        break;

                    case 0x04:
                        HandleActionResult("Create key", payload);
                        break;

                    case 0x05:
                        HandleActionResult("Set value", payload);
                        break;

                    case 0x06:
                        HandleActionResult("Rename key", payload);
                        break;

                    case 0x07:
                        HandleRootsList(payload);
                        break;

                    case 0xFF:
                        if (payload.Length > 1)
                        {
                            string errMsg = Encoding.UTF8.GetString(payload, 1, payload.Length - 1);
                            SetStatus($"Error: {errMsg}");
                        }
                        break;
                }
            });
        }

        private void HandleBrowseResult(byte[] payload)
        {
            try
            {
                using var ms = new MemoryStream(payload);
                using var reader = new BinaryReader(ms);

                bool containsSubKeys = reader.ReadBoolean();
                int subKeyCount = reader.ReadInt32();

                _currentSubKeys.Clear();
                string[] subKeyNames = new string[subKeyCount];
                for (int i = 0; i < subKeyCount; i++)
                {
                    subKeyNames[i] = reader.ReadString();
                }

                string fullPath = reader.ReadString();
                _currentPath = fullPath;
                _pathBox.Text = fullPath;

                int valueCount = reader.ReadInt32();
                _currentValues.Clear();
                _valueListView.Items.Clear();

                for (int i = 0; i < valueCount; i++)
                {
                    string keyName = reader.ReadString();
                    string valFullPath = reader.ReadString();
                    byte typeId = reader.ReadByte();
                    byte valueTypeId = reader.ReadByte();

                    string typeName = typeId switch
                    {
                        1 => "REG_SZ",
                        2 => "REG_EXPAND_SZ",
                        3 => "REG_BINARY",
                        4 => "REG_DWORD",
                        5 => "REG_MULTI_SZ",
                        6 => "REG_QWORD",
                        _ => "Unknown"
                    };

                    string displayValue = "";

                    switch (valueTypeId)
                    {
                        case 1:
                            displayValue = reader.ReadString();
                            break;
                        case 4:
                            displayValue = reader.ReadInt32().ToString();
                            break;
                        case 6:
                            displayValue = reader.ReadInt64().ToString();
                            break;
                        case 3:
                            int byteLen = reader.ReadInt32();
                            byte[] bytes = reader.ReadBytes(byteLen);
                            displayValue = BitConverter.ToString(bytes).Replace("-", " ");
                            if (displayValue.Length > 100) displayValue = displayValue.Substring(0, 100) + "...";
                            break;
                        case 5:
                            int strCount = reader.ReadInt32();
                            var strings = new List<string>();
                            for (int j = 0; j < strCount; j++)
                                strings.Add(reader.ReadString());
                            displayValue = string.Join(" | ", strings);
                            break;
                        case 7:
                            displayValue = "(unknown type)";
                            break;
                    }

                    var entry = new RegValueEntry
                    {
                        Name = string.IsNullOrEmpty(keyName) ? "(Default)" : keyName,
                        FullPath = valFullPath,
                        Type = typeName,
                        DisplayValue = displayValue
                    };

                    _currentValues.Add(entry);
                    _valueListView.Items.Add(entry);
                }

                UpdateTreeForPath(fullPath, subKeyNames, containsSubKeys);

                int valCount = _currentValues.Count;
                SetStatus($"{fullPath} - {subKeyCount} subkey(s), {valCount} value(s)");
                UpdateButtonStates();
            }
            catch (Exception ex)
            {
                SetStatus($"Parse error: {ex.Message}");
            }
        }

        private void UpdateTreeForPath(string path, string[] subKeyNames, bool hasSubKeys)
        {
            string[] pathParts = path.Split('\\');
            if (pathParts.Length == 0) return;

            TreeViewItem currentNode = null;
            foreach (TreeViewItem rootItem in _keyTree.Items)
            {
                if (rootItem.Tag is string rootPath && rootPath.Equals(pathParts[0], StringComparison.OrdinalIgnoreCase))
                {
                    currentNode = rootItem;
                    break;
                }
            }

            if (currentNode == null) return;

            for (int i = 1; i < pathParts.Length; i++)
            {
                TreeViewItem found = null;
                foreach (var child in currentNode.Items)
                {
                    if (child is TreeViewItem ti && ti.Tag is string tag)
                    {
                        string childName = tag.Split('\\').LastOrDefault() ?? "";
                        if (childName.Equals(pathParts[i], StringComparison.OrdinalIgnoreCase))
                        {
                            found = ti;
                            break;
                        }
                    }
                }

                if (found == null)
                {
                    string partialPath = string.Join("\\", pathParts.Take(i + 1));
                    found = new TreeViewItem
                    {
                        Header = $"?? {pathParts[i]}",
                        Tag = partialPath,
                        Foreground = FgDefault,
                        FontSize = 13
                    };
                    found.Selected += TreeItem_Selected;
                    found.Expanded += TreeItem_Expanded;
                    currentNode.Items.Add(found);
                }

                currentNode = found;
            }

            currentNode.Items.Clear();
            foreach (string subKey in subKeyNames)
            {
                string childPath = path + "\\" + subKey;
                var childItem = new TreeViewItem
                {
                    Header = $"?? {subKey}",
                    Tag = childPath,
                    Foreground = FgDefault,
                    FontSize = 13
                };
                childItem.Selected += TreeItem_Selected;
                childItem.Expanded += TreeItem_Expanded;
                childItem.Items.Add(new TreeViewItem { Header = "Loading...", Foreground = FgDim });
                currentNode.Items.Add(childItem);
            }

            currentNode.IsExpanded = true;
        }

        private void HandleRootsList(byte[] payload)
        {
            SetStatus("Root hives loaded. Select one to browse.");
        }

        private void HandleActionResult(string action, byte[] payload)
        {
            string result = Encoding.UTF8.GetString(payload);
            if (result.StartsWith("OK|"))
            {
                string detail = result.Substring(3);
                SetStatus($"{action} successful: {detail}");
                RefreshCurrent();
            }
            else if (result.StartsWith("FAIL|"))
            {
                string detail = result.Substring(5);
                SetStatus($"{action} failed: {detail}");
            }
            else
            {
                SetStatus($"{action}: {result}");
            }
        }

        // ==================== UTILITY ====================

        private string PromptInput(string title, string prompt, string defaultValue = "")
        {
            var dialog = new Window
            {
                Title = title,
                Width = 450,
                Height = 180,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Window.GetWindow(this),
                Background = BgMedium,
                ResizeMode = ResizeMode.NoResize
            };

            var panel = new StackPanel { Margin = new Thickness(16) };

            var promptText = new TextBlock
            {
                Text = prompt,
                Foreground = FgDefault,
                Margin = new Thickness(0, 0, 0, 8),
                FontSize = 13
            };
            panel.Children.Add(promptText);

            var inputBox = new TextBox
            {
                Text = defaultValue,
                Background = BgDark,
                Foreground = FgDefault,
                Padding = new Thickness(8, 5, 8, 5),
                BorderBrush = BorderBrushVal,
                BorderThickness = new Thickness(1),
                CaretBrush = FgDefault,
                Style = null,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 13
            };
            panel.Children.Add(inputBox);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 14, 0, 0)
            };

            var okButton = MakeThemedButton("OK", PrimaryColorVal, PrimaryHoverColorVal);
            okButton.Width = 80;
            okButton.Click += (s, e) => { dialog.DialogResult = true; dialog.Close(); };

            var cancelButton = MakeThemedButton("Cancel", SurfLightColorVal, C("ButtonBgHoverColor"));
            cancelButton.Width = 80;
            cancelButton.Click += (s, e) => { dialog.DialogResult = false; dialog.Close(); };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            panel.Children.Add(buttonPanel);

            dialog.Content = panel;
            inputBox.SelectAll();
            inputBox.Focus();

            inputBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) { dialog.DialogResult = true; dialog.Close(); }
                if (e.Key == Key.Escape) { dialog.DialogResult = false; dialog.Close(); }
            };

            return dialog.ShowDialog() == true ? inputBox.Text : null;
        }

        private static byte[] HexStringToBytes(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "");
            if (hex.Length % 2 != 0)
                hex = "0" + hex;

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        public void Dispose() { }
    }
}
