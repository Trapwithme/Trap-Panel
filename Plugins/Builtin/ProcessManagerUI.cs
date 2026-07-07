// File: Plugins/Builtin/ProcessMonUI.xaml.cs
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
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class ProcessManagerUI : UserControl, IDisposable
    {
        private readonly PluginContext _context;
        private readonly PluginHost _host;
        private readonly ProcessManagerPlugin _plugin;

        // ── Theme palette ──
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        Color BgDeep => Color.FromRgb(10, 12, 16);
        Color BgBase => Color.FromRgb(17, 21, 28);
        Color BgSurface => C("SurfaceColor");
        Color BgElevated => Color.FromRgb(30, 36, 44);
        Color BgHover => Color.FromRgb(38, 45, 55);
        Color BgSelected => Color.FromRgb(22, 50, 95);
        Color BgSelectedHover => Color.FromRgb(28, 58, 108);
        Color BorderClr => C("BorderColor");
        Color BorderLightClr => Color.FromRgb(56, 63, 71);
        Color TxtPrimary => C("TextPrimaryColor");
        Color TxtSecondary => C("TextSecondaryColor");
        Color TxtMuted => C("TextSecondaryColor");
        Color AccBlue => Color.FromRgb(56, 132, 255);
        Color AccBlueDim => Color.FromRgb(36, 100, 200);
        Color AccGreen => Color.FromRgb(46, 160, 67);
        Color AccGreenDim => C("SuccessColor");
        Color AccRed => C("DangerColor");
        Color AccRedDim => Color.FromRgb(164, 38, 38);
        Color AccOrange => C("WarningColor");
        Color DisabledBg => Color.FromRgb(35, 38, 42);
        Color ButtonBorderClr => C("ButtonBorderColor");
        Color ButtonBgClr => C("ButtonBgColor");
        Color ButtonBgHoverClr => C("ButtonBgHoverColor");

        SolidColorBrush BrBgDeep => Fr(BgDeep);
        SolidColorBrush BrBgBase => Fr(BgBase);
        SolidColorBrush BrBgSurface => B("SurfaceBrush");
        SolidColorBrush BrBgElevated => Fr(BgElevated);
        SolidColorBrush BrBgHover => Fr(BgHover);
        SolidColorBrush BrBgSelected => Fr(BgSelected);
        SolidColorBrush BrBgSelectedHover => Fr(BgSelectedHover);
        SolidColorBrush BrBorder => B("BorderBrush");
        SolidColorBrush BrBorderLight => Fr(BorderLightClr);
        SolidColorBrush BrTxtPrimary => B("TextPrimaryBrush");
        SolidColorBrush BrTxtSecondary => B("TextSecondaryBrush");
        SolidColorBrush BrTxtMuted => Fr(TxtMuted);
        SolidColorBrush BrAccBlue => Fr(AccBlue);
        SolidColorBrush BrAccBlueDim => Fr(AccBlueDim);
        SolidColorBrush BrAccGreen => Fr(AccGreen);
        SolidColorBrush BrAccRed => Fr(AccRed);
        SolidColorBrush BrAccOrange => Fr(AccOrange);
        SolidColorBrush BrDisabledBg => Fr(DisabledBg);
        SolidColorBrush BrTransparent => Brushes.Transparent;

        private static SolidColorBrush Fr(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }

        private static readonly FontFamily MonoFont = new("Cascadia Mono, Consolas, Courier New, monospace");
        private static readonly FontFamily UiFont = new("Segoe UI, Arial, sans-serif");

        // ── Controls ──
        private readonly TreeView _processTree;
        private readonly TextBlock _statusText;
        private readonly TextBlock _countLabel;
        private readonly TextBlock _selectedLabel;
        private readonly TextBlock _lastUpdateLabel;
        private readonly TextBox _searchBox;
        private readonly Button _refreshButton;
        private readonly Button _pauseButton;
        private readonly Button _killButton;
        private readonly Button _killTreeButton;
        private readonly Button _expandAllButton;
        private readonly Button _collapseAllButton;
        private readonly Button _clearSearchButton;
        private readonly Border _statusIcon;

        // ── State ──
        private bool _disposed;
        private bool _paused;
        private List<ProcessInfoNode> _currentRoots = new();
        private int _totalProcessCount;
        private string _searchFilter = "";
        private readonly Dictionary<int, bool> _expandedState = new();
        private readonly HashSet<int> _selectedPids = new();
        private readonly Dictionary<int, TreeViewItem> _pidToItem = new();
        private readonly Dictionary<int, Border> _pidToHeaderBorder = new();
        private int _lastClickedPid = -1;
        private readonly List<int> _flatPidOrder = new();
        private DispatcherTimer _searchDebounce;
        private DateTime _lastUpdate = DateTime.MinValue;
        private bool _hasReceivedData;

        public ProcessManagerUI(PluginContext context, PluginHost host, ProcessManagerPlugin plugin)
        {

            _context = context;
            _host = host;
            _plugin = plugin;

            _searchDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
            _searchDebounce.Tick += (s, e) =>
            {
                _searchDebounce.Stop();
                _searchFilter = _searchBox.Text?.Trim() ?? "";
                RebuildTree();
            };

            var root = new Grid { Background = BrBgDeep };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // ═══════════ TOOLBAR ═══════════
            var toolbarBorder = new Border
            {
                Background = BrBgSurface,
                BorderBrush = BrBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(8, 6, 8, 6)
            };

            var toolbarGrid = new Grid();
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var leftToolbar = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

            _refreshButton = MakeIconButton("⟳", "Refresh", AccGreen, AccGreenDim);
            _refreshButton.Click += (s, e) => ForceRefresh();
            leftToolbar.Children.Add(_refreshButton);

            _pauseButton = MakeIconButton("⏸", "Pause", BgElevated, BgHover, hasOutline: true);
            _pauseButton.Click += (s, e) => TogglePause();
            leftToolbar.Children.Add(_pauseButton);

            leftToolbar.Children.Add(MakeToolbarSep());

            _killButton = MakeIconButton("✕", "Kill", AccRed, AccRedDim);
            _killButton.Click += (s, e) => KillAllSelected();
            leftToolbar.Children.Add(_killButton);

            _killTreeButton = MakeIconButton("⌧", "Kill Tree", AccRed, AccRedDim);
            _killTreeButton.Click += (s, e) => KillAllSelectedTrees();
            leftToolbar.Children.Add(_killTreeButton);

            leftToolbar.Children.Add(MakeToolbarSep());

            _expandAllButton = MakeIconButton("⊞", "Expand", BgElevated, BgHover, hasOutline: true);
            _expandAllButton.Click += (s, e) => SetAllExpanded(true);
            leftToolbar.Children.Add(_expandAllButton);

            _collapseAllButton = MakeIconButton("⊟", "Collapse", BgElevated, BgHover, hasOutline: true);
            _collapseAllButton.Click += (s, e) => SetAllExpanded(false);
            leftToolbar.Children.Add(_collapseAllButton);

            Grid.SetColumn(leftToolbar, 0);
            toolbarGrid.Children.Add(leftToolbar);

            var rightToolbar = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

            _selectedLabel = new TextBlock
            {
                Text = "",
                Foreground = BrAccBlue,
                FontFamily = UiFont,
                FontSize = 12,
                FontWeight = FontWeights.Medium,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 12, 0),
                Visibility = Visibility.Collapsed
            };
            rightToolbar.Children.Add(_selectedLabel);

            var countBadge = new Border
            {
                Background = Fr(Color.FromArgb(40, AccGreen.R, AccGreen.G, AccGreen.B)),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(10, 3, 10, 3),
                VerticalAlignment = VerticalAlignment.Center
            };
            _countLabel = new TextBlock
            {
                Text = "0 processes",
                Foreground = BrAccGreen,
                FontFamily = UiFont,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
            countBadge.Child = _countLabel;
            rightToolbar.Children.Add(countBadge);

            Grid.SetColumn(rightToolbar, 1);
            toolbarGrid.Children.Add(rightToolbar);

            toolbarBorder.Child = toolbarGrid;
            Grid.SetRow(toolbarBorder, 0);
            root.Children.Add(toolbarBorder);

            // ═══════════ SEARCH BAR ═══════════
            var searchBorder = new Border
            {
                Background = BrBgSurface,
                BorderBrush = BrBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(8, 5, 8, 5)
            };

            var searchGrid = new Grid();
            searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var searchIcon = new TextBlock
            {
                Text = "🔍",
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(4, 0, 6, 0),
                Opacity = 0.6
            };
            Grid.SetColumn(searchIcon, 0);
            searchGrid.Children.Add(searchIcon);

            _searchBox = new TextBox
            {
                Background = Fr(C("BackgroundColor")),
                Foreground = BrTxtPrimary,
                BorderBrush = BrBorder,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 6, 10, 6),
                FontFamily = MonoFont,
                FontSize = 12.5,
                CaretBrush = BrTxtPrimary,
                VerticalContentAlignment = VerticalAlignment.Center,
                Style = null
            };
            _searchBox.GotFocus += (s, e) => _searchBox.BorderBrush = BrAccBlueDim;
            _searchBox.LostFocus += (s, e) => _searchBox.BorderBrush = BrBorder;
            _searchBox.TextChanged += (s, e) =>
            {
                _searchDebounce.Stop();
                _searchDebounce.Start();
                _clearSearchButton.Visibility = string.IsNullOrEmpty(_searchBox.Text)
                    ? Visibility.Collapsed : Visibility.Visible;
            };
            Grid.SetColumn(_searchBox, 1);
            searchGrid.Children.Add(_searchBox);

            _clearSearchButton = new Button
            {
                Content = "✕",
                Foreground = BrTxtMuted,
                Background = BrTransparent,
                BorderThickness = new Thickness(0),
                FontSize = 14,
                Cursor = Cursors.Hand,
                Margin = new Thickness(4, 0, 0, 0),
                Padding = new Thickness(6, 2, 6, 2),
                Visibility = Visibility.Collapsed,
                Style = null
            };
            _clearSearchButton.Click += (s, e) => { _searchBox.Text = ""; _searchBox.Focus(); };
            Grid.SetColumn(_clearSearchButton, 2);
            searchGrid.Children.Add(_clearSearchButton);

            searchBorder.Child = searchGrid;
            Grid.SetRow(searchBorder, 1);
            root.Children.Add(searchBorder);

            // ═══════════ COLUMN HEADERS ═══════════
            var headerBorder = new Border
            {
                Background = Fr(BgBase),
                BorderBrush = BrBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(38, 5, 12, 5)
            };

            var headerPanel = new Grid();
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(80) });
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(90) });
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200) });

            AddColumnHeader(headerPanel, "PROCESS NAME", 0);
            AddColumnHeader(headerPanel, "PID", 1);
            AddColumnHeader(headerPanel, "MEMORY", 2);
            AddColumnHeader(headerPanel, "DESCRIPTION", 3);

            headerBorder.Child = headerPanel;
            Grid.SetRow(headerBorder, 2);
            root.Children.Add(headerBorder);

            // ═══════════ TREE VIEW ═══════════
            _processTree = new TreeView
            {
                Background = BrBgDeep,
                Foreground = BrTxtPrimary,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(0),
                FontFamily = MonoFont,
                FontSize = 12,
                Style = null
            };
            VirtualizingPanel.SetIsVirtualizing(_processTree, false);

            _processTree.ItemContainerStyle = CreateTreeViewItemStyle();
            _processTree.ContextMenu = BuildContextMenu();
            _processTree.PreviewKeyDown += OnTreeKeyDown;

            Grid.SetRow(_processTree, 3);
            root.Children.Add(_processTree);

            // ═══════════ STATUS BAR ═══════════
            var statusBorder = new Border
            {
                Background = BrBgSurface,
                BorderBrush = BrBorder,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(10, 6, 10, 6)
            };

            var statusGrid = new Grid();
            statusGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            statusGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            statusGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _statusIcon = new Border
            {
                Width = 8,
                Height = 8,
                CornerRadius = new CornerRadius(4),
                Background = BrTxtMuted,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            };
            Grid.SetColumn(_statusIcon, 0);
            statusGrid.Children.Add(_statusIcon);

            _statusText = new TextBlock
            {
                Text = "Waiting for connection…",
                Foreground = BrTxtSecondary,
                FontFamily = UiFont,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            Grid.SetColumn(_statusText, 1);
            statusGrid.Children.Add(_statusText);

            _lastUpdateLabel = new TextBlock
            {
                Text = "",
                Foreground = BrTxtMuted,
                FontFamily = UiFont,
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0, 0, 0)
            };
            Grid.SetColumn(_lastUpdateLabel, 2);
            statusGrid.Children.Add(_lastUpdateLabel);

            statusBorder.Child = statusGrid;
            Grid.SetRow(statusBorder, 4);
            root.Children.Add(statusBorder);

            this.Content = root;
            this.Background = BrBgDeep;
        }

        // ═══════════ STYLING ═══════════

        private void AddColumnHeader(Grid panel, string text, int col)
        {
            var tb = new TextBlock
            {
                Text = text,
                Foreground = Fr(TxtMuted),
                FontFamily = UiFont,
                FontSize = 10.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(2, 0, 2, 0)
            };
            Grid.SetColumn(tb, col);
            panel.Children.Add(tb);
        }

        private Style CreateTreeViewItemStyle()
        {
            var style = new Style(typeof(TreeViewItem));

            style.Setters.Add(new Setter(TreeViewItem.BackgroundProperty, BrTransparent));
            style.Setters.Add(new Setter(TreeViewItem.ForegroundProperty, BrTxtPrimary));
            style.Setters.Add(new Setter(TreeViewItem.FontFamilyProperty, MonoFont));
            style.Setters.Add(new Setter(TreeViewItem.FontSizeProperty, 12.0));
            style.Setters.Add(new Setter(TreeViewItem.PaddingProperty, new Thickness(0)));
            style.Setters.Add(new Setter(TreeViewItem.MarginProperty, new Thickness(0)));
            style.Setters.Add(new Setter(TreeViewItem.BorderThicknessProperty, new Thickness(0)));

            var template = new ControlTemplate(typeof(TreeViewItem));

            var rootStack = new FrameworkElementFactory(typeof(StackPanel));
            rootStack.SetValue(StackPanel.OrientationProperty, Orientation.Vertical);

            var headerDock = new FrameworkElementFactory(typeof(DockPanel));
            headerDock.Name = "HeaderRow";
            headerDock.SetValue(DockPanel.LastChildFillProperty, true);

            var toggle = new FrameworkElementFactory(typeof(ToggleButton));
            toggle.Name = "Expander";
            toggle.SetValue(DockPanel.DockProperty, Dock.Left);
            toggle.SetValue(ToggleButton.StyleProperty, CreateExpanderToggleStyle());
            toggle.SetValue(ToggleButton.FocusableProperty, false);
            toggle.SetBinding(ToggleButton.IsCheckedProperty, new Binding("IsExpanded")
            {
                RelativeSource = new RelativeSource(RelativeSourceMode.TemplatedParent),
                Mode = BindingMode.TwoWay
            });
            headerDock.AppendChild(toggle);

            var contentHost = new FrameworkElementFactory(typeof(ContentPresenter));
            contentHost.Name = "PART_Header";
            contentHost.SetValue(ContentPresenter.ContentSourceProperty, "Header");
            contentHost.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            contentHost.SetValue(ContentPresenter.MarginProperty, new Thickness(0));
            headerDock.AppendChild(contentHost);

            rootStack.AppendChild(headerDock);

            var childrenBorder = new FrameworkElementFactory(typeof(Border));
            childrenBorder.Name = "ChildrenBorder";
            childrenBorder.SetValue(Border.MarginProperty, new Thickness(18, 0, 0, 0));
            childrenBorder.SetValue(UIElement.VisibilityProperty, Visibility.Collapsed);

            var itemsHost = new FrameworkElementFactory(typeof(ItemsPresenter));
            itemsHost.Name = "ItemsHost";
            childrenBorder.AppendChild(itemsHost);

            rootStack.AppendChild(childrenBorder);

            template.VisualTree = rootStack;

            var expandedTrigger = new Trigger { Property = TreeViewItem.IsExpandedProperty, Value = true };
            expandedTrigger.Setters.Add(new Setter(UIElement.VisibilityProperty, Visibility.Visible, "ChildrenBorder"));
            template.Triggers.Add(expandedTrigger);

            var noChildTrigger = new Trigger { Property = TreeViewItem.HasItemsProperty, Value = false };
            noChildTrigger.Setters.Add(new Setter(UIElement.VisibilityProperty, Visibility.Hidden, "Expander"));
            template.Triggers.Add(noChildTrigger);

            style.Setters.Add(new Setter(TreeViewItem.TemplateProperty, template));

            return style;
        }

        private Style CreateExpanderToggleStyle()
        {
            var style = new Style(typeof(ToggleButton));

            var template = new ControlTemplate(typeof(ToggleButton));

            var arrow = new FrameworkElementFactory(typeof(TextBlock));
            arrow.Name = "Arrow";
            arrow.SetValue(TextBlock.TextProperty, "▸");
            arrow.SetValue(TextBlock.ForegroundProperty, BrTxtMuted);
            arrow.SetValue(TextBlock.FontSizeProperty, 12.0);
            arrow.SetValue(TextBlock.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            arrow.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);

            template.VisualTree = arrow;

            var checkedTrigger = new Trigger { Property = ToggleButton.IsCheckedProperty, Value = true };
            checkedTrigger.Setters.Add(new Setter(TextBlock.TextProperty, "▾", "Arrow"));
            checkedTrigger.Setters.Add(new Setter(TextBlock.ForegroundProperty, BrTxtSecondary, "Arrow"));
            template.Triggers.Add(checkedTrigger);

            style.Setters.Add(new Setter(ToggleButton.TemplateProperty, template));
            style.Setters.Add(new Setter(ToggleButton.BackgroundProperty, BrTransparent));
            style.Setters.Add(new Setter(ToggleButton.BorderThicknessProperty, new Thickness(0)));
            style.Setters.Add(new Setter(ToggleButton.CursorProperty, Cursors.Hand));
            style.Setters.Add(new Setter(ToggleButton.WidthProperty, 18.0));
            style.Setters.Add(new Setter(ToggleButton.MinHeightProperty, 22.0));
            style.Setters.Add(new Setter(ToggleButton.VerticalAlignmentProperty, VerticalAlignment.Center));

            return style;
        }

        private Button MakeIconButton(string icon, string label, Color normalBg, Color hoverBg, bool hasOutline = false)
        {
            var normalBgBrush = Fr(normalBg);
            var hoverBgBrush = Fr(hoverBg);
            var outlineBrush = hasOutline ? Fr(BorderClr) : Fr(Colors.Transparent);

            var template = new ControlTemplate(typeof(Button));

            var border = new FrameworkElementFactory(typeof(Border));
            border.Name = "btnBd";
            border.SetValue(Border.BackgroundProperty, normalBgBrush);
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
            border.SetValue(Border.PaddingProperty, new Thickness(8, 4, 10, 4));
            border.SetValue(Border.BorderBrushProperty, outlineBrush);
            border.SetValue(Border.BorderThicknessProperty, new Thickness(hasOutline ? 1 : 0));
            border.SetValue(Border.SnapsToDevicePixelsProperty, true);

            var sp = new FrameworkElementFactory(typeof(StackPanel));
            sp.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);

            var iconTb = new FrameworkElementFactory(typeof(TextBlock));
            iconTb.SetValue(TextBlock.TextProperty, icon);
            iconTb.SetValue(TextBlock.FontSizeProperty, 13.0);
            iconTb.SetValue(TextBlock.MarginProperty, new Thickness(0, 0, 5, 0));
            iconTb.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            sp.AppendChild(iconTb);

            var lblTb = new FrameworkElementFactory(typeof(TextBlock));
            lblTb.Name = "btnLbl";
            lblTb.SetValue(TextBlock.TextProperty, label);
            lblTb.SetValue(TextBlock.FontSizeProperty, 12.0);
            lblTb.SetValue(TextBlock.FontWeightProperty, FontWeights.Medium);
            lblTb.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            sp.AppendChild(lblTb);

            border.AppendChild(sp);
            template.VisualTree = border;

            var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hoverTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBgBrush, "btnBd"));
            if (hasOutline)
                hoverTrigger.Setters.Add(new Setter(Border.BorderBrushProperty, Fr(BorderLightClr), "btnBd"));
            template.Triggers.Add(hoverTrigger);

            var pressedTrigger = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true };
            pressedTrigger.Setters.Add(new Setter(Border.OpacityProperty, 0.75, "btnBd"));
            template.Triggers.Add(pressedTrigger);

            var disabledTrigger = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabledTrigger.Setters.Add(new Setter(Border.BackgroundProperty, BrDisabledBg, "btnBd"));
            disabledTrigger.Setters.Add(new Setter(Border.OpacityProperty, 0.45, "btnBd"));
            template.Triggers.Add(disabledTrigger);

            return new Button
            {
                Template = template,
                Foreground = BrTxtPrimary,
                Cursor = Cursors.Hand,
                Margin = new Thickness(2),
                Style = null
            };
        }

        private Border MakeToolbarSep() => new Border
        {
            Width = 1,
            Height = 20,
            Background = Fr(C("BorderColor")),
            Margin = new Thickness(6, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center
        };

        private ContextMenu BuildContextMenu()
        {
            var ctx = new ContextMenu
            {
                Background = BrBgElevated,
                BorderBrush = BrBorderLight,
                BorderThickness = new Thickness(1),
                Foreground = BrTxtPrimary,
                Padding = new Thickness(2)
            };

            ctx.Items.Add(MakeMenuItem("Kill Selected", "Del", BrAccRed, (s, e) => KillAllSelected()));
            ctx.Items.Add(MakeMenuItem("Kill Selected Trees", "Shift+Del", BrAccRed, (s, e) => KillAllSelectedTrees()));
            ctx.Items.Add(new Separator { Background = BrBorder, Margin = new Thickness(4, 2, 4, 2) });
            ctx.Items.Add(MakeMenuItem("Select All Visible", "Ctrl+A", BrTxtPrimary, (s, e) => SelectAllVisible()));
            ctx.Items.Add(MakeMenuItem("Clear Selection", "Escape", BrTxtPrimary, (s, e) => ClearSelection()));
            ctx.Items.Add(new Separator { Background = BrBorder, Margin = new Thickness(4, 2, 4, 2) });
            ctx.Items.Add(MakeMenuItem("Copy PID(s)", "Ctrl+C", BrTxtSecondary, (s, e) => CopySelectedPids()));
            ctx.Items.Add(MakeMenuItem("Copy Path(s)", "Ctrl+Shift+C", BrTxtSecondary, (s, e) => CopySelectedPath()));

            return ctx;
        }

        private MenuItem MakeMenuItem(string header, string shortcut, SolidColorBrush fg, RoutedEventHandler onClick)
        {
            var mi = new MenuItem { Foreground = fg, FontFamily = UiFont, FontSize = 12 };

            var headerPanel = new Grid();
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var headerTb = new TextBlock { Text = header, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(headerTb, 0);
            headerPanel.Children.Add(headerTb);

            if (!string.IsNullOrEmpty(shortcut))
            {
                var shortcutTb = new TextBlock
                {
                    Text = shortcut,
                    Foreground = Fr(TxtMuted),
                    FontSize = 11,
                    Margin = new Thickness(24, 0, 0, 0),
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(shortcutTb, 1);
                headerPanel.Children.Add(shortcutTb);
            }

            mi.Header = headerPanel;
            mi.Click += onClick;
            return mi;
        }

        private void SetStatus(string text, bool isError = false, bool isSuccess = false)
        {
            Dispatcher.BeginInvoke(() =>
            {
                _statusText.Text = text;
                if (isError)
                {
                    _statusText.Foreground = BrAccRed;
                    _statusIcon.Background = BrAccRed;
                }
                else if (isSuccess)
                {
                    _statusText.Foreground = BrAccGreen;
                    _statusIcon.Background = BrAccGreen;
                }
                else
                {
                    _statusText.Foreground = BrTxtSecondary;
                    _statusIcon.Background = _hasReceivedData ? BrAccGreen : BrTxtMuted;
                }
            });
        }

        private void UpdateSelectedLabel()
        {
            _selectedLabel.Text = _selectedPids.Count == 0 ? "" : $"{_selectedPids.Count} selected";
            _selectedLabel.Visibility = _selectedPids.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        }

        // ═══════════ KEYBOARD ═══════════

        private void OnTreeKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Delete)
            {
                if (Keyboard.IsKeyDown(Key.LeftShift) || Keyboard.IsKeyDown(Key.RightShift))
                    KillAllSelectedTrees();
                else
                    KillAllSelected();
                e.Handled = true;
            }
            else if (e.Key == Key.A && (Keyboard.IsKeyDown(Key.LeftCtrl) || Keyboard.IsKeyDown(Key.RightCtrl)))
            {
                SelectAllVisible();
                e.Handled = true;
            }
            else if (e.Key == Key.C && (Keyboard.IsKeyDown(Key.LeftCtrl) || Keyboard.IsKeyDown(Key.RightCtrl)))
            {
                if (Keyboard.IsKeyDown(Key.LeftShift) || Keyboard.IsKeyDown(Key.RightShift))
                    CopySelectedPath();
                else
                    CopySelectedPids();
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                ClearSelection();
                e.Handled = true;
            }
            else if (e.Key == Key.F5)
            {
                ForceRefresh();
                e.Handled = true;
            }
        }

        // ═══════════ SELECTION ═══════════

        private bool IsExpanderClick(DependencyObject source)
        {
            var d = source;
            while (d != null)
            {
                if (d is ToggleButton)
                    return true;
                if (d is TreeViewItem)
                    return false;
                d = VisualTreeHelper.GetParent(d);
            }
            return false;
        }

        private void OnHeaderClick(int pid, MouseButtonEventArgs e)
        {
            if (!_pidToItem.TryGetValue(pid, out var item)) return;
            if (item.Tag is not ProcessInfoNode node) return;

            e.Handled = true;

            bool ctrl = Keyboard.IsKeyDown(Key.LeftCtrl) || Keyboard.IsKeyDown(Key.RightCtrl);
            bool shift = Keyboard.IsKeyDown(Key.LeftShift) || Keyboard.IsKeyDown(Key.RightShift);

            if (shift && _lastClickedPid >= 0 && _flatPidOrder.Count > 0)
            {
                int idxStart = _flatPidOrder.IndexOf(_lastClickedPid);
                int idxEnd = _flatPidOrder.IndexOf(node.PID);
                if (idxStart >= 0 && idxEnd >= 0)
                {
                    if (!ctrl)
                    {
                        ClearSelectionHighlights();
                        _selectedPids.Clear();
                    }
                    int from = Math.Min(idxStart, idxEnd);
                    int to = Math.Max(idxStart, idxEnd);
                    for (int i = from; i <= to; i++)
                    {
                        int p = _flatPidOrder[i];
                        _selectedPids.Add(p);
                        if (_pidToHeaderBorder.TryGetValue(p, out var hb))
                            hb.Background = Fr(BgSelected);
                    }
                }
            }
            else if (ctrl)
            {
                if (_selectedPids.Contains(node.PID))
                {
                    _selectedPids.Remove(node.PID);
                    SetItemVisual(node.PID, false);
                }
                else
                {
                    _selectedPids.Add(node.PID);
                    SetItemVisual(node.PID, true);
                }
            }
            else
            {
                ClearSelectionHighlights();
                _selectedPids.Clear();
                _selectedPids.Add(node.PID);
                SetItemVisual(node.PID, true);
            }

            _lastClickedPid = node.PID;
            UpdateSelectedLabel();
        }

        private void SetItemVisual(int pid, bool selected)
        {
            if (_pidToHeaderBorder.TryGetValue(pid, out var border))
                border.Background = selected ? Fr(BgSelected) : BrTransparent;
        }

        private void ClearSelectionHighlights()
        {
            foreach (var kvp in _pidToHeaderBorder)
                kvp.Value.Background = BrTransparent;
        }

        private void ClearSelection()
        {
            ClearSelectionHighlights();
            _selectedPids.Clear();
            _lastClickedPid = -1;
            UpdateSelectedLabel();
        }

        private void SelectAllVisible()
        {
            _selectedPids.Clear();
            foreach (var kvp in _pidToItem)
            {
                _selectedPids.Add(kvp.Key);
                SetItemVisual(kvp.Key, true);
            }
            UpdateSelectedLabel();
        }

        private List<ProcessInfoNode> GetSelectedNodes()
        {
            var result = new List<ProcessInfoNode>();
            if (_selectedPids.Count == 0)
            {
                if (_processTree.SelectedItem is TreeViewItem si && si.Tag is ProcessInfoNode sn)
                    result.Add(sn);
            }
            else
            {
                CollectNodesFromRoots(_currentRoots, result);
            }
            return result;
        }

        private void CollectNodesFromRoots(List<ProcessInfoNode> nodes, List<ProcessInfoNode> result)
        {
            foreach (var n in nodes)
            {
                if (_selectedPids.Contains(n.PID))
                    result.Add(n);
                CollectNodesFromRoots(n.Children, result);
            }
        }

        // ═══════════ COMMANDS ═══════════

        [SupportedOSPlatform("windows")]
        private async void ForceRefresh()
        {
            _refreshButton.IsEnabled = false;
            await _context.SendToClient(new byte[] { 0x05 });
            SetStatus("Refreshing…");
            _ = Task.Delay(800).ContinueWith(_ => Dispatcher.BeginInvoke(() => _refreshButton.IsEnabled = true));
        }

        [SupportedOSPlatform("windows")]
        private async void TogglePause()
        {
            _paused = !_paused;
            await _context.SendToClient(new byte[] { _paused ? (byte)0x01 : (byte)0x02 });
            UpdatePauseButtonVisual();
            SetStatus(_paused ? "Auto-refresh paused" : "Auto-refresh resumed");
        }

        private void UpdatePauseButtonVisual()
        {
            try
            {
                _pauseButton.ApplyTemplate();
                if (_pauseButton.Template?.FindName("btnLbl", _pauseButton) is TextBlock lbl)
                    lbl.Text = _paused ? "Resume" : "Pause";
            }
            catch { }
        }

        [SupportedOSPlatform("windows")]
        private async void KillAllSelected()
        {
            var nodes = GetSelectedNodes();
            if (nodes.Count == 0) { SetStatus("No process selected"); return; }

            if (nodes.Count == 1)
            {
                var n = nodes[0];
                byte[] msg = new byte[5];
                msg[0] = 0x03;
                WriteInt32LE(msg, 1, n.PID);
                await _context.SendToClient(msg);
                SetStatus($"Killing {n.Name} (PID {n.PID})…");
            }
            else
            {
                byte[] msg = new byte[5 + nodes.Count * 4];
                msg[0] = 0x07;
                WriteInt32LE(msg, 1, nodes.Count);
                for (int i = 0; i < nodes.Count; i++)
                    WriteInt32LE(msg, 5 + i * 4, nodes[i].PID);
                await _context.SendToClient(msg);
                SetStatus($"Killing {nodes.Count} process(es)…");
            }
            _selectedPids.Clear();
            UpdateSelectedLabel();
        }

        [SupportedOSPlatform("windows")]
        private async void KillAllSelectedTrees()
        {
            var nodes = GetSelectedNodes();
            if (nodes.Count == 0) { SetStatus("No process selected"); return; }

            if (nodes.Count == 1)
            {
                var n = nodes[0];
                byte[] msg = new byte[5];
                msg[0] = 0x06;
                WriteInt32LE(msg, 1, n.PID);
                await _context.SendToClient(msg);
                SetStatus($"Killing tree from {n.Name} (PID {n.PID})…");
            }
            else
            {
                byte[] msg = new byte[5 + nodes.Count * 4];
                msg[0] = 0x08;
                WriteInt32LE(msg, 1, nodes.Count);
                for (int i = 0; i < nodes.Count; i++)
                    WriteInt32LE(msg, 5 + i * 4, nodes[i].PID);
                await _context.SendToClient(msg);
                SetStatus($"Killing {nodes.Count} tree(s)…");
            }
            _selectedPids.Clear();
            UpdateSelectedLabel();
        }

        private void CopySelectedPids()
        {
            var nodes = GetSelectedNodes();
            if (nodes.Count > 0)
            {
                Clipboard.SetText(string.Join(", ", nodes.Select(n => n.PID)));
                SetStatus($"Copied {nodes.Count} PID(s) to clipboard", isSuccess: true);
            }
        }

        private void CopySelectedPath()
        {
            var nodes = GetSelectedNodes();
            var paths = nodes.Where(n => !string.IsNullOrEmpty(n.FilePath)).Select(n => n.FilePath).ToList();
            if (paths.Count > 0)
            {
                Clipboard.SetText(string.Join("\n", paths));
                SetStatus($"Copied {paths.Count} path(s) to clipboard", isSuccess: true);
            }
        }

        private void SetAllExpanded(bool expanded)
        {
            _expandedState.Clear();
            if (expanded)
            {
                foreach (var kvp in _pidToItem)
                    _expandedState[kvp.Key] = true;
            }
            foreach (TreeViewItem item in _processTree.Items)
                SetItemExpanded(item, expanded);
        }

        private void SetItemExpanded(TreeViewItem item, bool expanded)
        {
            item.IsExpanded = expanded;
            foreach (TreeViewItem child in item.Items)
                SetItemExpanded(child, expanded);
        }

        private static void WriteInt32LE(byte[] buf, int offset, int value)
        {
            buf[offset] = (byte)(value & 0xFF);
            buf[offset + 1] = (byte)((value >> 8) & 0xFF);
            buf[offset + 2] = (byte)((value >> 16) & 0xFF);
            buf[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        // ═══════════ DATA HANDLING ═══════════

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
                        case 0x01:
                            _hasReceivedData = true;
                            SetStatus("Client connected — receiving process data…");
                            break;
                        case 0x10:
                            _hasReceivedData = true;
                            ParseProcessData(data, 1);
                            break;
                        case 0xFE:
                            if (data.Length > 1)
                                SetStatus(Encoding.UTF8.GetString(data, 1, data.Length - 1), isSuccess: true);
                            break;
                        case 0xFF:
                            if (data.Length > 1)
                                SetStatus(Encoding.UTF8.GetString(data, 1, data.Length - 1), isError: true);
                            break;
                    }
                }
                catch (Exception ex) { SetStatus($"Parse error: {ex.Message}", isError: true); }
            });
        }

        private void ParseProcessData(byte[] data, int offset)
        {
            try
            {
                using var ms = new MemoryStream(data, offset, data.Length - offset);
                using var br = new BinaryReader(ms, Encoding.UTF8);

                int totalCount = br.ReadInt32();
                int rootCount = br.ReadInt32();

                _totalProcessCount = totalCount;
                _currentRoots = new List<ProcessInfoNode>();

                for (int i = 0; i < rootCount; i++)
                {
                    var node = DeserializeNode(br);
                    if (node != null)
                        _currentRoots.Add(node);
                }

                SaveExpandedState();
                RebuildTree();

                _lastUpdate = DateTime.Now;
                _countLabel.Text = $"{totalCount} processes";
                _lastUpdateLabel.Text = $"Updated {_lastUpdate:HH:mm:ss}";
                SetStatus($"{totalCount} processes · {rootCount} root(s)");
            }
            catch (Exception ex)
            {
                SetStatus($"Parse error: {ex.Message}", isError: true);
            }
        }

        private ProcessInfoNode DeserializeNode(BinaryReader br)
        {
            try
            {
                int pid = br.ReadInt32();
                string name = br.ReadString();
                string path = br.ReadString();
                string desc = br.ReadString();
                long mem = br.ReadInt64();
                int childCount = br.ReadInt32();

                var node = new ProcessInfoNode
                {
                    PID = pid,
                    Name = name,
                    FilePath = path,
                    Description = desc,
                    MemoryBytes = mem
                };

                for (int i = 0; i < childCount; i++)
                {
                    var child = DeserializeNode(br);
                    if (child != null)
                        node.Children.Add(child);
                }

                return node;
            }
            catch { return null; }
        }

        // ═══════════ TREE BUILDING ═══════════

        private void SaveExpandedState()
        {
            foreach (TreeViewItem item in _processTree.Items)
                SaveItemExpandedRecursive(item);
        }

        private void SaveItemExpandedRecursive(TreeViewItem item)
        {
            if (item.Tag is ProcessInfoNode node)
            {
                if (item.IsExpanded)
                    _expandedState[node.PID] = true;
                else
                    _expandedState.Remove(node.PID);
            }
            foreach (TreeViewItem child in item.Items)
                SaveItemExpandedRecursive(child);
        }

        private void RebuildTree()
        {
            _processTree.Items.Clear();
            _pidToItem.Clear();
            _pidToHeaderBorder.Clear();
            _flatPidOrder.Clear();

            foreach (var root in _currentRoots.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
            {
                var item = BuildTreeItem(root);
                if (item != null)
                    _processTree.Items.Add(item);
            }

            foreach (int pid in _selectedPids.ToList())
            {
                if (!_pidToItem.ContainsKey(pid))
                    _selectedPids.Remove(pid);
            }
            UpdateSelectedLabel();
        }

        private TreeViewItem BuildTreeItem(ProcessInfoNode node)
        {
            bool matchesSelf = MatchesFilter(node);
            bool hasMatchingDescendant = AnyDescendantMatches(node);

            if (!matchesSelf && !hasMatchingDescendant && !string.IsNullOrEmpty(_searchFilter))
                return null;

            bool isSelected = _selectedPids.Contains(node.PID);
            bool shouldExpand = _expandedState.ContainsKey(node.PID) ||
                                (!string.IsNullOrEmpty(_searchFilter) && hasMatchingDescendant);

            var item = new TreeViewItem
            {
                Tag = node,
                IsExpanded = shouldExpand,
                Foreground = BrTxtPrimary,
                FontFamily = MonoFont,
                FontSize = 12,
            };

            _pidToItem[node.PID] = item;
            _flatPidOrder.Add(node.PID);

            var headerBorder = new Border
            {
                Background = isSelected ? Fr(BgSelected) : BrTransparent,
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(4, 3, 8, 3),
                SnapsToDevicePixels = true
            };

            _pidToHeaderBorder[node.PID] = headerBorder;

            int nodePid = node.PID;

            headerBorder.MouseEnter += (s, e) =>
            {
                if (!_selectedPids.Contains(nodePid))
                    headerBorder.Background = Fr(BgHover);
                else
                    headerBorder.Background = Fr(BgSelectedHover);
            };
            headerBorder.MouseLeave += (s, e) =>
            {
                headerBorder.Background = _selectedPids.Contains(nodePid)
                    ? Fr(BgSelected) : BrTransparent;
            };

            headerBorder.MouseLeftButtonDown += (s, e) =>
            {
                if (!IsExpanderClick(e.OriginalSource as DependencyObject))
                    OnHeaderClick(nodePid, e);
            };

            var headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(80) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200) });

            var iconBlock = new TextBlock
            {
                Text = GetProcessIcon(node),
                FontSize = 12,
                Width = 18,
                TextAlignment = TextAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0)
            };
            Grid.SetColumn(iconBlock, 0);
            headerGrid.Children.Add(iconBlock);

            bool isSearchHighlight = matchesSelf && !string.IsNullOrEmpty(_searchFilter);
            var nameBlock = new TextBlock
            {
                Text = node.Name,
                FontWeight = node.Children.Count > 0 ? FontWeights.SemiBold : FontWeights.Normal,
                Foreground = isSearchHighlight ? BrAccBlue : BrTxtPrimary,
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis
            };

            if (node.Children.Count > 0)
            {
                var namePanel = new StackPanel { Orientation = Orientation.Horizontal };
                namePanel.Children.Add(nameBlock);

                var badge = new Border
                {
                    Background = Fr(Color.FromArgb(30, TxtSecondary.R, TxtSecondary.G, TxtSecondary.B)),
                    CornerRadius = new CornerRadius(8),
                    Padding = new Thickness(5, 0, 5, 0),
                    Margin = new Thickness(6, 0, 0, 0),
                    VerticalAlignment = VerticalAlignment.Center
                };
                badge.Child = new TextBlock
                {
                    Text = node.Children.Count.ToString(),
                    Foreground = BrTxtMuted,
                    FontSize = 10,
                    FontWeight = FontWeights.Medium
                };
                namePanel.Children.Add(badge);

                Grid.SetColumn(namePanel, 1);
                headerGrid.Children.Add(namePanel);
            }
            else
            {
                Grid.SetColumn(nameBlock, 1);
                headerGrid.Children.Add(nameBlock);
            }

            var pidBlock = new TextBlock
            {
                Text = node.PID.ToString(),
                Foreground = BrTxtMuted,
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(pidBlock, 2);
            headerGrid.Children.Add(pidBlock);

            if (node.MemoryBytes > 0)
            {
                var memFg = node.MemoryBytes > 500 * 1024 * 1024 ? BrAccRed :
                            node.MemoryBytes > 200 * 1024 * 1024 ? BrAccOrange :
                            node.MemoryBytes > 50 * 1024 * 1024 ? BrAccOrange : BrTxtSecondary;

                var memBlock = new TextBlock
                {
                    Text = node.MemoryDisplay,
                    Foreground = memFg,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(memBlock, 3);
                headerGrid.Children.Add(memBlock);
            }

            if (!string.IsNullOrEmpty(node.Description) && node.Description != "Unknown" &&
                !node.Description.Equals(node.Name, StringComparison.OrdinalIgnoreCase))
            {
                var descBlock = new TextBlock
                {
                    Text = node.Description,
                    Foreground = Fr(TxtSecondary),
                    FontSize = 11,
                    FontStyle = FontStyles.Italic,
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(descBlock, 4);
                headerGrid.Children.Add(descBlock);
            }

            headerBorder.Child = headerGrid;
            item.Header = headerBorder;

            item.ToolTip = BuildTooltip(node);

            foreach (var child in node.Children.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase))
            {
                var childItem = BuildTreeItem(child);
                if (childItem != null)
                    item.Items.Add(childItem);
            }

            return item;
        }

        private static string GetProcessIcon(ProcessInfoNode node)
        {
            if (node.Children.Count > 0)
                return "📁";

            var nameLow = (node.Name ?? "").ToLowerInvariant();

            if (nameLow.Contains("svchost") || nameLow.Contains("service"))
                return "⚙";
            if (nameLow.Contains("chrome") || nameLow.Contains("firefox") || nameLow.Contains("edge") ||
                nameLow.Contains("browser") || nameLow.Contains("opera") || nameLow.Contains("brave"))
                return "🌐";
            if (nameLow.Contains("explorer"))
                return "📂";
            if (nameLow.Contains("cmd") || nameLow.Contains("powershell") || nameLow.Contains("terminal") ||
                nameLow.Contains("bash") || nameLow.Contains("conhost") || nameLow.Contains("wt"))
                return "⌨";
            if (nameLow.Contains("system") || nameLow.Contains("csrss") || nameLow.Contains("smss") ||
                nameLow.Contains("lsass") || nameLow.Contains("wininit") || nameLow.Contains("winlogon"))
                return "🔒";
            if (nameLow.Contains("devenv") || nameLow.Contains("code") || nameLow.Contains("rider") ||
                nameLow.Contains("idea") || nameLow.Contains("studio"))
                return "💻";
            if (nameLow.Contains("discord") || nameLow.Contains("teams") || nameLow.Contains("slack") ||
                nameLow.Contains("zoom") || nameLow.Contains("skype"))
                return "💬";
            if (nameLow.Contains("spotify") || nameLow.Contains("music") || nameLow.Contains("vlc") ||
                nameLow.Contains("wmplayer"))
                return "🎵";
            if (nameLow.Contains("steam") || nameLow.Contains("game") || nameLow.Contains("epic"))
                return "🎮";
            if (nameLow.Contains("nvidia") || nameLow.Contains("amd") || nameLow.Contains("intel"))
                return "🖥";
            if (nameLow.Contains("dwm"))
                return "🪟";
            if (nameLow.Contains("search") || nameLow.Contains("cortana"))
                return "🔍";

            return "•";
        }

        private ToolTip BuildTooltip(ProcessInfoNode node)
        {
            var tip = new ToolTip
            {
                Background = Fr(C("SurfaceLightColor")),
                BorderBrush = Fr(BorderClr),
                BorderThickness = new Thickness(1),
                Foreground = Fr(TxtPrimary),
                Padding = new Thickness(10, 8, 10, 8)
            };

            var sp = new StackPanel { MaxWidth = 450 };

            sp.Children.Add(new TextBlock
            {
                Text = node.Name,
                FontWeight = FontWeights.Bold,
                FontSize = 13,
                Foreground = Fr(TxtPrimary),
                Margin = new Thickness(0, 0, 0, 4)
            });

            void AddRow(string label, string value, SolidColorBrush valueFg = null)
            {
                if (string.IsNullOrEmpty(value) || value == "Unknown") return;
                var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 1, 0, 1) };
                row.Children.Add(new TextBlock
                {
                    Text = label + ": ",
                    Foreground = Fr(TxtMuted),
                    FontSize = 11.5,
                    MinWidth = 75
                });
                row.Children.Add(new TextBlock
                {
                    Text = value,
                    Foreground = valueFg ?? Fr(TxtSecondary),
                    FontSize = 11.5,
                    TextWrapping = TextWrapping.Wrap,
                    MaxWidth = 360
                });
                sp.Children.Add(row);
            }

            AddRow("PID", node.PID.ToString());
            AddRow("Memory", node.MemoryDisplay);
            AddRow("Description", node.Description);
            AddRow("Path", node.FilePath);
            if (node.Children.Count > 0)
                AddRow("Children", $"{node.Children.Count} direct, {node.TotalDescendantCount} total");

            tip.Content = sp;
            return tip;
        }

        private bool MatchesFilter(ProcessInfoNode node)
        {
            if (string.IsNullOrEmpty(_searchFilter)) return true;
            string filter = _searchFilter.ToLowerInvariant();
            return (node.Name != null && node.Name.ToLowerInvariant().Contains(filter)) ||
                   (node.Description != null && node.Description.ToLowerInvariant().Contains(filter)) ||
                   (node.FilePath != null && node.FilePath.ToLowerInvariant().Contains(filter)) ||
                   node.PID.ToString().Contains(filter);
        }

        private bool AnyDescendantMatches(ProcessInfoNode node)
        {
            foreach (var child in node.Children)
            {
                if (MatchesFilter(child) || AnyDescendantMatches(child))
                    return true;
            }
            return false;
        }

        public void Dispose()
        {
            _disposed = true;
            _searchDebounce?.Stop();
        }
    }
}
