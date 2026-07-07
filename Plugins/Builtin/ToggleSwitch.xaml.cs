using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WpfApp.Plugins.Builtin
{
    public partial class ToggleSwitch : UserControl
    {
        private bool _isOn;
        public event Action<bool> Toggled;

        public bool IsOn
        {
            get => _isOn;
            set { _isOn = value; Upd(); }
        }

        public string Label
        {
            get => LabelText.Text;
            set => LabelText.Text = value;
        }

        public ToggleSwitch()
        {
            InitializeComponent();
        }

        public ToggleSwitch(string label) : this()
        {
            Label = label;
            RootBorder.MouseLeftButtonDown += (s, e) =>
            {
                _isOn = !_isOn;
                Upd();
                Toggled?.Invoke(_isOn);
            };
            Upd();
        }

        void Upd()
        {
            if (_isOn) { Thumb.HorizontalAlignment = HorizontalAlignment.Right; Thumb.Margin = new Thickness(0, 0, 2, 0); Track.Background = new SolidColorBrush(Tc("SuccessColor")); }
            else { Thumb.HorizontalAlignment = HorizontalAlignment.Left; Thumb.Margin = new Thickness(2, 0, 0, 0); Track.Background = new SolidColorBrush(Tc("ButtonBgColor")); }
        }
        private static Color Tc(string key) => (Color)Application.Current.Resources[key];
    }
}
