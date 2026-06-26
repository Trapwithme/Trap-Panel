using System;
using System.Collections.Generic;
using System.Windows;

namespace WpfApp
{
    public static class ThemeManager
    {
        private static readonly Dictionary<string, string> _themes = new()
        {
            { "Dark", "Themes/Dark.xaml" },
            { "Light", "Themes/Light.xaml" },
            { "Midnight", "Themes/Midnight.xaml" },
            { "Hacker", "Themes/Hacker.xaml" },
            { "Nord", "Themes/Nord.xaml" },
            { "Dracula", "Themes/Dracula.xaml" },
            { "Solarized", "Themes/Solarized.xaml" },
            { "Tokyo Night", "Themes/TokyoNight.xaml" },
            { "Monokai", "Themes/Monokai.xaml" },
            { "One Dark", "Themes/OneDark.xaml" },
            { "Catppuccin", "Themes/Catppuccin.xaml" }
        };

        public static IReadOnlyDictionary<string, string> Themes => _themes;
        public static string CurrentTheme { get; private set; } = "Dark";

        public static void ApplyTheme(string themeName)
        {
            if (!_themes.ContainsKey(themeName)) return;

            var newDict = new ResourceDictionary
            {
                Source = new Uri(_themes[themeName], UriKind.Relative)
            };

            var merged = Application.Current.Resources.MergedDictionaries;
            merged.Clear();
            merged.Add(newDict);

            CurrentTheme = themeName;
        }
    }
}
