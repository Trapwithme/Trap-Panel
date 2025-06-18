using Microsoft.Win32;
using System.Windows.Controls;

namespace WpfApp
{
    /// <summary>
    /// Simple wrapper around OpenFileDialog used by MainWindow.SelectFileButton_Click.
    /// </summary>
    public static class FileSelector
    {
        /// <param name="logBox">Optional TextBox to append selection log.</param>
        /// <returns>Selected file path or null if cancelled.</returns>
        public static string SelectFile(TextBox logBox = null)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Select executable or script to send",
                Filter = "Executable or Batch (*.exe;*.bat)|*.exe;*.bat|All files (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            };

            bool? result = dlg.ShowDialog();
            if (result == true)
            {
                string path = dlg.FileName;
                // Optional UI log
                if (logBox != null)
                {
                    logBox.Dispatcher.Invoke(() =>
                    {
                        logBox.Text += $"Selected: {System.IO.Path.GetFileName(path)}\n";
                    });
                }
                return path;
            }
            return null;
        }
    }
} 