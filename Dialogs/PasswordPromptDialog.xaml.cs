using System.Windows;

namespace WpfApp
{
    public partial class PasswordPromptDialog : Window
    {
        public string Password => txtPassword.Password;

        public PasswordPromptDialog()
        {
            InitializeComponent();
        }

        private void BtnOk_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
