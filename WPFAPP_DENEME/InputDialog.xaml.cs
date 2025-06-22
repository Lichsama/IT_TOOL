using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace WPFAPP_DENEME
{
    /// <summary>
    /// Interaction logic for InputDialog.xaml
    /// </summary>
    public partial class InputDialog : Window
    {
        public string Hostname { get; private set; }
        public string DomainUser { get; private set; }
        public string DomainPass { get; private set; }

        public InputDialog()
        {
            InitializeComponent();
        }

        private void Apply_Click(object sender, RoutedEventArgs e)
        {
            Hostname = txtHostname.Text.Trim();
            DomainUser = txtDomainUser.Text.Trim();
            DomainPass = txtPassword.Password.Trim();

            if (string.IsNullOrWhiteSpace(Hostname) || string.IsNullOrWhiteSpace(DomainUser) || string.IsNullOrWhiteSpace(DomainPass))
            {
                MessageBox.Show("Tüm alanları doldur kanka.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            DialogResult = true;
            Close();
        }
    }

}
