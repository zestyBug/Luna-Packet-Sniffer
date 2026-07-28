using System.Security.Cryptography;
using System.Windows;
using LunaPacketSniffer.Proxy;

namespace LunaPacketSniffer.App;

public partial class CertificateWindow : Window
{
    private readonly RootCertificateAuthority _rootCertificateAuthority;

    public CertificateWindow(RootCertificateAuthority rootCertificateAuthority)
    {
        _rootCertificateAuthority = rootCertificateAuthority;
        InitializeComponent();
    }

    private void InstallRootCertificate_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var certificate = _rootCertificateAuthority.EnsureInstalled();
            MessageBox.Show(this, $"Root CA installed: {certificate.Thumbprint}", Title, MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (CryptographicException exception)
        {
            MessageBox.Show(this, exception.Message, Title, MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RemoveRootCertificate_Click(object sender, RoutedEventArgs e)
    {
        _rootCertificateAuthority.Remove();
        MessageBox.Show(this, "Root CA removed.", Title, MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
