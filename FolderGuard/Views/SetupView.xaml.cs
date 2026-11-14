using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FolderGuard.Views;

/// <summary>Folder selection card on the dashboard.</summary>
public partial class SetupView : UserControl
{
    public SetupView()
    {
        InitializeComponent();
    }

    public event EventHandler? BrowseRequested;
    public event EventHandler? ProtectRequested;

    public string? SelectedPath { get; private set; }

    public void SetPath(string? path)
    {
        SelectedPath = path;
        PathBox.Text = string.IsNullOrEmpty(path) ? "No folder selected" : path;
        PathBox.ToolTip = path;
        ProtectButton.IsEnabled = !string.IsNullOrEmpty(path);
    }

    public void SetHint(string message, bool isError)
    {
        HintText.Text = message;
        HintText.Foreground = isError
            ? (Brush)FindResource("DangerTextBrush")
            : (Brush)FindResource("TextSecondaryBrush");
        ProtectButton.IsEnabled = isError == false && !string.IsNullOrEmpty(SelectedPath);
    }

    public void SetEnabledState(bool enabled)
    {
        BrowseButton.IsEnabled = enabled;
        ProtectButton.IsEnabled = enabled && !string.IsNullOrEmpty(SelectedPath);
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e) =>
        BrowseRequested?.Invoke(this, EventArgs.Empty);

    private void ProtectButton_Click(object sender, RoutedEventArgs e) =>
        ProtectRequested?.Invoke(this, EventArgs.Empty);
}
