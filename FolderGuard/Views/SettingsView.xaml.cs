using System.Windows;
using System.Windows.Controls;

namespace FolderGuard.Views;

/// <summary>Settings section of the dashboard.</summary>
public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
    }

    public event EventHandler? OpenDataFolderRequested;
    public event EventHandler? ReloadRequested;
    public event EventHandler? LockAllRequested;
    public event EventHandler? RepairRequested;

    public void Initialise(string dataDirectory)
    {
        DataFolderText.Text = dataDirectory;
        DataFolderText.ToolTip = dataDirectory;
    }

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e) =>
        OpenDataFolderRequested?.Invoke(this, EventArgs.Empty);

    private void Reload_Click(object sender, RoutedEventArgs e) =>
        ReloadRequested?.Invoke(this, EventArgs.Empty);

    private void LockAll_Click(object sender, RoutedEventArgs e) =>
        LockAllRequested?.Invoke(this, EventArgs.Empty);

    private void Repair_Click(object sender, RoutedEventArgs e) =>
        RepairRequested?.Invoke(this, EventArgs.Empty);
}
